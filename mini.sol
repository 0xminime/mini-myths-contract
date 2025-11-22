// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC721C} from "@limitbreak/creator-token-standards/src/erc721c/ERC721C.sol";
import {ERC721OpenZeppelin} from "@limitbreak/creator-token-standards/src/token/erc721/ERC721OpenZeppelin.sol";
import {ERC2981} from "@openzeppelin/contracts/token/common/ERC2981.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/security/Pausable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * Mini – mini myths are unique pixel art of 300+ traits
 * Three-phase mint on Base Chain (OG -> FCFS -> Public).
 * OG (free), FCFS (paid 0.00015 ETH), Public (paid 0.00025 ETH). Supply capped at 3333.
 */
contract Mini is ERC721C, ERC2981, Ownable, ReentrancyGuard, Pausable {
    using Strings for uint256;

    // ---------- Immutable / Constants ----------
    uint256 public constant MAX_SUPPLY = 3333;
    uint256 public constant ADMIN_MINT_MAX = 100;
    uint256 public constant OG_CAP_PER_WALLET = 1;
    uint256 public constant FCFS_CAP_PER_WALLET = 3;
    uint256 public constant PUBLIC_CAP_PER_WALLET = 20;

    // ---------- Configurable Params ----------
    address payable public treasury; // Where ETH is sent on mint
    uint256 public wlMintPriceWei; // Price in wei (ETH) for WL/FCFS mint
    uint256 public publicMintPriceWei; // Price in wei (ETH) for public mint
    bool public mintActive = true;
    uint256 public startTime; // when OG starts; FCFS/Public follow hourly
    bytes32 public ogRoot;    // merkle root for OG allowlist
    bytes32 public fcfsRoot;  // merkle root for FCFS allowlist

    // ---------- State ----------
    uint256 private _nextTokenId = 1; // tokenId starts at 1
    string private _baseTokenURI;
    string private _uriSuffix = ".json"; // Append .json to token metadata
    mapping(address => uint256) public mintedByWallet; // Tracks total minted per wallet
    mapping(address => uint256) public ogMintedByWallet;
    mapping(address => uint256) public fcfsMintedByWallet;
    mapping(address => uint256) public publicMintedByWallet;
    uint256 public adminMintedTotal; // total number of free mints by admin

    // Track default royalty bps so we can keep it when treasury changes
    uint96 public royaltyBps = 500;

    // ---------- Events ----------
    event Minted(address indexed minter, uint256 indexed tokenId, uint256 pricePaidWei);
    event MintedBatch(address indexed minter, uint256 quantity, uint256 totalPriceWei);
    event TreasuryUpdated(address indexed treasury);
    event MintActiveSet(bool active);
    event StartTimeSet(uint256 startTime);
    event BaseURISet(string baseURI);
    event PriceSet(uint256 priceWei);
    event MerkleRootsSet(bytes32 ogRoot, bytes32 fcfsRoot);
    event AdminMint(address indexed to, uint256 quantity);
    // ERC-4906 metadata refresh events
    event BatchMetadataUpdate(uint256 _fromTokenId, uint256 _toTokenId);
    event MetadataUpdate(uint256 _tokenId);

    // ---------- Errors ----------
    error MintClosed();
    error InvalidQuantity();
    error SupplyExceeded();
    error ZeroAddress();
    error WalletCapExceeded();
    error AdminCapExceeded();
    error NotAllowlisted();

    // ---------- Modifiers ----------
    constructor(address treasuryReceiver, string memory baseURI)
        ERC721OpenZeppelin("Mini Myths", "MYTH")
    {
        if (treasuryReceiver == address(0)) revert ZeroAddress();
        treasury = payable(treasuryReceiver);
        _baseTokenURI = baseURI;
        // Mint prices: WL = 0.0001 ETH, Public = 0.00015 ETH
        wlMintPriceWei = 0.0001 ether;
        publicMintPriceWei = 0.00015 ether;
        // Set default royalty to 5% (500 bps) paid to treasury
        _setDefaultRoyalty(treasury, royaltyBps);
    }

    // ---------- Phased Mint (ETH) ----------
    // Phases: 0=NotStarted, 1=OG, 2=FCFS, 3=Public
    function currentPhase() public view returns (uint8 phase) {
        if (startTime == 0 || block.timestamp < startTime) return 0;
        if (block.timestamp < startTime + 1 hours) return 1;
        if (block.timestamp < startTime + 2 hours) return 2;
        return 3;
    }

    function capForPhase(uint8 phase) public pure returns (uint256) {
        if (phase == 1) return OG_CAP_PER_WALLET;
        if (phase == 2) return FCFS_CAP_PER_WALLET;
        if (phase == 3) return PUBLIC_CAP_PER_WALLET;
        return 0;
    }

    function _verify(bytes32 root, address account, bytes32[] calldata proof) internal pure returns (bool) {
        if (root == bytes32(0)) return false;
        bytes32 leaf = keccak256(abi.encodePacked(account));
        return MerkleProof.verify(proof, root, leaf);
    }

    function mint(uint256 quantity, bytes32[] calldata merkleProof) external payable nonReentrant whenNotPaused {
        if (!mintActive) revert MintClosed();
        if (quantity == 0) revert InvalidQuantity();
        if (_nextTokenId - 1 + quantity > MAX_SUPPLY) revert SupplyExceeded();

        uint8 phase = currentPhase();
        if (phase == 0) revert MintClosed();

        uint256 requiredValue = 0;
        if (phase == 1) {
            // OG: allowlist, free, 1 per wallet
            if (!_verify(ogRoot, msg.sender, merkleProof)) revert NotAllowlisted();
            if (ogMintedByWallet[msg.sender] + quantity > OG_CAP_PER_WALLET) revert WalletCapExceeded();
            // OG is free
        } else if (phase == 2) {
            // FCFS: allowlist, paid (0.0001 ETH), 3 per wallet
            if (!_verify(fcfsRoot, msg.sender, merkleProof)) revert NotAllowlisted();
            if (fcfsMintedByWallet[msg.sender] + quantity > FCFS_CAP_PER_WALLET) revert WalletCapExceeded();
            requiredValue = wlMintPriceWei * quantity;
        } else {
            // Public: paid (0.00015 ETH), 20 per wallet
            if (publicMintedByWallet[msg.sender] + quantity > PUBLIC_CAP_PER_WALLET) revert WalletCapExceeded();
            requiredValue = publicMintPriceWei * quantity;
        }
        if (msg.value != requiredValue) revert("INVALID_MSG_VALUE");

        uint256 tokenId = _nextTokenId;
        unchecked {
            for (uint256 i = 0; i < quantity; i++) {
                _safeMint(msg.sender, tokenId);
                emit Minted(msg.sender, tokenId, requiredValue / quantity);
                tokenId++;
            }
        }
        _nextTokenId = tokenId;
        mintedByWallet[msg.sender] += quantity;
        if (phase == 1) ogMintedByWallet[msg.sender] += quantity;
        else if (phase == 2) fcfsMintedByWallet[msg.sender] += quantity;
        else publicMintedByWallet[msg.sender] += quantity;

        if (requiredValue > 0) {
            (bool ok, ) = treasury.call{value: requiredValue}("");
            require(ok, "PAYMENT_FAIL");
        }
        emit MintedBatch(msg.sender, quantity, requiredValue);
    }

    // (relayer/x402 mint removed)

    // ---------- Admin Free Mint (capped) ----------
    function adminMint(address recipient, uint256 quantity) external onlyOwner nonReentrant {
        if (recipient == address(0)) revert ZeroAddress();
        if (quantity == 0) revert InvalidQuantity();
        if (_nextTokenId - 1 + quantity > MAX_SUPPLY) revert SupplyExceeded();
        if (adminMintedTotal + quantity > ADMIN_MINT_MAX) revert AdminCapExceeded();

        uint256 tokenId = _nextTokenId;
        unchecked {
            for (uint256 i = 0; i < quantity; i++) {
                _safeMint(recipient, tokenId);
                tokenId++;
            }
        }
        _nextTokenId = tokenId;
        adminMintedTotal += quantity;
        emit AdminMint(recipient, quantity);
    }

    // ---------- Admin ----------
    function setMintActive(bool active) external onlyOwner {
        mintActive = active;
        emit MintActiveSet(active);
    }

    function setStartTime(uint256 newStartTime) external onlyOwner {
        startTime = newStartTime;
        emit StartTimeSet(newStartTime);
    }

    function setTreasury(address newTreasury) external onlyOwner {
        if (newTreasury == address(0)) revert ZeroAddress();
        treasury = payable(newTreasury);
        // keep default royalty to current bps but update receiver
        _setDefaultRoyalty(newTreasury, royaltyBps);
        emit TreasuryUpdated(newTreasury);
    }

    function setMintPrice(uint256 newWlPrice, uint256 newPublicPrice) external onlyOwner {
        // prices are expressed in wei (ETH)
        wlMintPriceWei = newWlPrice;
        publicMintPriceWei = newPublicPrice;
        emit PriceSet(newPublicPrice);
    }

    function setMerkleRoots(bytes32 newOgRoot, bytes32 newFcfsRoot) external onlyOwner {
        ogRoot = newOgRoot;
        fcfsRoot = newFcfsRoot;
        emit MerkleRootsSet(newOgRoot, newFcfsRoot);
    }

    function setBaseURI(string calldata newBaseURI) external onlyOwner {
        _baseTokenURI = newBaseURI;
        emit BaseURISet(newBaseURI);
        if (_nextTokenId > 1) {
            emit BatchMetadataUpdate(1, _nextTokenId - 1);
        }
    }

    // ----- Royalties (ERC2981) -----
    function setDefaultRoyalty(address receiver, uint96 feeNumeratorBps) external onlyOwner {
        royaltyBps = feeNumeratorBps;
        _setDefaultRoyalty(receiver, feeNumeratorBps);
    }

    // Allow owner to clear royalties entirely by passing receiver=address(0) or bps=0
    function clearDefaultRoyaltyIfZero(address receiver, uint96 feeNumeratorBps) external onlyOwner {
        if (receiver == address(0) || feeNumeratorBps == 0) {
            royaltyBps = 0;
            _deleteDefaultRoyalty();
        } else {
            royaltyBps = feeNumeratorBps;
            _setDefaultRoyalty(receiver, feeNumeratorBps);
        }
    }

    // ----- ERC721C transfer validator helpers -----
    // By default, ERC721C uses a curated default validator.
    // Owners may toggle auto-approval of the validator for smoother UX on compliant markets.
    function setAutoApproveValidator(bool autoApprove) external onlyOwner {
        this.setAutomaticApprovalOfTransfersFromValidator(autoApprove);
    }

    // ----- Required by ERC721C (OwnablePermissions) -----
    // Bridge ERC721C's OwnablePermissions to OpenZeppelin Ownable
    function _requireCallerIsContractOwner() internal view override {
        _checkOwner();
    }

    // per-phase caps are fixed constants; no dynamic cap setter

    // ---------- Rescue ----------
    receive() external payable {}

    function rescueERC20(address token, address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        bool ok = IERC20(token).transfer(to, amount);
        require(ok, "ERC20_TRANSFER_FAIL");
    }

    function rescueETH(address payable to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "ETH_TRANSFER_FAIL");
    }

    // Withdraw all native ETH accumulated on the contract to the treasury
    function withdraw() external onlyOwner {
        uint256 bal = address(this).balance;
        if (bal == 0) return;
        (bool ok, ) = treasury.call{value: bal}("");
        require(ok, "WITHDRAW_FAIL");
    }

    // ---------- Views ----------
    function totalMinted() external view returns (uint256) {
        return _nextTokenId - 1;
    }

    function remainingSupply() external view returns (uint256) {
        return MAX_SUPPLY - (_nextTokenId - 1);
    }

    function mintedOf(address account) external view returns (uint256) {
        return mintedByWallet[account];
    }

    function remainingMints(address account) external view returns (uint256) {
        uint8 phase = currentPhase();
        uint256 cap = capForPhase(phase);
        if (cap == 0) return 0;
        uint256 mintedPhase = phase == 1 ? ogMintedByWallet[account] : phase == 2 ? fcfsMintedByWallet[account] : publicMintedByWallet[account];
        if (mintedPhase >= cap) return 0;
        return cap - mintedPhase;
    }

    function _baseURI() internal view override returns (string memory) {
        return _baseTokenURI;
    }

    function setURISuffix(string calldata newSuffix) external onlyOwner {
        _uriSuffix = newSuffix;
        if (_nextTokenId > 1) {
            emit BatchMetadataUpdate(1, _nextTokenId - 1);
        }
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        require(_exists(tokenId), "URI query for nonexistent token");
        string memory base = _baseURI();
        if (bytes(base).length == 0) return "";
        return string(abi.encodePacked(base, tokenId.toString(), _uriSuffix));
    }

    // ---------- Pausable ----------
    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    // ---------- Metadata Refresh ----------
    function refreshMetadata(uint256 tokenId) external onlyOwner {
        require(_exists(tokenId), "nonexistent token");
        emit MetadataUpdate(tokenId);
    }

    function refreshAllMetadata() external onlyOwner {
        if (_nextTokenId > 1) {
            emit BatchMetadataUpdate(1, _nextTokenId - 1);
        }
    }

    // ---------- Progress helper for frontends ----------
    function mintProgress()
        external
        view
        returns (
            uint256 minted,
            uint256 maxSupply,
            uint256 priceWei,
            bool active
        )
    {
        minted = _nextTokenId - 1;
        maxSupply = MAX_SUPPLY;
        uint8 phase = currentPhase();
        priceWei = (phase == 1) ? 0 : (phase == 2) ? wlMintPriceWei : publicMintPriceWei;
        active = mintActive && !paused() && phase != 0;
    }

    function maxPerWallet() external view returns (uint256) {
        return capForPhase(currentPhase());
    }

    function isAllowlistedOG(address account, bytes32[] calldata proof) external view returns (bool) {
        return _verify(ogRoot, account, proof);
    }

    function isAllowlistedFCFS(address account, bytes32[] calldata proof) external view returns (bool) {
        return _verify(fcfsRoot, account, proof);
    }

    // ---------- Interfaces ----------
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721C, ERC2981)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}

