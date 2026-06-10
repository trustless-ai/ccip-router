// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Minimal interface — only what CommitRevealSettlerV2 needs from NodeRegistryV2.
interface INodeRegistryV2 {
    enum NodeType { Origin, Router, Hybrid }
    function getNodeType(address signer) external view returns (NodeType);
}

/// @title  CommitRevealSettlerV2
/// @notice ERC-8275 Layer 2 — commit/reveal settlement with bond-backed fraud proofs.
///         Extends CommitRevealSettler (V1) with:
///           - BOND_AMOUNT required at commit. Router + Hybrid only (Origin nodes do not
///             participate in the settlement quorum — see ERC-8275 NodeType rationale).
///           - REVEAL_WINDOW (48 h): node must reveal within this window or bond is slashable
///             by anyone via slashUnrevealed().
///           - CHALLENGE_PERIOD (7 d): window post-reveal before bond is claimable.
///           - challenge() entry point — proof-type-agnostic. V1 stores + emits for off-chain
///             indexing; on-chain resolution via IProofVerifier is V3 (ERC-8274 pattern).
///             V1 lightweight proof type: bytes4(keccak256("sig-contradiction"))
///           - slashRecipient: immutable. Set to deployer for Sepolia; point at EscrowV1.
///
/// @dev    PROTOTYPE — Sepolia only, not audited. No on-chain challenge resolution yet.
///         NodeRegistryV2: 0xeFae266aE0a74518da320a029dD76F4d47e2a87b (Sepolia)
contract CommitRevealSettlerV2 {

    // ── Constants ──────────────────────────────────────────────────────────────

    uint256 public constant BOND_AMOUNT      = 0.01 ether;
    uint256 public constant REVEAL_WINDOW    = 48 hours;
    uint256 public constant CHALLENGE_PERIOD = 7 days;

    // ── Immutables ─────────────────────────────────────────────────────────────

    INodeRegistryV2  public immutable nodeRegistry;
    address payable  public immutable slashRecipient;

    // ── Types ──────────────────────────────────────────────────────────────────

    struct SnapshotRow {
        address contributor;
        uint256 score;
        uint256 timestamp;
    }

    struct CommitRecord {
        bytes32 commitmentHash;
        uint256 committedAt;
        uint256 revealedAt;   // 0 until revealed
        bool    bondReleased; // true once bond transferred out (slashed or claimed)
    }

    struct ChallengeRecord {
        address challenger;
        bytes4  proofType;
        uint256 submittedAt;
    }

    // ── Storage ────────────────────────────────────────────────────────────────

    /// @notice periodId => nodeAddress => CommitRecord
    mapping(uint256 => mapping(address => CommitRecord))      public commits;
    /// @notice Verified snapshot roots: periodId => nodeAddress => snapshotRoot
    mapping(uint256 => mapping(address => bytes32))           public snapshotRoots;
    /// @notice Challenges: periodId => nodeAddress => ChallengeRecord[]
    mapping(uint256 => mapping(address => ChallengeRecord[])) private _challenges;

    // ── Events ─────────────────────────────────────────────────────────────────

    event Committed(
        uint256 indexed periodId,
        address indexed nodeAddress,
        bytes32         commitmentHash
    );
    event Revealed(
        uint256 indexed periodId,
        address indexed nodeAddress,
        bytes32         snapshotRoot,
        uint256         rowCount
    );
    event RevealMismatch(
        uint256 indexed periodId,
        address indexed nodeAddress,
        bytes32         expected,
        bytes32         actual
    );
    event BondSlashed(
        uint256 indexed periodId,
        address indexed nodeAddress,
        address         recipient,
        string          reason
    );
    event BondClaimed(
        uint256 indexed periodId,
        address indexed nodeAddress
    );
    event ChallengeSubmitted(
        uint256 indexed periodId,
        address indexed nodeAddress,
        address indexed challenger,
        bytes4          proofType,
        uint256         challengeIndex,
        bytes           proofData
    );

    // ── Constructor ────────────────────────────────────────────────────────────

    constructor(address nodeRegistry_, address payable slashRecipient_) {
        require(nodeRegistry_   != address(0), "CommitRevealSettlerV2: zero registry");
        require(slashRecipient_ != address(0), "CommitRevealSettlerV2: zero recipient");
        nodeRegistry   = INodeRegistryV2(nodeRegistry_);
        slashRecipient = slashRecipient_;
    }

    // ── Write: commit ───────────────────────────────────────────────────────────

    /// @notice Commit a snapshot hash for a period. Requires BOND_AMOUNT ETH.
    ///         Caller must be registered as Router or Hybrid in NodeRegistryV2.
    /// @param  periodId       The settlement period.
    /// @param  commitmentHash keccak256(abi.encode(snapshotRoot, periodId, msg.sender))
    function submitCommit(uint256 periodId, bytes32 commitmentHash) external payable {
        require(msg.value == BOND_AMOUNT,                        "CommitRevealSettlerV2: wrong bond");
        require(commitmentHash != bytes32(0),                    "CommitRevealSettlerV2: zero hash");
        require(commits[periodId][msg.sender].committedAt == 0,  "CommitRevealSettlerV2: already committed");

        INodeRegistryV2.NodeType nt = nodeRegistry.getNodeType(msg.sender);
        require(
            nt == INodeRegistryV2.NodeType.Router ||
            nt == INodeRegistryV2.NodeType.Hybrid,
            "CommitRevealSettlerV2: Origin nodes cannot commit"
        );

        commits[periodId][msg.sender] = CommitRecord({
            commitmentHash: commitmentHash,
            committedAt:    block.timestamp,
            revealedAt:     0,
            bondReleased:   false
        });

        emit Committed(periodId, msg.sender, commitmentHash);
    }

    // ── Write: reveal ───────────────────────────────────────────────────────────

    /// @notice Reveal snapshot rows for a committed period.
    ///         On hash mismatch: bond is slashed immediately, tx does NOT revert —
    ///         RevealMismatch is emitted and the function returns. The snapshot is
    ///         not recorded. The node cannot retry (bondReleased = true).
    ///         Rows MUST be sorted by contributor address ascending.
    function submitReveal(uint256 periodId, SnapshotRow[] calldata rows) external {
        CommitRecord storage c = commits[periodId][msg.sender];
        require(c.committedAt  != 0, "CommitRevealSettlerV2: no commit");
        require(c.revealedAt   == 0, "CommitRevealSettlerV2: already revealed");
        require(!c.bondReleased,      "CommitRevealSettlerV2: bond already released");
        require(
            block.timestamp <= c.committedAt + REVEAL_WINDOW,
            "CommitRevealSettlerV2: reveal window expired"
        );

        bytes32 computedRoot = _computeSnapshotRoot(rows);
        bytes32 computedHash = keccak256(abi.encode(computedRoot, periodId, msg.sender));

        if (computedHash != c.commitmentHash) {
            c.bondReleased = true;
            emit RevealMismatch(periodId, msg.sender, c.commitmentHash, computedHash);
            _slash(periodId, msg.sender, "reveal mismatch");
            return;
        }

        c.revealedAt                        = block.timestamp;
        snapshotRoots[periodId][msg.sender] = computedRoot;

        emit Revealed(periodId, msg.sender, computedRoot, rows.length);
    }

    // ── Write: slash unrevealed ─────────────────────────────────────────────────

    /// @notice Anyone may slash a node that committed but missed the reveal deadline.
    ///         Permissionless — no caller restrictions.
    function slashUnrevealed(uint256 periodId, address nodeAddress) external {
        CommitRecord storage c = commits[periodId][nodeAddress];
        require(c.committedAt  != 0, "CommitRevealSettlerV2: no commit");
        require(c.revealedAt   == 0, "CommitRevealSettlerV2: not revealed");
        require(!c.bondReleased,      "CommitRevealSettlerV2: bond already released");
        require(
            block.timestamp > c.committedAt + REVEAL_WINDOW,
            "CommitRevealSettlerV2: reveal window still open"
        );

        c.bondReleased = true;
        _slash(periodId, nodeAddress, "missed reveal deadline");
    }

    // ── Write: challenge ────────────────────────────────────────────────────────

    /// @notice Submit a fraud proof against a revealed report.
    ///         proofData is stored on-chain and indexed via ChallengeSubmitted event.
    ///         On-chain resolution is V3. V1 lightweight proof type:
    ///         bytes4(keccak256("sig-contradiction")) — off-chain verifier pulls the node's
    ///         signed /records responses and checks they contradict the revealed distribution.
    function challenge(
        uint256          periodId,
        address          nodeAddress,
        bytes4           proofType,
        bytes   calldata proofData
    ) external {
        CommitRecord storage c = commits[periodId][nodeAddress];
        require(c.revealedAt  != 0, "CommitRevealSettlerV2: not revealed");
        require(!c.bondReleased,     "CommitRevealSettlerV2: bond already released");
        require(
            block.timestamp <= c.revealedAt + CHALLENGE_PERIOD,
            "CommitRevealSettlerV2: challenge period expired"
        );

        uint256 idx = _challenges[periodId][nodeAddress].length;
        _challenges[periodId][nodeAddress].push(ChallengeRecord({
            challenger:  msg.sender,
            proofType:   proofType,
            submittedAt: block.timestamp
        }));

        emit ChallengeSubmitted(periodId, nodeAddress, msg.sender, proofType, idx, proofData);
    }

    // ── Write: claim bond ───────────────────────────────────────────────────────

    /// @notice Claim bond after challenge period expires with no successful challenges.
    ///         V1: challenge resolution is off-chain — any on-chain challenge only stores
    ///         the proof. Claim is unconditional once CHALLENGE_PERIOD has passed.
    ///         V3 will gate claim on challenge resolution status.
    function claimBond(uint256 periodId) external {
        CommitRecord storage c = commits[periodId][msg.sender];
        require(c.revealedAt  != 0, "CommitRevealSettlerV2: not revealed");
        require(!c.bondReleased,     "CommitRevealSettlerV2: bond already released");
        require(
            block.timestamp > c.revealedAt + CHALLENGE_PERIOD,
            "CommitRevealSettlerV2: challenge period not expired"
        );

        c.bondReleased = true;
        (bool ok,) = msg.sender.call{value: BOND_AMOUNT}("");
        require(ok, "CommitRevealSettlerV2: bond return failed");

        emit BondClaimed(periodId, msg.sender);
    }

    // ── Read ────────────────────────────────────────────────────────────────────

    function getCommit(uint256 periodId, address nodeAddress)
        external view
        returns (
            bytes32 commitmentHash,
            uint256 committedAt,
            uint256 revealedAt,
            bool    bondReleased
        )
    {
        CommitRecord memory c = commits[periodId][nodeAddress];
        return (c.commitmentHash, c.committedAt, c.revealedAt, c.bondReleased);
    }

    function hasRevealed(uint256 periodId, address nodeAddress) external view returns (bool) {
        return commits[periodId][nodeAddress].revealedAt != 0;
    }

    /// @notice Timestamp after which slashUnrevealed() becomes callable.
    function revealDeadline(uint256 periodId, address nodeAddress) external view returns (uint256) {
        uint256 ca = commits[periodId][nodeAddress].committedAt;
        return ca == 0 ? 0 : ca + REVEAL_WINDOW;
    }

    /// @notice Timestamp after which claimBond() becomes callable.
    function challengeDeadline(uint256 periodId, address nodeAddress) external view returns (uint256) {
        uint256 ra = commits[periodId][nodeAddress].revealedAt;
        return ra == 0 ? 0 : ra + CHALLENGE_PERIOD;
    }

    function getChallengeCount(uint256 periodId, address nodeAddress) external view returns (uint256) {
        return _challenges[periodId][nodeAddress].length;
    }

    function getChallenge(uint256 periodId, address nodeAddress, uint256 index)
        external view
        returns (address challenger, bytes4 proofType, uint256 submittedAt)
    {
        ChallengeRecord memory ch = _challenges[periodId][nodeAddress][index];
        return (ch.challenger, ch.proofType, ch.submittedAt);
    }

    // Off-chain helpers — same interface as V1
    function computeSnapshotRoot(SnapshotRow[] calldata rows) external pure returns (bytes32) {
        return _computeSnapshotRoot(rows);
    }

    function computeCommitmentHash(bytes32 snapshotRoot_, uint256 periodId, address nodeAddress)
        external pure returns (bytes32)
    {
        return keccak256(abi.encode(snapshotRoot_, periodId, nodeAddress));
    }

    // ── Internal ────────────────────────────────────────────────────────────────

    function _computeSnapshotRoot(SnapshotRow[] calldata rows) internal pure returns (bytes32) {
        if (rows.length == 0) return keccak256("");
        return keccak256(abi.encode(rows));
    }

    function _slash(uint256 periodId, address nodeAddress, string memory reason) internal {
        (bool ok,) = slashRecipient.call{value: BOND_AMOUNT}("");
        require(ok, "CommitRevealSettlerV2: slash transfer failed");
        emit BondSlashed(periodId, nodeAddress, slashRecipient, reason);
    }
}
