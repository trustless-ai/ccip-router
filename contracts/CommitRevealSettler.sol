// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  CommitRevealSettler
/// @notice ERC-8275 Layer 2 — on-chain settlement for ccip-router contribution snapshots.
///         Nodes submit a commitmentHash during the commit phase, then reveal the full
///         snapshot data. The contract verifies the reveal reconstructs the stored commit.
///
/// @dev    PROTOTYPE — Sepolia only, not audited. No bond/slash mechanism yet.
///         Row encoding and sort order must match ccip-router v0.6.0+:
///           snapshotRoot    = keccak256(abi.encode(rows))          // rows sorted by contributor asc
///           commitmentHash  = keccak256(abi.encode(snapshotRoot, periodId, nodeAddress))
contract CommitRevealSettler {

    // ── Types ─────────────────────────────────────────────────────────────────

    struct SnapshotRow {
        address contributor;
        uint256 score;
        uint256 timestamp;
    }

    struct CommitRecord {
        bytes32 commitmentHash;
        uint256 committedAt;
    }

    // ── Storage ───────────────────────────────────────────────────────────────

    /// @notice Commit records: periodId => nodeAddress => CommitRecord
    mapping(uint256 => mapping(address => CommitRecord)) public commits;

    /// @notice Verified snapshot roots after reveal: periodId => nodeAddress => snapshotRoot
    mapping(uint256 => mapping(address => bytes32)) public snapshotRoots;

    /// @notice Whether a node has successfully revealed for a period
    mapping(uint256 => mapping(address => bool)) public revealed;

    // ── Events ────────────────────────────────────────────────────────────────

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

    // ── Write ─────────────────────────────────────────────────────────────────

    /// @notice Submit a commitment for a period.
    ///         Call this with the commitmentHash returned by
    ///         POST /contributions/snapshot/freeze on your ccip-router node.
    /// @param  periodId       The settlement period.
    /// @param  commitmentHash keccak256(abi.encode(snapshotRoot, periodId, msg.sender))
    function submitCommit(uint256 periodId, bytes32 commitmentHash) external {
        require(commitmentHash != bytes32(0),             "CommitRevealSettler: zero hash");
        require(commits[periodId][msg.sender].committedAt == 0, "CommitRevealSettler: already committed");

        commits[periodId][msg.sender] = CommitRecord({
            commitmentHash: commitmentHash,
            committedAt:    block.timestamp
        });

        emit Committed(periodId, msg.sender, commitmentHash);
    }

    /// @notice Reveal the snapshot rows for a committed period.
    ///         Recomputes snapshotRoot and commitmentHash from rows and verifies
    ///         they match the stored commit. Rows MUST be sorted by contributor
    ///         address ascending — same order as the off-chain freeze.
    /// @param  periodId  The period to reveal.
    /// @param  rows      Contributor rows, sorted by contributor asc.
    function submitReveal(uint256 periodId, SnapshotRow[] calldata rows) external {
        CommitRecord memory c = commits[periodId][msg.sender];
        require(c.committedAt != 0,              "CommitRevealSettler: no commit found");
        require(!revealed[periodId][msg.sender], "CommitRevealSettler: already revealed");

        bytes32 computedRoot = _computeSnapshotRoot(rows);
        bytes32 computedHash = keccak256(abi.encode(computedRoot, periodId, msg.sender));

        if (computedHash != c.commitmentHash) {
            emit RevealMismatch(periodId, msg.sender, c.commitmentHash, computedHash);
            revert("CommitRevealSettler: commitment mismatch");
        }

        revealed[periodId][msg.sender]      = true;
        snapshotRoots[periodId][msg.sender] = computedRoot;

        emit Revealed(periodId, msg.sender, computedRoot, rows.length);
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /// @notice Returns commit details for a node/period pair.
    function getCommit(uint256 periodId, address nodeAddress)
        external view
        returns (bytes32 commitmentHash, uint256 committedAt)
    {
        CommitRecord memory c = commits[periodId][nodeAddress];
        return (c.commitmentHash, c.committedAt);
    }

    /// @notice Returns true if a node has successfully revealed for a period.
    function hasRevealed(uint256 periodId, address nodeAddress) external view returns (bool) {
        return revealed[periodId][nodeAddress];
    }

    /// @notice Off-chain helper — recomputes snapshotRoot for a set of rows.
    ///         Use to verify your rows will produce the expected root before revealing.
    function computeSnapshotRoot(SnapshotRow[] calldata rows) external pure returns (bytes32) {
        return _computeSnapshotRoot(rows);
    }

    /// @notice Off-chain helper — recomputes commitmentHash.
    ///         Must equal the value stored by your node's freeze endpoint.
    function computeCommitmentHash(bytes32 snapshotRoot, uint256 periodId, address nodeAddress)
        external pure
        returns (bytes32)
    {
        return keccak256(abi.encode(snapshotRoot, periodId, nodeAddress));
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /// @dev Matches computeSnapshotRoot() in ccip-router:
    ///      empty rows → keccak256("") (same as keccak256('0x') in viem)
    ///      non-empty  → keccak256(abi.encode(rows)) matching viem encodeAbiParameters tuple[]
    function _computeSnapshotRoot(SnapshotRow[] calldata rows) internal pure returns (bytes32) {
        if (rows.length == 0) return keccak256("");
        return keccak256(abi.encode(rows));
    }
}
