// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  GenericCommitRevealSettler
/// @notice Bytes-generic commit/reveal primitive.
///         Accepts any record type — contribution snapshots (ERC-8275),
///         judgment attestations (WYRIWE L4), OCP observations, or any
///         future schema. Schema discrimination is handled off-chain via
///         EIP-712 type strings; this contract only verifies the preimage binding.
///
///         No bond or NodeType gate — those are ERC-8275-specific concerns
///         handled by CommitRevealSettlerV2. This contract is the shared
///         settlement primitive that typed settlers build on top of.
///
///         commitmentHash = keccak256(abi.encode(record, periodId, committer))
///         Binding to periodId + committer prevents cross-period and cross-sender replay.
///
/// @dev    PROTOTYPE — Sepolia only, not audited.
///         CommitRevealSettlerV2: 0x5e2e0007F5371e96035CFBab75d5d8db5875A267
contract GenericCommitRevealSettler {

    // ── Constants ──────────────────────────────────────────────────────────────

    uint256 public constant REVEAL_WINDOW    = 48 hours;
    uint256 public constant CHALLENGE_PERIOD = 7 days;

    // ── Types ──────────────────────────────────────────────────────────────────

    struct CommitRecord {
        bytes32 commitmentHash;
        uint256 committedAt;
        uint256 revealedAt;
        bytes32 recordHash;   // keccak256(record) stored at reveal; zero before
    }

    struct ChallengeRecord {
        address challenger;
        bytes4  proofType;
        uint256 submittedAt;
    }

    // ── Storage ────────────────────────────────────────────────────────────────

    mapping(uint256 => mapping(address => CommitRecord))      public commits;
    mapping(uint256 => mapping(address => ChallengeRecord[])) private _challenges;

    // ── Events ─────────────────────────────────────────────────────────────────

    event Committed(
        uint256 indexed periodId,
        address indexed committer,
        bytes32         commitmentHash
    );
    event Revealed(
        uint256 indexed periodId,
        address indexed committer,
        bytes32         recordHash,
        bytes           record
    );
    event RevealMismatch(
        uint256 indexed periodId,
        address indexed committer,
        bytes32         expected,
        bytes32         actual
    );
    event ChallengeSubmitted(
        uint256 indexed periodId,
        address indexed committer,
        address indexed challenger,
        bytes4          proofType,
        uint256         challengeIndex,
        bytes           proofData
    );

    // ── Write: commit ───────────────────────────────────────────────────────────

    /// @notice Commit a hash for any record type.
    ///         commitmentHash = keccak256(abi.encode(record, periodId, msg.sender))
    function submitCommit(uint256 periodId, bytes32 commitmentHash) external {
        require(commitmentHash != bytes32(0),                   "GenericCommitRevealSettler: zero hash");
        require(commits[periodId][msg.sender].committedAt == 0, "GenericCommitRevealSettler: already committed");

        commits[periodId][msg.sender] = CommitRecord({
            commitmentHash: commitmentHash,
            committedAt:    block.timestamp,
            revealedAt:     0,
            recordHash:     bytes32(0)
        });

        emit Committed(periodId, msg.sender, commitmentHash);
    }

    // ── Write: reveal ───────────────────────────────────────────────────────────

    /// @notice Reveal the committed record. Verifies preimage binding.
    ///         record is ABI-encoded off-chain; this contract treats it as opaque bytes.
    ///         On mismatch: emits RevealMismatch and reverts (no bond — safe to revert).
    function submitReveal(uint256 periodId, bytes calldata record) external {
        CommitRecord storage c = commits[periodId][msg.sender];
        require(c.committedAt != 0, "GenericCommitRevealSettler: no commit");
        require(c.revealedAt  == 0, "GenericCommitRevealSettler: already revealed");
        require(
            block.timestamp <= c.committedAt + REVEAL_WINDOW,
            "GenericCommitRevealSettler: reveal window expired"
        );

        bytes32 actual = keccak256(abi.encode(record, periodId, msg.sender));

        if (actual != c.commitmentHash) {
            emit RevealMismatch(periodId, msg.sender, c.commitmentHash, actual);
            revert("GenericCommitRevealSettler: commitment mismatch");
        }

        c.revealedAt = block.timestamp;
        c.recordHash = keccak256(record);

        emit Revealed(periodId, msg.sender, c.recordHash, record);
    }

    // ── Write: challenge ────────────────────────────────────────────────────────

    /// @notice Submit a fraud proof against a revealed record.
    ///         V1 lightweight proof type: bytes4(keccak256("sig-contradiction"))
    ///         On-chain resolution is V3.
    function challenge(
        uint256          periodId,
        address          committer,
        bytes4           proofType,
        bytes   calldata proofData
    ) external {
        CommitRecord storage c = commits[periodId][committer];
        require(c.revealedAt != 0, "GenericCommitRevealSettler: not revealed");
        require(
            block.timestamp <= c.revealedAt + CHALLENGE_PERIOD,
            "GenericCommitRevealSettler: challenge period expired"
        );

        uint256 idx = _challenges[periodId][committer].length;
        _challenges[periodId][committer].push(ChallengeRecord({
            challenger:  msg.sender,
            proofType:   proofType,
            submittedAt: block.timestamp
        }));

        emit ChallengeSubmitted(periodId, committer, msg.sender, proofType, idx, proofData);
    }

    // ── Read ────────────────────────────────────────────────────────────────────

    function getCommit(uint256 periodId, address committer)
        external view
        returns (bytes32 commitmentHash, uint256 committedAt, uint256 revealedAt, bytes32 recordHash)
    {
        CommitRecord memory c = commits[periodId][committer];
        return (c.commitmentHash, c.committedAt, c.revealedAt, c.recordHash);
    }

    function revealDeadline(uint256 periodId, address committer) external view returns (uint256) {
        uint256 ca = commits[periodId][committer].committedAt;
        return ca == 0 ? 0 : ca + REVEAL_WINDOW;
    }

    function challengeDeadline(uint256 periodId, address committer) external view returns (uint256) {
        uint256 ra = commits[periodId][committer].revealedAt;
        return ra == 0 ? 0 : ra + CHALLENGE_PERIOD;
    }

    function getChallengeCount(uint256 periodId, address committer) external view returns (uint256) {
        return _challenges[periodId][committer].length;
    }

    /// @notice Off-chain helper — compute commitment hash for any record.
    function computeCommitmentHash(bytes calldata record, uint256 periodId, address committer)
        external pure returns (bytes32)
    {
        return keccak256(abi.encode(record, periodId, committer));
    }
}
