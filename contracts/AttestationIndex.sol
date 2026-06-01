// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  AttestationIndex
/// @notice On-chain anchor for WYRIWE EIP-712 attestations produced by ccip-router nodes.
///         Any gateway may call `record()` to anchor a signed WyriweAttestation.
///         Signature is verified against the ERC-8004 registry domain used at signing time.
///
/// @dev    Deploy on the same chain as configured in CHAIN_ID / opts.chainId so that
///         block.chainid matches the chainId used in the EIP-712 domain during signing.
contract AttestationIndex {

    // ── Types ─────────────────────────────────────────────────────────────────

    struct WyriweAttestation {
        bytes32 agentId;
        address registry;               // ERC-8004 registry — used as EIP-712 verifyingContract
        bytes32 modelHash;
        bytes32 rawInputHash;
        bytes32 sanitizationPipelineHash;
        bytes32 inputHash;
        bytes32 outputHash;
        bytes32 commitmentHash;
        uint256 timestamp;
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 private constant ATTESTATION_TYPEHASH = keccak256(
        "WyriweAttestation(bytes32 agentId,address registry,bytes32 modelHash,"
        "bytes32 rawInputHash,bytes32 sanitizationPipelineHash,bytes32 inputHash,"
        "bytes32 outputHash,bytes32 commitmentHash,uint256 timestamp)"
    );

    // ── Storage ───────────────────────────────────────────────────────────────

    /// @notice Returns the signer address for a commitmentHash (zero = not recorded).
    mapping(bytes32 => address) public signerOf;

    /// @notice Returns the latest commitmentHash anchored for a given inputHash.
    mapping(bytes32 => bytes32) public commitmentOf;

    // ── Events ────────────────────────────────────────────────────────────────

    event AttestationRecorded(
        bytes32 indexed commitmentHash,
        bytes32 indexed inputHash,
        bytes32 indexed agentId,
        address         signer,
        uint256         timestamp
    );

    // ── Write ─────────────────────────────────────────────────────────────────

    /// @notice Anchor a WyriweAttestation on-chain.
    ///         Verifies the EIP-712 signature against the domain used at signing time
    ///         (name="WyriweAttestation", version="1", chainId=block.chainid,
    ///          verifyingContract=a.registry).
    /// @param  a         The attestation struct matching the off-chain signed message.
    /// @param  signature 65-byte EIP-712 signature produced by the gateway key.
    /// @return signer    Recovered signer address.
    function record(
        WyriweAttestation calldata a,
        bytes calldata signature
    ) external returns (address signer) {
        require(signerOf[a.commitmentHash] == address(0), "AttestationIndex: already recorded");

        // Reconstruct the EIP-712 domain separator as signed by the gateway.
        // verifyingContract is a.registry (ERC-8004 registry) — NOT this contract.
        bytes32 domainSeparator = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256("WyriweAttestation"),
            keccak256("1"),
            block.chainid,
            a.registry
        ));

        bytes32 structHash = keccak256(abi.encode(
            ATTESTATION_TYPEHASH,
            a.agentId, a.registry, a.modelHash,
            a.rawInputHash, a.sanitizationPipelineHash,
            a.inputHash, a.outputHash,
            a.commitmentHash, a.timestamp
        ));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        signer = _recover(digest, signature);
        require(signer != address(0), "AttestationIndex: invalid signature");

        signerOf[a.commitmentHash]  = signer;
        commitmentOf[a.inputHash]   = a.commitmentHash;

        emit AttestationRecorded(a.commitmentHash, a.inputHash, a.agentId, signer, a.timestamp);
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /// @notice Returns true if a commitmentHash has been anchored.
    function isRecorded(bytes32 commitmentHash) external view returns (bool) {
        return signerOf[commitmentHash] != address(0);
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "AttestationIndex: bad sig length");
        bytes32 r;
        bytes32 s;
        uint8   v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "AttestationIndex: bad v");
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "AttestationIndex: ecrecover failed");
        return recovered;
    }
}
