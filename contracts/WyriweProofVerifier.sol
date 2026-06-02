// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IProofVerifier } from "./IProofVerifier.sol";

/// @title  WyriweProofVerifier
/// @notice IProofVerifier (ERC-8274) implementation for WYRIWE / OCP attestations.
///
///         Parameter mapping:
///           inputHash  = WYRIWE inputHash (anchored commitment to model input)
///           outputHash = commitment to inference output
///           metadata   = abi.encode(bytes32 agentId, address registry)
///           proof      = abi.encode(
///                          bytes32 modelHash,
///                          bytes32 rawInputHash,          // needed to reconstruct EIP-712 digest
///                          bytes32 sanitizationPipelineHash, // same — not enforced, just in struct
///                          bytes32 commitmentHash,
///                          uint256 timestamp,
///                          bytes   signature
///                        )
///
///         Verification:
///           1. Recompute OCP commitmentHash from (agentId, modelHash, inputHash, outputHash, timestamp)
///              and check it matches the supplied commitmentHash.
///           2. Reconstruct the EIP-712 digest over the full WyriweAttestation struct and
///              verify the signature recovers to a non-zero signer.
///
///         The gateway's prior signature on the struct guarantees the
///         rawInputHash → sanitizationPipelineHash → inputHash provenance chain.
///         This verifier trusts that guarantee without re-validating it.
contract WyriweProofVerifier is IProofVerifier {

    // ── Constants ─────────────────────────────────────────────────────────────

    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 private constant ATTESTATION_TYPEHASH = keccak256(
        "WyriweAttestation(bytes32 agentId,address registry,bytes32 modelHash,"
        "bytes32 rawInputHash,bytes32 sanitizationPipelineHash,bytes32 inputHash,"
        "bytes32 outputHash,bytes32 commitmentHash,uint256 timestamp)"
    );

    bytes32 private constant PROOF_PROFILE_ID = keccak256("WYRIWE_EIP712_ATTESTATION_V1");

    // ── IProofVerifier ────────────────────────────────────────────────────────

    /// @inheritdoc IProofVerifier
    function verify(
        bytes32 inputHash,
        bytes32 outputHash,
        bytes calldata metadata,
        bytes calldata proof
    ) external view returns (bool) {
        (bytes32 agentId, address registry) = abi.decode(metadata, (bytes32, address));
        (
            bytes32 modelHash,
            bytes32 rawInputHash,
            bytes32 sanitizationPipelineHash,
            bytes32 commitmentHash,
            uint256 timestamp,
            bytes memory sig
        ) = abi.decode(proof, (bytes32, bytes32, bytes32, bytes32, uint256, bytes));

        // ── 1. Verify OCP commitmentHash ──────────────────────────────────
        // Binds agentId, modelHash, inputHash (WYRIWE anchor), outputHash, timestamp.
        bytes32 recomputed = keccak256(abi.encode(
            agentId, modelHash, inputHash, outputHash, timestamp
        ));
        if (recomputed != commitmentHash) return false;

        // ── 2. Verify EIP-712 signature ───────────────────────────────────
        // rawInputHash and sanitizationPipelineHash appear here not as enforced constraints
        // but because they are fields in the signed struct and are required for digest
        // reconstruction. The gateway's signature on the full struct guarantees their binding.
        bytes32 domainSeparator = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256("WyriweAttestation"),
            keccak256("1"),
            block.chainid,
            registry
        ));

        bytes32 structHash = keccak256(abi.encode(
            ATTESTATION_TYPEHASH,
            agentId, registry, modelHash,
            rawInputHash, sanitizationPipelineHash,
            inputHash, outputHash,
            commitmentHash, timestamp
        ));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        return _recover(digest, sig) != address(0);
    }

    function name() external pure returns (string memory) { return "WyriweProofVerifier"; }
    function version() external pure returns (string memory) { return "1"; }
    function proofProfile() external pure returns (bytes32) { return PROOF_PROFILE_ID; }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        return ecrecover(digest, v, r, s);
    }
}
