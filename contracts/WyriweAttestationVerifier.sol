// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IAttestationVerifier } from "./IAttestationVerifier.sol";

/// @title  WyriweAttestationVerifier
/// @notice IAttestationVerifier implementation for WYRIWE / OCP attestations.
///
///         Mapping for ERC-8183 attested settlement:
///           attestationHash = commitmentHash
///                           = keccak256(abi.encode(agentId, modelHash, inputHash, outputHash, timestamp))
///           proof           = abi.encode(WyriweAttestation attestation, bytes signature)
///
///         verify() recovers the gateway signer from the EIP-712 signature, recomputes
///         commitmentHash from the decoded struct, and checks both against attestationHash.
///         No external contract calls — fully self-contained.
contract WyriweAttestationVerifier is IAttestationVerifier {

    // ── Types ─────────────────────────────────────────────────────────────────

    struct WyriweAttestation {
        bytes32 agentId;
        address registry;                   // ERC-8004 registry — EIP-712 verifyingContract
        bytes32 modelHash;
        bytes32 rawInputHash;
        bytes32 sanitizationPipelineHash;
        bytes32 inputHash;                  // WYRIWE anchor — must be included in commitmentHash
        bytes32 outputHash;
        bytes32 commitmentHash;             // OCP observation commitment — this == attestationHash
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

    // ── IAttestationVerifier ──────────────────────────────────────────────────

    /// @notice Verify a WYRIWE attestation proof.
    /// @param  attestationHash  The commitmentHash stored as job.reason in ERC-8183.
    /// @param  proof            abi.encode(WyriweAttestation attestation, bytes signature)
    /// @return true if:
    ///           1. The recomputed OCP commitmentHash matches attestationHash.
    ///           2. The EIP-712 signature over the struct is valid (non-zero signer recovered).
    function verify(
        bytes32 attestationHash,
        bytes calldata proof
    ) external view returns (bool) {
        (WyriweAttestation memory a, bytes memory sig) = abi.decode(
            proof,
            (WyriweAttestation, bytes)
        );

        // ── 1. Recompute and check commitmentHash ──────────────────────────
        // OCP observation commitment: binds agentId, modelHash, inputHash (WYRIWE anchor),
        // outputHash, and timestamp. inputHash is an explicit named field — independently
        // verifiable from the struct without trusting the verifier for the binding.
        bytes32 recomputed = keccak256(abi.encode(
            a.agentId,
            a.modelHash,
            a.inputHash,
            a.outputHash,
            a.timestamp
        ));
        if (recomputed != attestationHash) return false;
        if (a.commitmentHash != attestationHash) return false;

        // ── 2. Verify EIP-712 signature ────────────────────────────────────
        // Domain: name="WyriweAttestation", version="1", chainId=block.chainid,
        //         verifyingContract=a.registry (ERC-8004 registry, NOT this contract).
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
        address signer = _recover(digest, sig);

        return signer != address(0);
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8   v;
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
