// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  IAttestationVerifier
/// @notice ERC-8183 attestation verifier interface.
///         Called by settlement contracts via the attested complete() overload:
///         IAttestationVerifier.verify(job.reason, proof)
///         The verifier owns the proof encoding scheme entirely.
interface IAttestationVerifier {
    function verify(bytes32 attestationHash, bytes calldata proof) external view returns (bool);
}
