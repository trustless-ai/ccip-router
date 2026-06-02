// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  IProofVerifier
/// @notice ERC-8274 proof verifier interface.
///
///         A uniform L4 attestation check: "did an authorized party attest that
///         this input produced this output?" Proof format is backend-defined
///         (EIP-712 signature for WYRIWE, ZK proof bytes for zkML, etc.).
///
///         Scope: pure L4 attestation check.
///         Not in scope: L3 on-chain anchoring of inputHash (gateway responsibility),
///         rawInputHash → sanitizationPipelineHash → inputHash provenance chain
///         (the gateway's prior signature guarantees this).
interface IProofVerifier {
    /// @param inputHash   Commitment to the model input (WYRIWE anchor)
    /// @param outputHash  Commitment to the inference output
    /// @param metadata    Backend-specific signer identity: abi.encode(agentId, registry)
    /// @param proof       Backend-specific cryptographic material: the L4 attestation
    function verify(
        bytes32 inputHash,
        bytes32 outputHash,
        bytes calldata metadata,
        bytes calldata proof
    ) external view returns (bool);

    /// @notice Human-readable verifier name
    function name() external view returns (string memory);

    /// @notice Verifier version string
    function version() external view returns (string memory);

    /// @notice Opaque identifier for the proof encoding scheme.
    ///         Off-chain consumers use this to know how to encode the `proof` bytes.
    ///         e.g. keccak256("WYRIWE_EIP712_ATTESTATION_V1")
    function proofProfile() external view returns (bytes32);
}
