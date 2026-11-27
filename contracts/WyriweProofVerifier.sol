// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IProofVerifier } from "./IProofVerifier.sol";

/// @title  WyriweProofVerifier (v2)
/// @notice IProofVerifier (ERC-8274) implementation for WYRIWE (ERC-8299) attestations.
///
///         Parameter mapping:
///           inputHash  = WYRIWE inputHash (commitment to the exact model input)
///           outputHash = commitment to the inference output
///           metadata   = abi.encode(bytes32 agentId, address registry, address attestor)
///           proof      = abi.encode(
///                          bytes32 modelHash,
///                          bytes32 rawInputHash,
///                          bytes32 sanitizationPipelineHash,
///                          bytes32 commitmentHash,
///                          uint256 timestamp,
///                          bytes   signature            // 65 bytes r || s || v
///                        )
///
///         Verification (returns true only if ALL hold):
///           1. commitmentHash == keccak256(abi.encode(agentId, modelHash, inputHash, outputHash, timestamp))
///           2. the EIP-712 signature over the WyriweAttestation struct, under the domain
///              { name "WyriweAttestation", version "1", chainId, verifyingContract = registry },
///              recovers to `attestor` — the attestor this deployment's metadata names.
///
///         v1 (mainnet 0xd8a09d83…, Sepolia 0x001eFFa0…) accepted ANY non-zero signer: anyone
///         could sign an attestation and get `true`. v2 checks the signer against `metadata`.
///         It still does not check that `attestor` is authorised for `agentId` in the registry;
///         an IAgentVerifier that needs that binding performs it before choosing `metadata`.
contract WyriweProofVerifier is IProofVerifier {

    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 private constant ATTESTATION_TYPEHASH = keccak256(
        "WyriweAttestation(bytes32 agentId,address registry,bytes32 modelHash,"
        "bytes32 rawInputHash,bytes32 sanitizationPipelineHash,bytes32 inputHash,"
        "bytes32 outputHash,bytes32 commitmentHash,uint256 timestamp)"
    );

    string private constant PROOF_SYSTEM = "attestation/wyriwe";

    // ERC-8274: proofProfile SHOULD be keccak256(abi.encode(proofSystem(), deploymentSalt)).
    bytes32 private constant PROOF_PROFILE_ID =
        keccak256(abi.encode(PROOF_SYSTEM, keccak256("WYRIWE_EIP712_ATTESTATION_V2_SIGNER_CHECKED")));

    // secp256k1n / 2 — signatures with a higher s are malleated copies and are refused.
    uint256 private constant HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @inheritdoc IProofVerifier
    function verify(
        bytes32 inputHash,
        bytes32 outputHash,
        bytes calldata metadata,
        bytes calldata proof
    ) external view returns (bool) {
        (bytes32 agentId, address registry, address attestor) =
            abi.decode(metadata, (bytes32, address, address));
        if (attestor == address(0)) return false;

        (
            bytes32 modelHash,
            bytes32 rawInputHash,
            bytes32 sanitizationPipelineHash,
            bytes32 commitmentHash,
            uint256 timestamp,
            bytes memory sig
        ) = abi.decode(proof, (bytes32, bytes32, bytes32, bytes32, uint256, bytes));

        // 1. OCP commitment binds agentId, modelHash, inputHash, outputHash, timestamp.
        if (keccak256(abi.encode(agentId, modelHash, inputHash, outputHash, timestamp)) != commitmentHash) {
            return false;
        }

        // 2. EIP-712 signature must recover to the attestor named in metadata.
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
        return _recover(digest, sig) == attestor;
    }

    /// @notice ERC-8274 proof system identifier.
    function proofSystem() external pure returns (string memory) { return PROOF_SYSTEM; }
    function name() external pure returns (string memory) { return "WyriweProofVerifier"; }
    function version() external pure returns (string memory) { return "2"; }
    function proofProfile() external pure returns (bytes32) { return PROOF_PROFILE_ID; }

    function _recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (uint256(s) > HALF_N) return address(0);
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        return ecrecover(digest, v, r, s);
    }
}
