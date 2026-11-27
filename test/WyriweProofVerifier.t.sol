// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { WyriweProofVerifier } from "../contracts/WyriweProofVerifier.sol";
import { WyriweAttestationVerifier } from "../contracts/WyriweAttestationVerifier.sol";

interface Vm {
    function sign(uint256 pk, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function addr(uint256 pk) external returns (address);
    function chainId(uint256) external;
}

contract WyriweProofVerifierTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    WyriweProofVerifier v;

    uint256 constant ATTESTOR_PK = 0xA11CE;
    uint256 constant STRANGER_PK = 0xBAD;
    bytes32 constant AGENT = bytes32(uint256(860));
    address constant REGISTRY = address(0x8004);
    bytes32 constant MODEL = keccak256("model");
    bytes32 constant RAW = keccak256("raw");
    bytes32 constant SAN = keccak256("san");
    bytes32 constant INPUT = keccak256("input");
    bytes32 constant OUTPUT = keccak256("output");
    uint256 constant TS = 1_790_000_000;
    uint256 constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    uint256 constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function setUp() public { v = new WyriweProofVerifier(); }

    function _commitment() internal pure returns (bytes32) {
        return keccak256(abi.encode(AGENT, MODEL, INPUT, OUTPUT, TS));
    }

    function _digest(address registry, bytes32 commitment) internal view returns (bytes32) {
        bytes32 domain = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("WyriweAttestation"), keccak256("1"), block.chainid, registry));
        bytes32 structHash = keccak256(abi.encode(
            keccak256("WyriweAttestation(bytes32 agentId,address registry,bytes32 modelHash,bytes32 rawInputHash,bytes32 sanitizationPipelineHash,bytes32 inputHash,bytes32 outputHash,bytes32 commitmentHash,uint256 timestamp)"),
            AGENT, registry, MODEL, RAW, SAN, INPUT, OUTPUT, commitment, TS));
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    function _sig(uint256 pk, bytes32 digest) internal returns (bytes memory) {
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, vv);
    }

    function _proof(bytes32 commitment, bytes memory sig) internal pure returns (bytes memory) {
        return abi.encode(MODEL, RAW, SAN, commitment, TS, sig);
    }

    function _meta(address attestor) internal pure returns (bytes memory) {
        return abi.encode(AGENT, REGISTRY, attestor);
    }

    function test_attestorSignatureVerifies() public {
        bytes memory p = _proof(_commitment(), _sig(ATTESTOR_PK, _digest(REGISTRY, _commitment())));
        require(v.verify(INPUT, OUTPUT, _meta(vm.addr(ATTESTOR_PK)), p), "attestor must verify");
    }

    // The v1 hole: any key's valid signature returned true.
    function test_strangerSignatureRejected() public {
        bytes memory p = _proof(_commitment(), _sig(STRANGER_PK, _digest(REGISTRY, _commitment())));
        require(!v.verify(INPUT, OUTPUT, _meta(vm.addr(ATTESTOR_PK)), p), "stranger must not verify");
    }

    function test_zeroAttestorRejected() public {
        bytes memory p = _proof(_commitment(), _sig(ATTESTOR_PK, _digest(REGISTRY, _commitment())));
        require(!v.verify(INPUT, OUTPUT, _meta(address(0)), p), "zero attestor must not verify");
    }

    function test_wrongCommitmentRejected() public {
        bytes32 bad = keccak256("other");
        bytes memory p = _proof(bad, _sig(ATTESTOR_PK, _digest(REGISTRY, bad)));
        require(!v.verify(INPUT, OUTPUT, _meta(vm.addr(ATTESTOR_PK)), p), "commitment must bind");
    }

    function test_otherOutputRejected() public {
        bytes memory p = _proof(_commitment(), _sig(ATTESTOR_PK, _digest(REGISTRY, _commitment())));
        require(!v.verify(INPUT, keccak256("other output"), _meta(vm.addr(ATTESTOR_PK)), p), "output must bind");
    }

    function test_signatureForOtherRegistryRejected() public {
        bytes memory p = _proof(_commitment(), _sig(ATTESTOR_PK, _digest(address(0xBEEF), _commitment())));
        require(!v.verify(INPUT, OUTPUT, _meta(vm.addr(ATTESTOR_PK)), p), "domain must bind registry");
    }

    function test_highSMalleatedSignatureRejected() public {
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(ATTESTOR_PK, _digest(REGISTRY, _commitment()));
        bytes32 s2 = bytes32(N - uint256(s));
        uint8 v2 = vv == 27 ? 28 : 27;
        require(uint256(s2) > HALF_N, "test setup: s2 is high");
        bytes memory p = _proof(_commitment(), abi.encodePacked(r, s2, v2));
        require(!v.verify(INPUT, OUTPUT, _meta(vm.addr(ATTESTOR_PK)), p), "high-s copy must not verify");
    }

    function test_proofSystemAndProfile() public view {
        require(keccak256(bytes(v.proofSystem())) == keccak256("attestation/wyriwe"), "proofSystem");
        require(v.proofProfile() == keccak256(abi.encode("attestation/wyriwe", keccak256("WYRIWE_EIP712_ATTESTATION_V2_SIGNER_CHECKED"))), "proofProfile");
        require(keccak256(bytes(v.version())) == keccak256("2"), "version");
    }

    function test_attestationVerifierChecksSigner() public {
        WyriweAttestationVerifier av = new WyriweAttestationVerifier(vm.addr(ATTESTOR_PK));
        WyriweAttestationVerifier.WyriweAttestation memory a = WyriweAttestationVerifier.WyriweAttestation(
            AGENT, REGISTRY, MODEL, RAW, SAN, INPUT, OUTPUT, _commitment(), TS);
        bytes32 d = _digest(REGISTRY, _commitment());
        require(av.verify(_commitment(), abi.encode(a, _sig(ATTESTOR_PK, d))), "attestor verifies");
        require(!av.verify(_commitment(), abi.encode(a, _sig(STRANGER_PK, d))), "stranger rejected");
    }
}
