// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * OffchainResolver v2 — EIP-3668 (CCIP Read) resolver for ENS.
 *
 * v2 changes from v1:
 *   - Multi-signer: replaces single `signerAddress` with
 *     `mapping(address => bool) authorizedSigners`
 *   - `addSigner` / `removeSigner` admin functions
 *   - `setSigner` kept for compatibility (adds to mapping, doesn't remove others)
 *
 * Flow:
 *   1. ENS client calls resolve(name, data) on this contract.
 *   2. Contract reverts with OffchainLookup, pointing to gateway URLs.
 *   3. Client queries gateway, gets signed response.
 *   4. Client calls resolveWithProof(response, extraData) to verify.
 *      Any authorized signer's signature is accepted.
 */
contract OffchainResolver {
    // EIP-3668 error — triggers CCIP Read in compliant clients
    error OffchainLookup(
        address sender,
        string[] urls,
        bytes callData,
        bytes4 callbackFunction,
        bytes extraData
    );

    address public owner;
    string[] public gatewayURLs;

    // v2: multiple authorized signers (any gateway node may sign)
    mapping(address => bool) public authorizedSigners;

    // On-chain contenthash per node — read directly by browsers (Brave, etc.)
    // that don't support CCIP Read. Set via setContenthash(), costs gas once.
    mapping(bytes32 => bytes) public contenthashes;

    event GatewayURLsUpdated(string[] urls);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ContenthashUpdated(bytes32 indexed node, bytes contenthash);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(string[] memory _urls, address _initialSigner) {
        owner = msg.sender;
        gatewayURLs = _urls;
        authorizedSigners[_initialSigner] = true;
        emit SignerAdded(_initialSigner);
    }

    // ─── ENS Resolver Interface ──────────────────────────────────────────────

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return
            interfaceId == 0x9061b923 || // IExtendedResolver (resolve/ENSIP-10)
            interfaceId == 0x3b3b57de || // IAddrResolver (addr)
            interfaceId == 0x59d1d43c || // ITextResolver (text)
            interfaceId == 0xbc1c58d1 || // IContentHashResolver (contenthash)
            interfaceId == 0x01ffc9a7;   // IERC165
    }

    /**
     * Returns the on-chain contenthash for a node.
     */
    function contenthash(bytes32 node) external view returns (bytes memory) {
        return contenthashes[node];
    }

    function setContenthash(bytes32 node, bytes calldata _contenthash) external onlyOwner {
        contenthashes[node] = _contenthash;
        emit ContenthashUpdated(node, _contenthash);
    }

    /**
     * Wildcard resolution entry point (ENSIP-10).
     */
    function resolve(bytes calldata name, bytes calldata data)
        external
        view
        returns (bytes memory)
    {
        string[] memory urls = new string[](gatewayURLs.length);
        for (uint i = 0; i < gatewayURLs.length; i++) {
            urls[i] = gatewayURLs[i];
        }

        revert OffchainLookup(
            address(this),
            urls,
            abi.encode(name, data),
            OffchainResolver.resolveWithProof.selector,
            abi.encode(name, data)
        );
    }

    /**
     * Callback — verifies the signed gateway response.
     * Accepts any authorized signer's signature.
     */
    function resolveWithProof(bytes calldata response, bytes calldata extraData)
        external
        view
        returns (bytes memory)
    {
        (bytes memory result, uint64 expires, bytes memory sig) =
            abi.decode(response, (bytes, uint64, bytes));

        require(block.timestamp <= expires, "response expired");

        bytes32 hash = keccak256(
            abi.encodePacked(
                hex"1900",
                address(this),
                expires,
                keccak256(extraData),
                keccak256(result)
            )
        );

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;

        address recovered = ecrecover(
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)),
            v, r, s
        );

        require(authorizedSigners[recovered], "invalid signature");
        return result;
    }

    // ─── Admin ───────────────────────────────────────────────────────────────

    function setGatewayURLs(string[] calldata _urls) external onlyOwner {
        gatewayURLs = _urls;
        emit GatewayURLsUpdated(_urls);
    }

    function addSigner(address signer) external onlyOwner {
        authorizedSigners[signer] = true;
        emit SignerAdded(signer);
    }

    function removeSigner(address signer) external onlyOwner {
        authorizedSigners[signer] = false;
        emit SignerRemoved(signer);
    }

    // kept for v1 compatibility — adds to mapping without removing others
    function setSigner(address signer) external onlyOwner {
        authorizedSigners[signer] = true;
        emit SignerAdded(signer);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
