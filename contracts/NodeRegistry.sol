// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  NodeRegistry
/// @notice Public directory of ccip-router nodes.
///         Any node may register or update its URL by proving ownership of its signing key.
///         The relayer (msg.sender) does not need to be the signing key — gateways
///         can register without holding ETH in their hot key.
contract NodeRegistry {

    struct NodeInfo {
        string  url;
        uint256 registeredAt;
    }

    mapping(address => NodeInfo) private _nodes;
    address[] private _signers;

    event NodeRegistered(address indexed signer, string url);
    event NodeUpdated(address indexed signer, string url);

    /// @notice Register or update a node.
    ///         `signature` must be EIP-191 personal_sign over keccak256("ccip-router:node:" + url).
    ///         The signing key is the node's gateway key — recovered to derive the signer address.
    function register(string calldata url, bytes calldata signature) external returns (address signer) {
        bytes32 msgHash   = keccak256(bytes(string.concat("ccip-router:node:", url)));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        signer = _recover(ethSigned, signature);

        bool isNew = _nodes[signer].registeredAt == 0;
        _nodes[signer] = NodeInfo({ url: url, registeredAt: block.timestamp });

        if (isNew) {
            _signers.push(signer);
            emit NodeRegistered(signer, url);
        } else {
            emit NodeUpdated(signer, url);
        }
    }

    /// @notice Lookup a node by its signer address.
    function getNode(address signer) external view returns (string memory url, uint256 registeredAt) {
        NodeInfo storage n = _nodes[signer];
        return (n.url, n.registeredAt);
    }

    function nodeCount() external view returns (uint256) {
        return _signers.length;
    }

    /// @notice Paginated node list.
    function getNodes(uint256 offset, uint256 limit)
        external view
        returns (address[] memory signers, string[] memory urls, uint256[] memory timestamps)
    {
        uint256 total = _signers.length;
        if (offset >= total) return (new address[](0), new string[](0), new uint256[](0));
        uint256 end = offset + limit > total ? total : offset + limit;
        uint256 n   = end - offset;
        signers    = new address[](n);
        urls       = new string[](n);
        timestamps = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            address s  = _signers[offset + i];
            signers[i]    = s;
            urls[i]       = _nodes[s].url;
            timestamps[i] = _nodes[s].registeredAt;
        }
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "NodeRegistry: bad sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "NodeRegistry: bad v");
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "NodeRegistry: ecrecover failed");
        return recovered;
    }
}
