// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  NodeRegistryV2
/// @notice ERC-8275 node registry with NodeType classification.
///         Extends NodeRegistry with an Origin / Router / Hybrid enum so EscrowV1
///         can route payouts to the correct reward pool at settlement time.
///
/// @dev    PENDING GROUP SIGN-OFF — breaking change to NodeRegistry interface.
///         Deployed: 0xeFae266aE0a74518da320a029dD76F4d47e2a87b (Sepolia, verified)
///         Deploy alongside CommitRevealSettler and EscrowV1 in the next mainnet
///         contract revision cycle. See group DM draft:
///         Downloads/group-dm/pending/msg-group-nodetype-registry-proposal.md
///
///         NodeType pool routing:
///           Origin  — rewarded from Origin pool proportional to sourcePeer contribution
///                     counts as independently observed by Router nodes. No quorum obligations.
///           Router  — rewarded from Router pool proportional to uptime and sync frequency.
///                     Must submit commit + reveal on-chain each period. Quorum signers.
///           Hybrid  — receives both pool shares. Origin share derived from sourcePeer
///                     attribution counted by other routers (not self-reported).
///                     Router share from routing/uptime. V1: fixed 50/50 split.
///
///         Self-misrepresentation is punished economically: a Router that never submits
///         commits forfeits its Router pool share and has its bond slashed after the
///         reveal deadline.
contract NodeRegistryV2 {

    // ── Types ─────────────────────────────────────────────────────────────────

    /// @notice Node classification used by EscrowV1 to route reward pool payouts.
    enum NodeType { Origin, Router, Hybrid }

    struct NodeInfo {
        string   url;
        NodeType nodeType;
        uint256  registeredAt;
    }

    // ── Storage ───────────────────────────────────────────────────────────────

    mapping(address => NodeInfo) private _nodes;
    address[] private _signers;

    // ── Events ────────────────────────────────────────────────────────────────

    event NodeRegistered(address indexed signer, string url, NodeType nodeType);
    event NodeUpdated(address indexed signer, string url, NodeType nodeType);

    // ── Write ─────────────────────────────────────────────────────────────────

    /// @notice Register or update a node.
    ///         `signature` must be EIP-191 personal_sign over
    ///         keccak256("ccip-router:node:" + url).
    ///         The recovered signer is the node's gateway key.
    /// @param  url       The node's CCIP-Read gateway URL.
    /// @param  nodeType  Origin, Router, or Hybrid.
    /// @param  signature EIP-191 signature over the URL commitment.
    function register(
        string   calldata url,
        NodeType          nodeType,
        bytes    calldata signature
    ) external returns (address signer) {
        bytes32 msgHash   = keccak256(bytes(string.concat("ccip-router:node:", url)));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        signer = _recover(ethSigned, signature);

        bool isNew = _nodes[signer].registeredAt == 0;
        _nodes[signer] = NodeInfo({ url: url, nodeType: nodeType, registeredAt: block.timestamp });

        if (isNew) {
            _signers.push(signer);
            emit NodeRegistered(signer, url, nodeType);
        } else {
            emit NodeUpdated(signer, url, nodeType);
        }
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /// @notice Lookup a node by its signer address.
    function getNode(address signer)
        external view
        returns (string memory url, NodeType nodeType, uint256 registeredAt)
    {
        NodeInfo storage n = _nodes[signer];
        return (n.url, n.nodeType, n.registeredAt);
    }

    /// @notice Returns the NodeType of a registered node. Reverts if unregistered.
    function getNodeType(address signer) external view returns (NodeType) {
        require(_nodes[signer].registeredAt != 0, "NodeRegistryV2: not registered");
        return _nodes[signer].nodeType;
    }

    function nodeCount() external view returns (uint256) {
        return _signers.length;
    }

    /// @notice Paginated node list including nodeType.
    function getNodes(uint256 offset, uint256 limit)
        external view
        returns (
            address[]  memory signers,
            string[]   memory urls,
            NodeType[] memory nodeTypes,
            uint256[]  memory timestamps
        )
    {
        uint256 total = _signers.length;
        if (offset >= total) {
            return (new address[](0), new string[](0), new NodeType[](0), new uint256[](0));
        }
        uint256 end = offset + limit > total ? total : offset + limit;
        uint256 n   = end - offset;
        signers    = new address[](n);
        urls       = new string[](n);
        nodeTypes  = new NodeType[](n);
        timestamps = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            address s  = _signers[offset + i];
            signers[i]    = s;
            urls[i]       = _nodes[s].url;
            nodeTypes[i]  = _nodes[s].nodeType;
            timestamps[i] = _nodes[s].registeredAt;
        }
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "NodeRegistryV2: bad sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "NodeRegistryV2: bad v");
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "NodeRegistryV2: ecrecover failed");
        return recovered;
    }
}
