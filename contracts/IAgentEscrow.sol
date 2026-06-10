// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  IAgentEscrow
/// @notice ERC-8275 trust-minimized escrow payment interface for AI agent services.
///
///         agentId convention: bytes32(uint160(agentAddress)) — compatible with
///         NodeRegistryV2's address-keyed signer model. Reverse: address(uint160(uint256(agentId))).
interface IAgentEscrow {
    // ── Events ──────────────────────────────────────────────────────────────────

    event OrderCreated(bytes32 indexed orderId, bytes32 indexed agentId, address indexed client, uint256 amount);
    event OrderConfirmed(bytes32 indexed orderId);
    event OrderDisputed(bytes32 indexed orderId, bytes reason);
    event OrderResolved(bytes32 indexed orderId, uint8 resolution);
    event OrderRefunded(bytes32 indexed orderId);

    // ── Write ───────────────────────────────────────────────────────────────────

    /// @notice Create an escrow order and lock funds.
    /// @param agentId      bytes32(uint160(agentAddress)) — see convention above.
    /// @param paymentToken ERC-20 token address, or address(0) for native ETH.
    /// @param amount       Payment amount. For ETH orders must equal msg.value.
    /// @param deadline     Unix timestamp for service completion. Order is refundable after this.
    /// @param metadata     Service description hash or IPFS CID.
    /// @return orderId     Unique order identifier.
    function createOrder(
        bytes32  agentId,
        address  paymentToken,
        uint256  amount,
        uint64   deadline,
        bytes calldata metadata
    ) external payable returns (bytes32 orderId);

    /// @notice Client confirms service delivery — releases full payment to agent.
    /// @dev Only the order creator (client) may call this.
    function confirmOrder(bytes32 orderId) external;

    /// @notice Open a dispute. Funds remain locked pending arbitration.
    /// @dev Either the client or agent may call this on a Pending order.
    function disputeOrder(bytes32 orderId, bytes calldata reason) external;

    /// @notice Arbitrator resolves a disputed order.
    /// @param resolution 0 = full refund to client | 1 = full release to agent | 2 = split 50/50.
    /// @dev Only registered arbitrators may call this.
    function resolveDispute(bytes32 orderId, uint8 resolution) external;

    /// @notice Refund a Pending order whose deadline has passed.
    /// @dev Permissionless — any address may trigger.
    function refundExpiredOrder(bytes32 orderId) external;

    // ── Read ────────────────────────────────────────────────────────────────────

    /// @notice Get full order state. status: 0=Pending 1=Confirmed 2=Disputed 3=Refunded 4=Resolved
    function getOrder(bytes32 orderId) external view returns (
        bytes32  agentId,
        address  client,
        address  agent,
        address  paymentToken,
        uint256  amount,
        uint64   deadline,
        uint8    status,
        bytes memory metadata
    );
}
