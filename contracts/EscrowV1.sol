// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title  EscrowV1
/// @notice ERC-8275 trust-minimized escrow for AI agent service payments.
///         Implements IAgentEscrow: createOrder / confirmOrder / disputeOrder /
///         resolveDispute / refundExpiredOrder / getOrder.
///
///         Also serves as the slashRecipient for CommitRevealSettlerV2 — slashed bonds
///         accumulate in `slashPool` via receive(). Pool distribution is V2.
///
///         agentId convention: bytes32(uint160(agentAddress)) — compatible with
///         NodeRegistryV2's address-keyed signer model.
///         Reverse: address(uint160(uint256(agentId))).
///
/// @dev    PROTOTYPE — Sepolia only, not audited.
///         Arbitrators are owner-managed in V1; V2 will gate on NodeRegistryV2 NodeType.
///         ERC-20 support assumes compliant return values. Non-standard tokens (e.g. USDT
///         on mainnet) are not safe to use with V1.
contract EscrowV1 {

    // ── Types ──────────────────────────────────────────────────────────────────

    enum OrderStatus { Pending, Confirmed, Disputed, Refunded, Resolved }

    struct Order {
        bytes32     agentId;
        address     client;
        address     agent;
        address     paymentToken;   // address(0) = native ETH
        uint256     amount;
        uint64      deadline;
        OrderStatus status;
        bytes       metadata;
    }

    // ── Storage ────────────────────────────────────────────────────────────────

    mapping(bytes32 => Order)   public orders;
    mapping(address => bool)    public arbitrators;
    mapping(address => uint256) private _nonces;

    address public owner;
    uint256 public slashPool;       // accumulated slash proceeds from CommitRevealSettlerV2

    // ── Events ─────────────────────────────────────────────────────────────────

    event OrderCreated(bytes32 indexed orderId, bytes32 indexed agentId, address indexed client, uint256 amount);
    event OrderConfirmed(bytes32 indexed orderId);
    event OrderDisputed(bytes32 indexed orderId, bytes reason);
    event OrderResolved(bytes32 indexed orderId, uint8 resolution);
    event OrderRefunded(bytes32 indexed orderId);
    event ArbitratorSet(address indexed arbitrator, bool active);
    event SlashReceived(address indexed from, uint256 amount);

    // ── Errors ─────────────────────────────────────────────────────────────────

    error NotClient();
    error NotParty();
    error NotArbitrator();
    error NotOwner();
    error WrongStatus(OrderStatus got, OrderStatus want);
    error DeadlineNotPassed();
    error InvalidResolution();
    error TransferFailed();
    error ZeroAmount();
    error InvalidDeadline();

    // ── Constructor ────────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
    }

    // ── Admin ──────────────────────────────────────────────────────────────────

    function setArbitrator(address arb, bool active) external {
        if (msg.sender != owner) revert NotOwner();
        arbitrators[arb] = active;
        emit ArbitratorSet(arb, active);
    }

    // ── Receive slash proceeds ─────────────────────────────────────────────────

    /// @dev CommitRevealSettlerV2 calls this when slashing a node.
    ///      Slash proceeds accumulate in slashPool. Distribution is V2.
    receive() external payable {
        slashPool += msg.value;
        emit SlashReceived(msg.sender, msg.value);
    }

    // ── Write: createOrder ─────────────────────────────────────────────────────

    /// @notice Lock funds and create an escrow order.
    function createOrder(
        bytes32        agentId,
        address        paymentToken,
        uint256        amount,
        uint64         deadline,
        bytes calldata metadata
    ) external payable returns (bytes32 orderId) {
        if (amount == 0)                       revert ZeroAmount();
        if (deadline <= block.timestamp)       revert InvalidDeadline();

        address agent = address(uint160(uint256(agentId)));
        require(agent != address(0), "EscrowV1: zero agent");
        require(agent != msg.sender, "EscrowV1: self-order");

        if (paymentToken == address(0)) {
            require(msg.value == amount, "EscrowV1: ETH amount mismatch");
        } else {
            require(msg.value == 0,      "EscrowV1: unexpected ETH");
            bool ok = IERC20(paymentToken).transferFrom(msg.sender, address(this), amount);
            if (!ok) revert TransferFailed();
        }

        orderId = keccak256(abi.encode(msg.sender, agentId, block.timestamp, _nonces[msg.sender]++));

        orders[orderId] = Order({
            agentId:      agentId,
            client:       msg.sender,
            agent:        agent,
            paymentToken: paymentToken,
            amount:       amount,
            deadline:     deadline,
            status:       OrderStatus.Pending,
            metadata:     metadata
        });

        emit OrderCreated(orderId, agentId, msg.sender, amount);
    }

    // ── Write: confirmOrder ────────────────────────────────────────────────────

    /// @notice Client confirms service delivery — releases full payment to agent.
    function confirmOrder(bytes32 orderId) external {
        Order storage o = orders[orderId];
        if (msg.sender != o.client)           revert NotClient();
        if (o.status != OrderStatus.Pending)  revert WrongStatus(o.status, OrderStatus.Pending);

        o.status = OrderStatus.Confirmed;
        _transfer(o.paymentToken, o.agent, o.amount);

        emit OrderConfirmed(orderId);
    }

    // ── Write: disputeOrder ────────────────────────────────────────────────────

    /// @notice Either party opens a dispute. Funds remain locked pending arbitration.
    function disputeOrder(bytes32 orderId, bytes calldata reason) external {
        Order storage o = orders[orderId];
        if (msg.sender != o.client && msg.sender != o.agent) revert NotParty();
        if (o.status != OrderStatus.Pending)  revert WrongStatus(o.status, OrderStatus.Pending);

        o.status = OrderStatus.Disputed;

        emit OrderDisputed(orderId, reason);
    }

    // ── Write: resolveDispute ──────────────────────────────────────────────────

    /// @notice Arbitrator resolves a disputed order.
    /// @param resolution 0 = full refund to client | 1 = full release to agent | 2 = split 50/50
    function resolveDispute(bytes32 orderId, uint8 resolution) external {
        if (!arbitrators[msg.sender])           revert NotArbitrator();
        Order storage o = orders[orderId];
        if (o.status != OrderStatus.Disputed)   revert WrongStatus(o.status, OrderStatus.Disputed);
        if (resolution > 2)                     revert InvalidResolution();

        o.status = OrderStatus.Resolved;

        if (resolution == 0) {
            _transfer(o.paymentToken, o.client, o.amount);
        } else if (resolution == 1) {
            _transfer(o.paymentToken, o.agent, o.amount);
        } else {
            // resolution == 2: split 50/50. Odd wei goes to agent.
            uint256 clientShare = o.amount / 2;
            _transfer(o.paymentToken, o.client, clientShare);
            _transfer(o.paymentToken, o.agent,  o.amount - clientShare);
        }

        emit OrderResolved(orderId, resolution);
    }

    // ── Write: refundExpiredOrder ──────────────────────────────────────────────

    /// @notice Refund a Pending order after its deadline. Permissionless.
    function refundExpiredOrder(bytes32 orderId) external {
        Order storage o = orders[orderId];
        if (o.status != OrderStatus.Pending)   revert WrongStatus(o.status, OrderStatus.Pending);
        if (block.timestamp <= o.deadline)     revert DeadlineNotPassed();

        o.status = OrderStatus.Refunded;
        _transfer(o.paymentToken, o.client, o.amount);

        emit OrderRefunded(orderId);
    }

    // ── Read ────────────────────────────────────────────────────────────────────

    function getOrder(bytes32 orderId) external view returns (
        bytes32      agentId,
        address      client,
        address      agent,
        address      paymentToken,
        uint256      amount,
        uint64       deadline,
        uint8        status,
        bytes memory metadata
    ) {
        Order storage o = orders[orderId];
        return (
            o.agentId,
            o.client,
            o.agent,
            o.paymentToken,
            o.amount,
            o.deadline,
            uint8(o.status),
            o.metadata
        );
    }

    function nonce(address account) external view returns (uint256) {
        return _nonces[account];
    }

    // ── Internal ────────────────────────────────────────────────────────────────

    function _transfer(address token, address to, uint256 amount) internal {
        if (token == address(0)) {
            (bool ok,) = to.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            bool ok = IERC20(token).transfer(to, amount);
            if (!ok) revert TransferFailed();
        }
    }
}
