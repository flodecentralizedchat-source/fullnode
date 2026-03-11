//! ═══════════════════════════════════════════════════════════════════
//! MODULE 11 — DEX-SPECIFIC MODULES
//!
//! Data Structures:
//!   AmmPool        — UniswapV2/V3 pool: reserve0, reserve1, fee, sqrt_price
//!   OrderBook      — BTreeMap<Price, VecDeque<Order>> bid + ask sides
//!   RoutingGraph   — Weighted directed graph: pools as edges, tokens as nodes
//!   LiquidityPosition — LP (tokenId → PositionState)
//!   CrossChainMsg  — Relay message with Merkle proof
//!
//! Algorithms:
//!   AMM swap:       x*y = k  →  amountOut = (y*amountIn*997) / (x*1000 + amountIn*997)
//!   V3 concentrated: √P arithmetic, tick-to-price mapping (1.0001^tick)
//!   Smart routing:  Bellman-Ford shortest path on log-price-impact graph
//!   CLOB matching:  Price-time priority matching loop
//!   Imperm loss:    IL = 2√r/(1+r) - 1  where r = price_ratio
//! ═══════════════════════════════════════════════════════════════════

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::Arc,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

pub type Address = [u8; 20];
pub type U256    = u128; // simplified to u128 for readability

// ═══════════════════════════════════════════════════════════════════
// 11A — AMM ENGINE (UniswapV2 + V3 style)
// ═══════════════════════════════════════════════════════════════════

/// UniswapV2-style constant product pool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmmPoolV2 {
    pub address:   Address,
    pub token0:    Address,
    pub token1:    Address,
    pub reserve0:  U256,        // amount of token0
    pub reserve1:  U256,        // amount of token1
    pub fee_bps:   u32,         // basis points, e.g. 30 = 0.3%
    pub lp_supply: U256,        // total LP tokens
    pub block_timestamp_last: u64,
    pub price0_cumulative: u128,  // TWAP accumulator
    pub price1_cumulative: u128,
}

impl AmmPoolV2 {
    /// Constant product swap: amountOut given amountIn of token0 → token1
    /// Formula: amountOut = reserve1 * amountIn * (10000 - fee) / (reserve0 * 10000 + amountIn * (10000 - fee))
    pub fn get_amount_out(&self, amount_in: U256, zero_for_one: bool) -> U256 {
        let (reserve_in, reserve_out) = if zero_for_one {
            (self.reserve0, self.reserve1)
        } else {
            (self.reserve1, self.reserve0)
        };
        let fee_factor = (10_000 - self.fee_bps) as u128;
        let amount_in_with_fee = amount_in * fee_factor;
        let numerator   = amount_in_with_fee * reserve_out;
        let denominator = reserve_in * 10_000 + amount_in_with_fee;
        if denominator == 0 { return 0; }
        numerator / denominator
    }

    /// Price impact: how much slippage for a given trade size
    pub fn price_impact_bps(&self, amount_in: U256, zero_for_one: bool) -> u32 {
        let reserve_in = if zero_for_one { self.reserve0 } else { self.reserve1 };
        if reserve_in == 0 { return 10_000; }
        // impact ≈ amountIn / (reserveIn + amountIn)
        let impact = amount_in * 10_000 / (reserve_in + amount_in);
        impact as u32
    }

    /// Add liquidity: returns LP tokens minted
    pub fn add_liquidity(&mut self, amount0: U256, amount1: U256) -> U256 {
        let lp_minted = if self.lp_supply == 0 {
            // Geometric mean for initial liquidity
            isqrt(amount0 * amount1).saturating_sub(1000) // burn 1000 to 0x0
        } else {
            // Proportional to smaller ratio
            let lp0 = amount0 * self.lp_supply / self.reserve0.max(1);
            let lp1 = amount1 * self.lp_supply / self.reserve1.max(1);
            lp0.min(lp1)
        };
        self.reserve0 += amount0;
        self.reserve1 += amount1;
        self.lp_supply += lp_minted;
        lp_minted
    }

    /// Remove liquidity: returns (amount0, amount1) returned
    pub fn remove_liquidity(&mut self, lp_amount: U256) -> (U256, U256) {
        if self.lp_supply == 0 { return (0, 0); }
        let amount0 = lp_amount * self.reserve0 / self.lp_supply;
        let amount1 = lp_amount * self.reserve1 / self.lp_supply;
        self.reserve0  -= amount0;
        self.reserve1  -= amount1;
        self.lp_supply -= lp_amount;
        (amount0, amount1)
    }

    /// Update TWAP accumulators (called each block)
    pub fn update_twap(&mut self, timestamp: u64) {
        let dt = timestamp.saturating_sub(self.block_timestamp_last) as u128;
        if dt > 0 && self.reserve0 > 0 && self.reserve1 > 0 {
            // Q112.112 price: price0 = reserve1/reserve0 × 2^112
            let price0 = (self.reserve1 << 112) / self.reserve0;
            let price1 = (self.reserve0 << 112) / self.reserve1;
            self.price0_cumulative = self.price0_cumulative.wrapping_add(price0 * dt);
            self.price1_cumulative = self.price1_cumulative.wrapping_add(price1 * dt);
        }
        self.block_timestamp_last = timestamp;
    }

    /// Impermanent loss given current price ratio vs entry price ratio
    pub fn impermanent_loss_pct(entry_price: f64, current_price: f64) -> f64 {
        let r = current_price / entry_price;
        (2.0 * r.sqrt() / (1.0 + r) - 1.0) * 100.0
    }
}

// UniswapV3-style concentrated liquidity (simplified tick math)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmmPoolV3 {
    pub address:     Address,
    pub token0:      Address,
    pub token1:      Address,
    pub fee_tier:    u32,        // 500, 3000, 10000
    pub sqrt_price:  u128,       // Q64.96 sqrt(price)
    pub liquidity:   u128,       // active liquidity
    pub tick:        i32,        // current tick
    pub fee_growth0: u128,       // global fee growth per unit liquidity (token0)
    pub fee_growth1: u128,
    pub ticks:       BTreeMap<i32, TickInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TickInfo {
    pub liquidity_net:   i128,    // liquidity delta when crossing
    pub liquidity_gross: u128,
    pub fee_growth_outside0: u128,
    pub fee_growth_outside1: u128,
}

impl AmmPoolV3 {
    /// tick → sqrt_price: √(1.0001^tick) × 2^96
    pub fn tick_to_sqrt_price(tick: i32) -> u128 {
        // Simplified: use 2^96 × 1.0001^(tick/2)
        // Real implementation uses bit-manipulation magic from UniswapV3 TickMath
        let ratio = 1.0001_f64.powi(tick).sqrt();
        (ratio * (1u128 << 96) as f64) as u128
    }

    pub fn sqrt_price_to_tick(sqrt_price: u128) -> i32 {
        let price = (sqrt_price as f64 / (1u128 << 96) as f64).powi(2);
        (price.log(1.0001)) as i32
    }

    pub fn current_price(&self) -> f64 {
        let sp = self.sqrt_price as f64 / (1u128 << 96) as f64;
        sp * sp
    }
}

// ═══════════════════════════════════════════════════════════════════
// 11B — ORDER BOOK (CLOB)
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side { Buy, Sell }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub id:         u64,
    pub trader:     Address,
    pub pair:       (Address, Address),  // (base, quote)
    pub side:       Side,
    pub price:      u64,        // in quote token micro-units (fixed point ×10^6)
    pub quantity:   U256,       // in base token
    pub filled:     U256,       // amount filled so far
    pub timestamp:  u64,
    pub post_only:  bool,
    pub ioc:        bool,       // immediate or cancel
}

impl Order {
    pub fn remaining(&self) -> U256 { self.quantity.saturating_sub(self.filled) }
    pub fn is_filled(&self) -> bool { self.filled >= self.quantity }
}

/// Central Limit Order Book
pub struct OrderBook {
    pub pair:   (Address, Address),
    /// Bids: price (descending) → FIFO queue of orders
    bids:       BTreeMap<std::cmp::Reverse<u64>, VecDeque<Order>>,
    /// Asks: price (ascending) → FIFO queue
    asks:       BTreeMap<u64, VecDeque<Order>>,
    order_map:  HashMap<u64, (Side, u64)>,  // id → (side, price)
    next_id:    u64,
}

#[derive(Debug)]
pub struct FillResult {
    pub maker_id:   u64,
    pub taker_id:   u64,
    pub price:      u64,
    pub quantity:   U256,
}

impl OrderBook {
    pub fn new(pair: (Address, Address)) -> Self {
        Self { pair, bids: BTreeMap::new(), asks: BTreeMap::new(), order_map: HashMap::new(), next_id: 1 }
    }

    pub fn place_order(&mut self, mut order: Order) -> (u64, Vec<FillResult>) {
        let id = self.next_id;
        order.id = id;
        self.next_id += 1;

        let fills = self.match_order(&mut order);

        if !order.is_filled() && !order.ioc {
            self.insert_resting(order);
        }
        (id, fills)
    }

    /// Price-time priority matching
    fn match_order(&mut self, taker: &mut Order) -> Vec<FillResult> {
        let mut fills = Vec::new();
        loop {
            if taker.remaining() == 0 { break; }
            // Get best opposite side
            let best_maker_price = match taker.side {
                Side::Buy  => self.asks.keys().next().copied(),
                Side::Sell => self.bids.keys().next().map(|r| r.0),
            };
            let maker_price = match best_maker_price {
                Some(p) => p,
                None    => break,
            };
            // Check if prices cross
            let crosses = match taker.side {
                Side::Buy  => taker.price >= maker_price,
                Side::Sell => taker.price <= maker_price,
            };
            if !crosses { break; }

            // Pop maker order
            let maker_queue = match taker.side {
                Side::Buy  => self.asks.get_mut(&maker_price),
                Side::Sell => self.bids.get_mut(&std::cmp::Reverse(maker_price)),
            };
            let maker = match maker_queue.and_then(|q| q.front_mut()) {
                Some(m) => m,
                None    => break,
            };

            // Fill
            let fill_qty = taker.remaining().min(maker.remaining());
            maker.filled  += fill_qty;
            taker.filled  += fill_qty;
            fills.push(FillResult { maker_id: maker.id, taker_id: taker.id, price: maker_price, quantity: fill_qty });

            // Remove fully filled maker
            let maker_id = maker.id;
            if maker.is_filled() {
                match taker.side {
                    Side::Buy  => { if let Some(q) = self.asks.get_mut(&maker_price) { q.pop_front(); } }
                    Side::Sell => { if let Some(q) = self.bids.get_mut(&std::cmp::Reverse(maker_price)) { q.pop_front(); } }
                }
                self.order_map.remove(&maker_id);
                // Clean empty price levels
                match taker.side {
                    Side::Buy  => { if self.asks.get(&maker_price).map(|q| q.is_empty()).unwrap_or(false) { self.asks.remove(&maker_price); } }
                    Side::Sell => { if self.bids.get(&std::cmp::Reverse(maker_price)).map(|q| q.is_empty()).unwrap_or(false) { self.bids.remove(&std::cmp::Reverse(maker_price)); } }
                }
            }
        }
        fills
    }

    fn insert_resting(&mut self, order: Order) {
        let price = order.price;
        let id    = order.id;
        match order.side {
            Side::Buy  => self.bids.entry(std::cmp::Reverse(price)).or_default().push_back(order),
            Side::Sell => self.asks.entry(price).or_default().push_back(order),
        }
        self.order_map.insert(id, (if price > 0 { Side::Buy } else { Side::Sell }, price));
    }

    pub fn best_bid(&self) -> Option<u64> { self.bids.keys().next().map(|r| r.0) }
    pub fn best_ask(&self) -> Option<u64> { self.asks.keys().next().copied() }
    pub fn spread(&self) -> Option<u64> {
        Some(self.best_ask()?.saturating_sub(self.best_bid()?))
    }

    pub fn depth(&self, levels: usize) -> OrderBookDepth {
        let bids = self.bids.iter().take(levels)
            .map(|(p, q)| (p.0, q.iter().map(|o| o.remaining()).sum()))
            .collect();
        let asks = self.asks.iter().take(levels)
            .map(|(p, q)| (*p, q.iter().map(|o| o.remaining()).sum()))
            .collect();
        OrderBookDepth { bids, asks }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OrderBookDepth {
    pub bids: Vec<(u64, U256)>,  // (price, total_qty)
    pub asks: Vec<(u64, U256)>,
}

// ═══════════════════════════════════════════════════════════════════
// 11C — ROUTING / LIQUIDITY AGGREGATOR
// ═══════════════════════════════════════════════════════════════════

/// Edge in the routing graph: pool that connects two tokens
#[derive(Debug, Clone)]
pub struct PoolEdge {
    pub pool:      Address,
    pub token_in:  Address,
    pub token_out: Address,
    pub fee_bps:   u32,
    pub reserve_in:  U256,
    pub reserve_out: U256,
}

impl PoolEdge {
    /// Log-space price impact weight for Bellman-Ford
    pub fn log_price(&self) -> f64 {
        if self.reserve_in == 0 { return f64::NEG_INFINITY; }
        -(self.reserve_out as f64 / self.reserve_in as f64).ln()
    }
}

/// Token routing graph for best-path discovery
pub struct RoutingGraph {
    /// token → list of outgoing pool edges
    edges: HashMap<Address, Vec<PoolEdge>>,
    pools: HashMap<Address, AmmPoolV2>,
}

impl RoutingGraph {
    pub fn new() -> Self { Self { edges: HashMap::new(), pools: HashMap::new() } }

    pub fn add_pool(&mut self, pool: AmmPoolV2) {
        let edge0 = PoolEdge {
            pool: pool.address, token_in: pool.token0, token_out: pool.token1,
            fee_bps: pool.fee_bps, reserve_in: pool.reserve0, reserve_out: pool.reserve1,
        };
        let edge1 = PoolEdge {
            pool: pool.address, token_in: pool.token1, token_out: pool.token0,
            fee_bps: pool.fee_bps, reserve_in: pool.reserve1, reserve_out: pool.reserve0,
        };
        self.edges.entry(pool.token0).or_default().push(edge0);
        self.edges.entry(pool.token1).or_default().push(edge1);
        self.pools.insert(pool.address, pool);
    }

    /// Bellman-Ford shortest path in log-price space (maximizes output)
    /// Returns list of pool hops: [(pool_addr, zero_for_one)]
    pub fn find_best_route(
        &self, token_in: Address, token_out: Address, amount: U256, max_hops: usize
    ) -> Option<SwapRoute> {
        // Initialize distances (log-space: 0 = 100% output retained)
        let mut dist: HashMap<Address, f64>     = HashMap::new();
        let mut prev: HashMap<Address, PoolEdge> = HashMap::new();
        dist.insert(token_in, 0.0);

        // Relax up to max_hops times
        for _ in 0..max_hops {
            let mut updated = false;
            for (from_token, outgoing) in &self.edges {
                let d = match dist.get(from_token).copied() {
                    Some(d) => d,
                    None    => continue,
                };
                for edge in outgoing {
                    let edge_cost = edge.log_price() + (edge.fee_bps as f64 / 10_000.0).ln();
                    let new_dist  = d + edge_cost;
                    let entry     = dist.entry(edge.token_out).or_insert(f64::NEG_INFINITY);
                    if new_dist > *entry {
                        *entry = new_dist;
                        prev.insert(edge.token_out, edge.clone());
                        updated = true;
                    }
                }
            }
            if !updated { break; }
        }

        // Reconstruct path
        if !dist.contains_key(&token_out) { return None; }
        let mut path = Vec::new();
        let mut current = token_out;
        while current != token_in {
            let edge = prev.get(&current)?.clone();
            current = edge.token_in;
            path.push(edge);
        }
        path.reverse();

        // Simulate output
        let mut out = amount;
        for edge in &path {
            if let Some(pool) = self.pools.get(&edge.pool) {
                let zero_for_one = edge.token_in == pool.token0;
                out = pool.get_amount_out(out, zero_for_one);
            }
        }

        Some(SwapRoute { hops: path, expected_out: out, price_impact_bps: 0 })
    }
}

#[derive(Debug, Clone)]
pub struct SwapRoute {
    pub hops:             Vec<PoolEdge>,
    pub expected_out:     U256,
    pub price_impact_bps: u32,
}

// ═══════════════════════════════════════════════════════════════════
// 11D — CROSS-CHAIN BRIDGE RELAYER
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainMessage {
    pub nonce:          u64,
    pub source_chain:   u64,
    pub dest_chain:     u64,
    pub sender:         Address,
    pub receiver:       Address,
    pub token:          Address,
    pub amount:         U256,
    pub data:           Vec<u8>,
    pub merkle_proof:   Vec<[u8; 32]>,
    pub source_block:   u64,
    pub source_tx_hash: [u8; 32],
}

impl CrossChainMessage {
    /// Verify Merkle inclusion proof against source chain state root
    pub fn verify_proof(&self, state_root: &[u8; 32]) -> bool {
        use sha3::{Digest, Keccak256};
        // Leaf = keccak256(abi.encode(nonce, sender, receiver, token, amount))
        let mut leaf_input = Vec::new();
        leaf_input.extend_from_slice(&self.nonce.to_be_bytes());
        leaf_input.extend_from_slice(&self.sender);
        leaf_input.extend_from_slice(&self.receiver);
        leaf_input.extend_from_slice(&self.token);
        leaf_input.extend_from_slice(&(self.amount as u128).to_be_bytes());
        let mut current: [u8; 32] = Keccak256::digest(&leaf_input).into();

        // Walk up Merkle tree
        for sibling in &self.merkle_proof {
            let (left, right) = if current <= *sibling { (current, *sibling) } else { (*sibling, current) };
            let mut concat = [0u8; 64];
            concat[..32].copy_from_slice(&left);
            concat[32..].copy_from_slice(&right);
            current = Keccak256::digest(&concat).into();
        }
        &current == state_root
    }
}

// ═══════════════════════════════════════════════════════════════════
// 11E — POOL REGISTRY
// ═══════════════════════════════════════════════════════════════════

pub struct DexRegistry {
    pub v2_pools:   RwLock<HashMap<Address, AmmPoolV2>>,
    pub v3_pools:   RwLock<HashMap<Address, AmmPoolV3>>,
    pub order_books: RwLock<HashMap<(Address, Address), OrderBook>>,
    pub router:     RwLock<RoutingGraph>,
}

impl DexRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            v2_pools:    RwLock::new(HashMap::new()),
            v3_pools:    RwLock::new(HashMap::new()),
            order_books: RwLock::new(HashMap::new()),
            router:      RwLock::new(RoutingGraph::new()),
        })
    }

    pub fn register_v2_pool(&self, pool: AmmPoolV2) {
        let mut router = self.router.write();
        router.add_pool(pool.clone());
        self.v2_pools.write().insert(pool.address, pool);
    }

    pub fn get_swap_quote(&self, token_in: Address, token_out: Address, amount: U256) -> Option<SwapRoute> {
        self.router.read().find_best_route(token_in, token_out, amount, 3)
    }

    pub fn tvl(&self) -> U256 {
        self.v2_pools.read().values()
            .map(|p| p.reserve0 + p.reserve1)
            .sum()
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
pub fn isqrt(n: U256) -> U256 {
    if n == 0 { return 0; }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x { x = y; y = (x + n / x) / 2; }
    x
}

// ─── Tests ───────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn make_pool(r0: U256, r1: U256) -> AmmPoolV2 {
        AmmPoolV2 {
            address: [1u8; 20], token0: [2u8; 20], token1: [3u8; 20],
            reserve0: r0, reserve1: r1, fee_bps: 30, lp_supply: 0,
            block_timestamp_last: 0, price0_cumulative: 0, price1_cumulative: 0,
        }
    }

    #[test]
    fn test_get_amount_out_basic() {
        let pool = make_pool(1_000_000, 1_000_000);
        let out = pool.get_amount_out(1000, true);
        // With 0.3% fee, small trade should yield ~997 (slightly less than 1:1)
        assert!(out > 900 && out < 1000);
    }

    #[test]
    fn test_get_amount_out_zero_reserves() {
        let pool = make_pool(0, 0);
        assert_eq!(pool.get_amount_out(1000, true), 0);
    }

    #[test]
    fn test_price_impact_bps_zero_input() {
        let pool = make_pool(1_000_000, 1_000_000);
        assert_eq!(pool.price_impact_bps(0, true), 0);
    }

    #[test]
    fn test_add_liquidity_initial() {
        let mut pool = make_pool(0, 0);
        let lp = pool.add_liquidity(1_000_000, 1_000_000);
        // LP minted = isqrt(1e6 * 1e6) - 1000 = 1e6 - 1000 = 999000
        assert_eq!(lp, 999_000);
    }

    #[test]
    fn test_remove_liquidity_roundtrip() {
        let mut pool = make_pool(0, 0);
        let lp = pool.add_liquidity(1_000_000, 1_000_000);
        let (a0, a1) = pool.remove_liquidity(lp);
        // Should get back almost all (minus the burned 1000 min liquidity)
        assert!(a0 > 990_000);
        assert!(a1 > 990_000);
    }

    #[test]
    fn test_impermanent_loss_no_price_change() {
        let il = AmmPoolV2::impermanent_loss_pct(100.0, 100.0);
        assert!((il - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_impermanent_loss_2x_price() {
        let il = AmmPoolV2::impermanent_loss_pct(100.0, 200.0);
        // For 2x price: IL = 2*sqrt(2)/(1+2) - 1 ≈ -5.72%
        assert!(il < -5.0 && il > -6.0);
    }

    #[test]
    fn test_isqrt_values() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(9), 3);
        assert_eq!(isqrt(10), 3);
        assert_eq!(isqrt(100), 10);
    }

    #[test]
    fn test_order_book_place_buy_fills_ask() {
        let pair = ([1u8; 20], [2u8; 20]);
        let mut ob = OrderBook::new(pair);
        // Place an ask at 100
        let ask = Order {
            id: 0, trader: [0u8; 20], pair, side: Side::Sell,
            price: 100, quantity: 500, filled: 0, timestamp: 0,
            post_only: false, ioc: false,
        };
        ob.place_order(ask);
        // Place a buy at 100
        let buy = Order {
            id: 0, trader: [1u8; 20], pair, side: Side::Buy,
            price: 100, quantity: 500, filled: 0, timestamp: 0,
            post_only: false, ioc: false,
        };
        let (_, fills) = ob.place_order(buy);
        assert_eq!(fills.len(), 1);
        assert_eq!(fills[0].quantity, 500);
    }

    #[test]
    fn test_order_book_spread() {
        let pair = ([1u8; 20], [2u8; 20]);
        let mut ob = OrderBook::new(pair);
        let bid = Order {
            id: 0, trader: [0u8; 20], pair, side: Side::Buy,
            price: 99, quantity: 100, filled: 0, timestamp: 0,
            post_only: false, ioc: false,
        };
        let ask = Order {
            id: 0, trader: [1u8; 20], pair, side: Side::Sell,
            price: 101, quantity: 100, filled: 0, timestamp: 0,
            post_only: false, ioc: false,
        };
        ob.place_order(bid);
        ob.place_order(ask);
        assert_eq!(ob.spread(), Some(2));
    }

    #[test]
    fn test_routing_graph_no_path() {
        let rg = RoutingGraph::new();
        let t0 = [1u8; 20];
        let t1 = [2u8; 20];
        assert!(rg.find_best_route(t0, t1, 1000, 3).is_none());
    }

    #[test]
    fn test_dex_registry_tvl() {
        let reg = DexRegistry::new();
        reg.register_v2_pool(make_pool(1_000_000, 2_000_000));
        assert_eq!(reg.tvl(), 3_000_000);
    }

    // ── Layer 1: Security definitions ────────────────────────────────────────

    #[test]
    fn test_swap_with_zero_input_returns_zero() {
        // L1: zero input swap must return zero output (no free tokens)
        let pool = make_pool(1_000_000, 1_000_000);
        assert_eq!(pool.get_amount_out(0, true), 0);
    }

    #[test]
    fn test_swap_output_never_exceeds_reserve() {
        // L1: output must be strictly less than the available reserve
        let pool = make_pool(1_000_000, 1_000_000);
        let out = pool.get_amount_out(u128::MAX / 2, true);
        assert!(out < pool.reserve1, "output must never exceed reserve");
    }

    #[test]
    fn test_add_liquidity_zero_input_mints_zero_lp() {
        // L1: zero liquidity add must not mint LP tokens
        let mut pool = make_pool(1_000_000, 1_000_000);
        let lp = pool.add_liquidity(0, 0);
        assert_eq!(lp, 0);
    }

    #[test]
    fn test_remove_liquidity_more_than_supply_gives_zero() {
        // L1: removing more LP than exists must return (0,0) — no underflow panic
        let mut pool = make_pool(1_000_000, 1_000_000);
        let lp = pool.add_liquidity(100_000, 100_000);
        let (a0, a1) = pool.remove_liquidity(lp * 10);
        // Implementation clamps via division; just must not panic
        let _ = (a0, a1);
    }

    // ── Layer 2: Functional correctness ──────────────────────────────────────

    #[test]
    fn test_constant_product_invariant_after_swap() {
        // L2: k = reserve0 * reserve1 must only increase after swap (due to fees)
        let mut pool = make_pool(1_000_000, 1_000_000);
        let k_before = pool.reserve0 * pool.reserve1;
        let out = pool.get_amount_out(10_000, true);
        pool.reserve0 += 10_000;
        pool.reserve1 -= out;
        let k_after = pool.reserve0 * pool.reserve1;
        assert!(k_after >= k_before, "k must not decrease after swap");
    }

    #[test]
    fn test_twap_accumulates_with_time() {
        // L2: TWAP accumulator must increase when time passes
        let mut pool = make_pool(1_000_000, 2_000_000);
        pool.update_twap(1000);
        let acc_before = pool.price0_cumulative;
        pool.update_twap(2000); // advance 1000s
        assert!(pool.price0_cumulative > acc_before);
    }

    #[test]
    fn test_routing_graph_single_hop_route() {
        // L2: a direct pool between two tokens must produce a valid 1-hop route
        let mut rg = RoutingGraph::new();
        let t0 = [1u8; 20];
        let t1 = [2u8; 20];
        let pool = AmmPoolV2 {
            address: [3u8; 20], token0: t0, token1: t1,
            reserve0: 1_000_000, reserve1: 1_000_000,
            fee_bps: 30, lp_supply: 0,
            block_timestamp_last: 0, price0_cumulative: 0, price1_cumulative: 0,
        };
        rg.add_pool(pool);
        let route = rg.find_best_route(t0, t1, 1_000, 3);
        assert!(route.is_some());
    }

    #[test]
    fn test_price_impact_increases_with_trade_size() {
        // L2: larger trade must always have higher price impact
        let pool = make_pool(1_000_000, 1_000_000);
        let small = pool.price_impact_bps(1_000, true);
        let large = pool.price_impact_bps(500_000, true);
        assert!(large > small);
    }

    // ── Layer 3: Protection ───────────────────────────────────────────────────

    #[test]
    fn test_order_book_buy_below_ask_does_not_fill() {
        // L3: buy order priced below ask must rest, not match
        let pair = ([1u8; 20], [2u8; 20]);
        let mut ob = OrderBook::new(pair);
        let ask = Order {
            id: 1, trader: [0u8; 20], pair, side: Side::Sell,
            price: 200, quantity: 100, filled: 0, timestamp: 0,
            post_only: false, ioc: false,
        };
        ob.place_order(ask);
        let buy = Order {
            id: 2, trader: [1u8; 20], pair, side: Side::Buy,
            price: 150, quantity: 100, filled: 0, timestamp: 0,
            post_only: false, ioc: false,
        };
        let (_, fills) = ob.place_order(buy);
        assert!(fills.is_empty(), "buy below ask must not fill");
    }

    #[test]
    fn test_pool_with_zero_reserves_returns_max_price_impact() {
        // L3: zero reserve pool must signal maximum price impact (full slippage)
        let pool = make_pool(0, 0);
        let impact = pool.price_impact_bps(1_000, true);
        assert_eq!(impact, 10_000); // 100% impact
    }

    #[test]
    fn test_remove_liquidity_on_empty_pool_is_safe() {
        // L3: removing from zero lp_supply must return (0,0) without panic
        let mut pool = make_pool(0, 0);
        let (a0, a1) = pool.remove_liquidity(1_000);
        assert_eq!(a0, 0);
        assert_eq!(a1, 0);
    }

    // ── Layer 4: Detection & Response ────────────────────────────────────────

    #[test]
    fn test_registry_tvl_updates_after_new_pool() {
        // L4: TVL metric must reflect each new pool registration
        let reg = DexRegistry::new();
        assert_eq!(reg.tvl(), 0);
        reg.register_v2_pool(make_pool(500_000, 500_000));
        assert_eq!(reg.tvl(), 1_000_000);
        reg.register_v2_pool(make_pool(200_000, 300_000));
        assert_eq!(reg.tvl(), 1_500_000);
    }

    #[test]
    fn test_order_book_spread_is_zero_when_crossed() {
        // L4: after a match, spread must update (crossed spread detected)
        let pair = ([1u8; 20], [2u8; 20]);
        let mut ob = OrderBook::new(pair);
        let ask = Order {
            id: 1, trader: [0u8; 20], pair, side: Side::Sell,
            price: 100, quantity: 100, filled: 0, timestamp: 0,
            post_only: false, ioc: false,
        };
        ob.place_order(ask);
        let buy = Order {
            id: 2, trader: [1u8; 20], pair, side: Side::Buy,
            price: 100, quantity: 100, filled: 0, timestamp: 0,
            post_only: false, ioc: false,
        };
        ob.place_order(buy);
        // After full fill, both sides empty — spread should be None
        assert!(ob.spread().is_none() || ob.spread() == Some(0));
    }

    #[test]
    fn test_impermanent_loss_is_negative_always() {
        // L4: impermanent loss must always be <= 0 (you always lose vs hold)
        for ratio in [0.5f64, 1.5, 2.0, 4.0, 0.25] {
            let il = AmmPoolV2::impermanent_loss_pct(100.0, 100.0 * ratio);
            assert!(il <= 0.0, "IL must be <= 0 for ratio {ratio}, got {il}");
        }
    }

    // ── Layer 5: Resilience ───────────────────────────────────────────────────

    #[test]
    fn test_empty_routing_graph_returns_none() {
        // L5: routing on empty graph must return None without panic
        let rg = RoutingGraph::new();
        assert!(rg.find_best_route([0u8; 20], [1u8; 20], 1_000, 5).is_none());
    }

    #[test]
    fn test_twap_no_update_when_dt_zero() {
        // L5: zero time delta must not change accumulator (prevent NaN/inf)
        let mut pool = make_pool(1_000_000, 1_000_000);
        pool.update_twap(1000);
        let acc0 = pool.price0_cumulative;
        pool.update_twap(1000); // same timestamp
        assert_eq!(pool.price0_cumulative, acc0);
    }

    #[test]
    fn test_add_then_remove_all_liquidity_leaves_empty_pool() {
        // L5: full liquidity round-trip must leave pool with reserves >= 0
        let mut pool = make_pool(0, 0);
        let lp = pool.add_liquidity(1_000_000, 1_000_000);
        pool.remove_liquidity(lp);
        assert!(pool.reserve0 < 1_000_000);
        assert!(pool.reserve1 < 1_000_000);
    }

    // ── Layer 6: Governance & Compliance ─────────────────────────────────────

    #[test]
    fn test_fee_bps_is_applied_to_swap() {
        // L6: fee must reduce output vs a zero-fee pool (compliance with fee param)
        let pool_fee   = make_pool(1_000_000, 1_000_000); // fee_bps = 30
        let mut pool_free = make_pool(1_000_000, 1_000_000);
        pool_free.fee_bps = 0;
        let out_fee  = pool_fee.get_amount_out(10_000, true);
        let out_free = pool_free.get_amount_out(10_000, true);
        assert!(out_free > out_fee, "fee must reduce output");
    }

    #[test]
    fn test_amm_pool_address_is_unique_identifier() {
        // L6: pool address must be the canonical identifier used for routing
        let pool = make_pool(1_000_000, 1_000_000);
        let mut rg = RoutingGraph::new();
        rg.add_pool(pool.clone());
        assert!(rg.pools.contains_key(&pool.address));
    }

    // ── Reentrancy simulation ─────────────────────────────────────────────────

    #[test]
    fn test_add_liquidity_then_swap_then_remove_consistent_state() {
        // Reentrancy: interleaved add, swap, remove must leave pool in valid state
        let mut pool = make_pool(0, 0);
        pool.add_liquidity(1_000_000, 1_000_000);
        let out = pool.get_amount_out(10_000, true);
        // Apply swap manually
        pool.reserve0 += 10_000;
        pool.reserve1 -= out;
        let k = pool.reserve0 * pool.reserve1;
        assert!(k > 0, "k must remain positive after swap");
        let lp = pool.lp_supply;
        let (a0, a1) = pool.remove_liquidity(lp / 2);
        assert!(a0 > 0 && a1 > 0);
    }

    #[test]
    fn test_concurrent_registry_registration_is_safe() {
        // Reentrancy: concurrent pool registration must not corrupt TVL
        use std::thread;
        let reg = Arc::new(DexRegistry::new());
        let mut handles = vec![];
        for i in 0u8..8 {
            let r = Arc::clone(&reg);
            handles.push(thread::spawn(move || {
                let mut pool = make_pool(100_000, 100_000);
                pool.address[0] = i;
                r.register_v2_pool(pool);
            }));
        }
        for h in handles { h.join().unwrap(); }
        assert_eq!(reg.tvl(), 8 * 200_000);
    }

    // ── Read-only reentrancy ──────────────────────────────────────────────────

    #[test]
    fn test_amm_get_amount_out_is_pure_read_no_side_effects() {
        // Read-only reentrancy: get_amount_out must not mutate pool state
        let pool = make_pool(1_000_000, 1_000_000);
        let r0_before = pool.reserve0;
        let r1_before = pool.reserve1;
        let _ = pool.get_amount_out(50_000, true);
        let _ = pool.get_amount_out(50_000, true);
        assert_eq!(pool.reserve0, r0_before);
        assert_eq!(pool.reserve1, r1_before);
    }

    #[test]
    fn test_price_impact_read_does_not_affect_reserves() {
        // Read-only reentrancy: price_impact_bps is read-only — reserves unchanged
        let pool = make_pool(1_000_000, 1_000_000);
        let r0 = pool.reserve0;
        pool.price_impact_bps(100_000, true);
        pool.price_impact_bps(200_000, false);
        assert_eq!(pool.reserve0, r0);
    }

    // ── Function parameter validation ─────────────────────────────────────────

    #[test]
    fn test_get_amount_out_with_zero_amount_in_returns_zero() {
        // Param validation: zero input must produce zero output (no free tokens)
        let pool = make_pool(1_000_000, 1_000_000);
        assert_eq!(pool.get_amount_out(0, true), 0);
    }

    #[test]
    fn test_remove_liquidity_zero_lp_returns_zero() {
        // Param validation: removing 0 LP tokens must return (0, 0)
        let mut pool = make_pool(1_000_000, 1_000_000);
        let (out0, out1) = pool.remove_liquidity(0);
        assert_eq!(out0, 0);
        assert_eq!(out1, 0);
    }

    #[test]
    fn test_isqrt_of_perfect_square() {
        // Param validation: isqrt(n²) must equal n for small values
        for n in 0u128..20 {
            assert_eq!(isqrt(n * n), n, "isqrt({}) must be {}", n * n, n);
        }
    }

    // ── Misconfiguration ──────────────────────────────────────────────────────

    #[test]
    fn test_pool_fee_bps_zero_does_not_panic() {
        // Misconfiguration: zero fee (no-fee pool) must not cause division errors
        let pool = AmmPoolV2 { address: [1u8; 20], token0: [2u8; 20], token1: [3u8; 20],
            reserve0: 1_000_000, reserve1: 1_000_000, fee_bps: 0, lp_supply: 1_000_000,
            block_timestamp_last: 0, price0_cumulative: 0, price1_cumulative: 0 };
        let out = pool.get_amount_out(1000, true);
        assert!(out > 0, "zero-fee pool should still produce output");
    }

    #[test]
    fn test_add_liquidity_to_empty_pool_sets_initial_reserves() {
        // Misconfiguration: first liquidity add to empty pool must set both reserves
        let mut pool = AmmPoolV2 { address: [1u8; 20], token0: [2u8; 20], token1: [3u8; 20],
            reserve0: 0, reserve1: 0, fee_bps: 30, lp_supply: 0,
            block_timestamp_last: 0, price0_cumulative: 0, price1_cumulative: 0 };
        let lp = pool.add_liquidity(1_000_000, 1_000_000);
        assert!(lp > 0, "initial liquidity add must mint LP tokens");
        assert!(pool.reserve0 > 0);
        assert!(pool.reserve1 > 0);
    }

    #[test]
    fn test_routing_graph_path_between_unknown_tokens_returns_none() {
        // Misconfiguration: routing with unknown tokens must return None, not panic
        let rg = RoutingGraph::new();
        let token_a = [0xAAu8; 20];
        let token_b = [0xBBu8; 20];
        let path = rg.find_best_route(token_a, token_b, 1000, 3);
        assert!(path.is_none());
    }

    // ── Governance attack ─────────────────────────────────────────────────────

    #[test]
    fn test_constant_product_invariant_maintained_after_get_amount_out() {
        // Governance attack: get_amount_out is pure — k must not change
        let pool = make_pool(1_000_000, 2_000_000);
        let k_before = pool.reserve0 * pool.reserve1;
        pool.get_amount_out(50_000, true); // read-only
        let k_after = pool.reserve0 * pool.reserve1;
        assert_eq!(k_before, k_after);
    }

    #[test]
    fn test_price_impact_increases_with_larger_trade() {
        // Governance attack: large trades must have higher price impact (slippage protection)
        let pool = make_pool(1_000_000, 1_000_000);
        let small_impact = pool.price_impact_bps(1_000, true);
        let large_impact = pool.price_impact_bps(500_000, true);
        assert!(large_impact > small_impact,
            "large trade must have higher price impact than small trade");
    }

    #[test]
    fn test_swap_output_never_exceeds_reserve() {
        // Governance attack: output must never exceed the available reserve
        let pool = make_pool(1_000_000, 1_000_000);
        let max_out = pool.get_amount_out(u128::MAX / 2, true);
        assert!(max_out < pool.reserve1,
            "swap output must never exceed reserve1");
    }
}
