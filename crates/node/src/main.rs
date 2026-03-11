//! fullnode — DEX Full Node binary entry point

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "fullnode", version = "0.1.0", about = "DEX Full Node")]
struct Cli {
    /// Path to optional TOML config file (CLI flags take precedence)
    #[arg(long, default_value = "./config.toml")]
    config: String,

    /// Log level / filter (RUST_LOG style)
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log_level: String,

    /// Data directory for RocksDB and keystores
    #[arg(long, env = "DATA_DIR", default_value = "./data")]
    data_dir: String,

    /// Chain ID (1 = mainnet, 31337 = local testnet)
    #[arg(long, env = "CHAIN_ID", default_value_t = 1)]
    chain_id: u64,

    /// Sync mode: full | snap | archive | light
    #[arg(long, env = "SYNC_MODE", default_value = "snap")]
    sync_mode: String,

    /// P2P listen address (host:port)
    #[arg(long, env = "LISTEN_ADDR", default_value = "0.0.0.0:30303")]
    listen_addr: String,

    /// Maximum number of P2P peers
    #[arg(long, env = "MAX_PEERS", default_value_t = 50)]
    max_peers: usize,

    /// Bootnode addresses (may be repeated: --boot-node 1.2.3.4:30303)
    #[arg(long = "boot-node", env = "BOOT_NODES", value_delimiter = ',')]
    boot_nodes: Vec<String>,

    /// Enable HTTP JSON-RPC server
    #[arg(long, env = "HTTP_ENABLED")]
    http: bool,

    /// HTTP JSON-RPC bind address
    #[arg(long, env = "HTTP_ADDR", default_value = "127.0.0.1:8545")]
    http_addr: String,

    /// WebSocket JSON-RPC bind address
    #[arg(long, env = "WS_ADDR", default_value = "127.0.0.1:8546")]
    ws_addr: String,

    /// Enable validator duties
    #[arg(long, env = "VALIDATOR_ENABLED")]
    validator: bool,

    /// Path to validator keystore directory
    #[arg(long, env = "KEYSTORE_PATH", default_value = "./keystore")]
    keystore: String,

    /// Fee recipient address for block rewards
    #[arg(long, env = "FEE_RECIPIENT", default_value = "0x0000000000000000000000000000000000000000")]
    fee_recipient: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // ── Structured logging ──────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&cli.log_level))
        .with_target(true)
        .with_thread_ids(false)
        .json()
        .init();

    tracing::info!("═══════════════════════════════════════════════════");
    tracing::info!("  fullnode DEX — starting up");
    tracing::info!("  chain_id:   {}", cli.chain_id);
    tracing::info!("  sync_mode:  {}", cli.sync_mode);
    tracing::info!("  data_dir:   {}", cli.data_dir);
    tracing::info!("  validator:  {}", cli.validator);
    tracing::info!("═══════════════════════════════════════════════════");

    // ── Build NodeConfig from CLI ────────────────────────────────────────────
    let mut config = fullnode_node::NodeConfig::default();
    config.chain_id = cli.chain_id;
    config.data_dir = cli.data_dir;
    config.sync_mode = match cli.sync_mode.as_str() {
        "full"    => fullnode_node::SyncModeConfig::Full,
        "archive" => fullnode_node::SyncModeConfig::Archive,
        "light"   => fullnode_node::SyncModeConfig::Light,
        _         => fullnode_node::SyncModeConfig::Snap,
    };
    config.network.listen_addr  = cli.listen_addr;
    config.network.boot_nodes   = cli.boot_nodes;
    config.network.max_peers    = cli.max_peers;
    config.rpc.http_enabled     = cli.http;
    config.rpc.http_addr        = cli.http_addr;
    config.rpc.ws_addr          = cli.ws_addr;

    if cli.validator {
        config.validator = Some(fullnode_node::ValidatorConfig {
            enabled:       true,
            keystore_path: cli.keystore,
            fee_recipient: cli.fee_recipient,
        });
    }

    // ── Start node ──────────────────────────────────────────────────────────
    let (node, mut events) = fullnode_node::FullNode::new(config);

    // Background event logger
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            tracing::debug!(?event, "node event");
        }
    });

    node.run().await
}
