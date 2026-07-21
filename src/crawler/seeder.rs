use crate::bitcoin::protocol::{Network, Node, message::Version};
use crate::db::NodeDatabase;
use crate::{log_error, log_info, log_verbose};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str;

pub struct Crawler {
    nodes: HashMap<SocketAddr, Node>,
    network: Network,
    database: Option<NodeDatabase>,
    /// Cached reliable-node list served to DNS, refreshed once per crawl so DNS
    /// queries never trigger a DB aggregation while holding the seeder lock.
    reliable_cache: Vec<SocketAddr>,
}

/// Stateless network prober. Holds only the network (Copy) so it can be moved
/// into concurrent probe tasks without borrowing the shared Crawler / its lock.
#[derive(Clone, Copy)]
struct Prober {
    network: Network,
}

/// Why a probe failed, so the result can be recorded with the right status.
enum ProbeError {
    Connect(String),
    Handshake(String),
}

/// Outcome of probing a single node: its version plus discovered peers, or why it failed.
type ProbeOutcome = Result<(Version, Vec<SocketAddr>), ProbeError>;

/// Read a Bitcoin CompactSize (varint) from the front of `payload`.
/// Returns `(value, bytes_consumed)`.
fn read_compact_size(payload: &[u8]) -> Result<(usize, usize), String> {
    let first = *payload.first().ok_or("empty payload for compact size")?;
    match first {
        0xff => {
            let bytes = payload.get(1..9).ok_or("truncated u64 compact size")?;
            Ok((u64::from_le_bytes(bytes.try_into().unwrap()) as usize, 9))
        }
        0xfe => {
            let bytes = payload.get(1..5).ok_or("truncated u32 compact size")?;
            Ok((u32::from_le_bytes(bytes.try_into().unwrap()) as usize, 5))
        }
        0xfd => {
            let bytes = payload.get(1..3).ok_or("truncated u16 compact size")?;
            Ok((u16::from_le_bytes(bytes.try_into().unwrap()) as usize, 3))
        }
        n => Ok((n as usize, 1)),
    }
}

impl Crawler {
    pub fn new(_bind_addr: &str, network: Network) -> std::io::Result<Self> {
        Ok(Crawler {
            nodes: HashMap::new(),
            network,
            database: None,
            reliable_cache: Vec::new(),
        })
    }

    /// Network this crawler is configured for.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Initialize the database connection for persistent statistics tracking
    pub async fn init_database(
        &mut self,
        database_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        log_info!(
            "Initializing database for persistent node tracking at: {}",
            database_path
        );
        let db = NodeDatabase::new(database_path).await?;
        self.database = Some(db);
        log_info!("Database initialized successfully");
        Ok(())
    }

    /// Get a reference to the database for external access (e.g., cleanup tasks)
    pub fn get_database(&self) -> &Option<NodeDatabase> {
        &self.database
    }

    /// Load existing nodes from database into memory on startup
    /// This is the critical missing piece that causes the memory-database disconnect
    pub async fn load_nodes_from_database(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref db) = self.database {
            log_info!("Loading existing nodes from database into memory...");
            let min_protocol_version = self.network.min_protocol_version();

            match db.get_all_known_nodes(min_protocol_version).await {
                Ok(nodes_data) => {
                    let mut loaded_count = 0;

                    for node_data in nodes_data {
                        // Skip legacy off-port entries: only standard-port nodes
                        // can be served via DNS, so don't track anything else.
                        if node_data.address.port() != self.network.default_port() {
                            continue;
                        }

                        // Create a new Node instance with database information
                        let mut node = Node::new(node_data.address, self.network);

                        // Set protocol version if available (informational only;
                        // status stays Unknown until we actually handshake it).
                        if let Some(version) = node_data.last_protocol_version {
                            node.protocol_version = Some(version);
                        }

                        // Do NOT mark as good/recently-verified here. The previous
                        // code called update_last_seen(), which recomputed status to
                        // Good from the stored protocol version WITHOUT contacting the
                        // node — so on every restart `good` spiked with unverified,
                        // possibly-dead nodes and DNS served them. Leave it Unknown so
                        // the crawler must confirm it by a real handshake first.

                        // Insert into the HashMap
                        self.nodes.insert(node_data.address, node);
                        loaded_count += 1;

                        log_verbose!(
                            "Loaded node {} (availability: {:.1}%, {} checks)",
                            node_data.address,
                            node_data.availability_score * 100.0,
                            node_data.total_checks
                        );
                    }

                    log_info!(
                        "Successfully loaded {} nodes from database into memory",
                        loaded_count
                    );
                }
                Err(e) => {
                    log_error!("Failed to load nodes from database: {}", e);
                    return Err(e);
                }
            }
        } else {
            log_verbose!("No database available, skipping node loading");
        }

        Ok(())
    }

    /// Periodically reload nodes from database that may have been lost
    /// This ensures we don't permanently lose track of good nodes
    pub async fn reload_lost_nodes(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref db) = self.database {
            log_verbose!("Checking database for lost nodes to reload...");

            // Get all nodes with good history that aren't in memory
            let min_protocol_version = self.network.min_protocol_version();
            let db_nodes = db.get_all_known_nodes(min_protocol_version).await?;
            let total_db_nodes = db_nodes.len();

            let mut reloaded_count = 0;
            for node_data in db_nodes {
                // Only standard-port nodes are servable via DNS; skip the rest.
                if node_data.address.port() != self.network.default_port() {
                    continue;
                }
                // Only reload if not already in memory
                if !self.nodes.contains_key(&node_data.address) {
                    // Only reload nodes with good history
                    if node_data.availability_score > 0.8
                        || (node_data.days_seen >= 5 && node_data.successful_checks >= 20)
                    {
                        let mut node = Node::new(node_data.address, self.network);

                        // Set protocol version if available
                        if let Some(version) = node_data.last_protocol_version {
                            node.protocol_version = Some(version);
                        }

                        // Don't mark as recently seen - let the crawler verify it's still alive
                        self.nodes.insert(node_data.address, node);
                        reloaded_count += 1;

                        log_verbose!(
                            "Reloaded lost node {} ({}% uptime over {} days)",
                            node_data.address,
                            (node_data.availability_score * 100.0) as u32,
                            node_data.days_seen
                        );
                    }
                }
            }

            if reloaded_count > 0 {
                log_info!("Reloaded {} lost nodes from database", reloaded_count);
            } else {
                log_verbose!(
                    "No lost nodes needed reloading (checked {} database nodes)",
                    total_db_nodes
                );
            }
        }

        Ok(())
    }

    /// Add a new node or update an existing one
    pub async fn add_or_update_node(&mut self, address: SocketAddr, version_msg: Option<&Version>) {
        if let Some(version) = version_msg {
            // Store version data before borrowing
            let version_num = version.version;
            let user_agent_data = version.user_agent.clone();

            // Handle nodes with version information
            let was_good_before = {
                let node = self.nodes.entry(address).or_insert_with(|| {
                    log_verbose!("Adding new node: {}", address);
                    Node::new(address, self.network)
                });
                node.is_good_node()
            };

            let (is_good_now, status_reason, cooldown_remaining) = {
                let node = self.nodes.get_mut(&address).unwrap();
                node.update_from_version(version);

                log_verbose!(
                    "Updated node {} with protocol version {} (user_agent: {})",
                    address,
                    version_num,
                    user_agent_data
                );

                let is_good_now = node.is_good_node();
                let status_reason = node.get_status_reason();
                let cooldown_remaining = node.get_protocol_version_cooldown_remaining();

                (is_good_now, status_reason, cooldown_remaining)
            };

            // Record health check result in database
            if let Some(ref db) = self.database {
                let result = if is_good_now {
                    db.record_successful_check(
                        address,
                        Some(version_num),
                        Some(user_agent_data.clone()),
                        30,
                    )
                    .await
                } else {
                    db.record_failed_check(address).await
                };

                if let Err(e) = result {
                    log_error!("Failed to record health check for {}: {}", address, e);
                }
            }

            match status_reason {
                crate::bitcoin::protocol::NodeStatusReason::Good => {
                    if !was_good_before {
                        log_verbose!("✓ Node {} is now GOOD", address);
                    }
                }
                reason => {
                    log_verbose!("✗ Node {} is BAD - Reason: {}", address, reason);
                    if let crate::bitcoin::protocol::NodeStatusReason::ProtocolVersionTooOld(
                        _,
                        required,
                    ) = reason
                    {
                        log_verbose!(
                            "  → Node {} needs to upgrade to protocol version {} or higher",
                            address,
                            required
                        );

                        // Show cooldown information if applicable
                        if let Some(cooldown_remaining) = cooldown_remaining {
                            let hours = cooldown_remaining / 3600;
                            let minutes = (cooldown_remaining % 3600) / 60;
                            log_verbose!(
                                "  → Will be ignored for {}h {}m (protocol version cooldown)",
                                hours,
                                minutes
                            );
                        }
                    }
                }
            }
        } else {
            // No version message: this is a bare discovery -- an addr-gossip entry
            // from a peer, or a seed / known IP. Only register the node if it's
            // new; NEVER touch its status, last_seen, or the DB here.
            //
            // Critical: a node is Good ONLY after WE handshake it (the branch
            // above). Previously this branch called update_last_seen(), which
            // recomputed status from the node's stored protocol_version -- so any
            // DB-loaded node that showed up in another peer's addr list was
            // promoted to Good without ever being contacted, and the seeder served
            // unreachable nodes. Registering must not imply reachability.
            self.nodes.entry(address).or_insert_with(|| {
                log_verbose!("Discovered new node: {}", address);
                Node::new(address, self.network)
            });
        }
    }

    /// Get the top N good nodes based on protocol version and uptime
    /// Returns nodes with highest protocol version and lowest connection attempts (indicating better uptime)
    pub fn get_top_good_nodes(&self, count: usize) -> Vec<SocketAddr> {
        let mut good_nodes: Vec<&Node> = self
            .nodes
            .values()
            .filter(|node| node.is_good_node() && node.is_recently_seen())
            .collect();

        // Sort by protocol version (highest first), then by connection attempts (lowest first - indicating better uptime)
        good_nodes.sort_by(|a, b| {
            let version_cmp = b
                .protocol_version
                .unwrap_or(0)
                .cmp(&a.protocol_version.unwrap_or(0));
            if version_cmp == std::cmp::Ordering::Equal {
                a.connection_attempts.cmp(&b.connection_attempts)
            } else {
                version_cmp
            }
        });

        good_nodes
            .into_iter()
            .take(count)
            .map(|node| node.address)
            .collect()
    }

    /// Recompute the DNS-served node cache. Called once per crawl (under the
    /// lock) so DNS queries are served from memory instead of scanning nodes /
    /// hitting the DB per request while holding the seeder lock.
    async fn refresh_reliable_cache(&mut self) {
        let port = self.network.default_port();
        // Serve only freshly-verified good nodes ON THE STANDARD PORT. A DNS A
        // record carries no port, so a node on any other port is unreachable for
        // clients that always dial the default port. get_top_good_nodes already
        // requires a successful recent handshake (is_good_node), so this is
        // current reachability, not stale 30-day history.
        self.reliable_cache = self
            .get_top_good_nodes(usize::MAX)
            .into_iter()
            .filter(|addr| addr.port() == port)
            .take(25)
            .collect();
    }

    /// Serve reliable nodes from the in-memory cache (no DB, no await).
    pub fn get_cached_reliable_nodes(&self, count: usize) -> Vec<SocketAddr> {
        self.reliable_cache.iter().take(count).copied().collect()
    }

    /// Get count of good vs bad nodes
    pub fn get_node_stats(&self) -> (usize, usize) {
        let good_count = self
            .nodes
            .values()
            .filter(|node| node.is_good_node())
            .count();
        let total_count = self.nodes.len();
        (good_count, total_count - good_count)
    }

    /// Print a concise summary for standard mode
    fn print_node_summary(&self) {
        let (good, bad) = self.get_node_stats();
        let total = self.nodes.len();

        if total > 0 {
            log_verbose!(
                "Node Status: {} good, {} bad, {} total ({}% healthy)",
                good,
                bad,
                total,
                (good * 100) / total.max(1)
            );
        } else {
            log_info!("Node Status: No nodes discovered yet");
        }
    }

    /// Print detailed node status report for verbose mode
    fn print_detailed_node_status(&self) {
        log_verbose!("\n=== Detailed Node Status ===");

        let mut good_nodes = Vec::new();
        let mut bad_nodes = Vec::new();
        let mut unknown_nodes = Vec::new();

        for node in self.nodes.values() {
            match node.get_status_reason() {
                crate::bitcoin::protocol::NodeStatusReason::Good => {
                    good_nodes.push((
                        node.address,
                        node.protocol_version.unwrap_or(0),
                        &node.user_agent,
                        node.connection_attempts,
                    ));
                }
                crate::bitcoin::protocol::NodeStatusReason::Unknown => {
                    unknown_nodes.push((node.address, node.connection_attempts));
                }
                reason => {
                    bad_nodes.push((
                        node.address,
                        node.protocol_version.unwrap_or(0),
                        &node.user_agent,
                        reason,
                        node.connection_attempts,
                    ));
                }
            }
        }

        if !good_nodes.is_empty() {
            log_verbose!("✓ GOOD NODES ({}):", good_nodes.len());
            for (addr, version, user_agent, attempts) in good_nodes {
                log_verbose!(
                    "  {} - v{} - {} (attempts: {})",
                    addr,
                    version,
                    user_agent.as_ref().unwrap_or(&"Unknown".to_string()),
                    attempts
                );
            }
        }

        if !bad_nodes.is_empty() {
            log_verbose!("✗ BAD NODES ({}):", bad_nodes.len());
            for (addr, version, user_agent, reason, attempts) in bad_nodes {
                if version > 0 {
                    log_verbose!(
                        "  {} - v{} - {} (attempts: {})",
                        addr,
                        version,
                        user_agent.as_ref().unwrap_or(&"Unknown".to_string()),
                        attempts
                    );
                } else {
                    log_verbose!(
                        "  {} - No version info - {} (attempts: {})",
                        addr,
                        user_agent.as_ref().unwrap_or(&"Unknown".to_string()),
                        attempts
                    );
                }
                log_verbose!("    → Reason: {}", reason);

                // Give specific advice based on the reason
                match reason {
                    crate::bitcoin::protocol::NodeStatusReason::ProtocolVersionTooOld(
                        _,
                        required,
                    ) => {
                        log_verbose!(
                            "    → Solution: Upgrade to protocol version {} or higher",
                            required
                        );
                    }
                    crate::bitcoin::protocol::NodeStatusReason::ConnectionFailed(_) => {
                        log_verbose!("    → Will retry connection later");
                    }
                    crate::bitcoin::protocol::NodeStatusReason::NotRecentlySeen => {
                        log_verbose!("    → Node needs to be active and reachable");
                    }
                    _ => {}
                }
            }
        }

        if !unknown_nodes.is_empty() {
            log_verbose!(
                "? UNKNOWN NODES ({}) - No successful connection yet:",
                unknown_nodes.len()
            );
            for (addr, attempts) in unknown_nodes {
                log_verbose!("  {} - Connection attempts: {}", addr, attempts);
                log_verbose!("    → Waiting for successful connection and version exchange");
            }
        }

        log_verbose!("=============================\n");
    }

    /// Load initial seed servers for the configured network
    pub async fn load_seed_servers(&mut self) -> std::io::Result<()> {
        log_info!("Loading seed servers for network: {}", self.network);

        // Add known static IP addresses first
        self.add_known_ips().await;

        for seed in self.network.seed_servers() {
            log_verbose!("Resolving seed server: {}", seed);

            match self.resolve_hostname_with_cname_support(seed) {
                Ok(addrs) => {
                    if addrs.is_empty() {
                        log_error!("No addresses found for seed: {}", seed);
                    } else {
                        for addr in addrs {
                            let socket_addr = SocketAddr::new(addr, self.network.default_port());
                            log_verbose!("Adding seed node: {}", socket_addr);
                            self.add_or_update_node(socket_addr, None).await;
                        }
                    }
                }
                Err(e) => {
                    log_error!("Failed to resolve seed {}: {}", seed, e);
                    // Fallback to standard resolution
                    let addr_with_port = format!("{}:{}", seed, self.network.default_port());
                    match addr_with_port.to_socket_addrs() {
                        Ok(addrs) => {
                            for addr in addrs {
                                log_verbose!("Adding seed node (fallback): {}", addr);
                                self.add_or_update_node(addr, None).await;
                            }
                        }
                        Err(fallback_e) => {
                            log_error!(
                                "Fallback resolution also failed for {}: {}",
                                seed,
                                fallback_e
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Add known static IP addresses for well-known nodes
    async fn add_known_ips(&mut self) {
        for ip_str in self.network.known_ips() {
            if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                let socket_addr = SocketAddr::new(ip, self.network.default_port());
                log_verbose!("Adding known IP: {}", socket_addr);
                self.add_or_update_node(socket_addr, None).await;
            } else {
                log_error!("Invalid IP address in known_ips: {}", ip_str);
            }
        }
    }

    /// Resolve hostname with CNAME chain support
    /// This function provides better logging and handles CNAME chains explicitly
    fn resolve_hostname_with_cname_support(
        &self,
        hostname: &str,
    ) -> std::io::Result<Vec<std::net::IpAddr>> {
        use std::net::IpAddr;

        log_verbose!("Starting DNS resolution for: {}", hostname);

        // Use the standard library's resolution which handles CNAME chains automatically
        // but with better error handling and logging
        let addr_with_dummy_port = format!("{hostname}:0");
        match addr_with_dummy_port.to_socket_addrs() {
            Ok(socket_addrs) => {
                let ip_addrs: Vec<IpAddr> =
                    socket_addrs.map(|socket_addr| socket_addr.ip()).collect();

                if ip_addrs.is_empty() {
                    log_verbose!("No IP addresses found for: {}", hostname);
                    return Ok(Vec::new());
                }

                log_verbose!(
                    "Resolved {} to {} IP address(es):",
                    hostname,
                    ip_addrs.len()
                );
                for ip in &ip_addrs {
                    log_verbose!("  -> {}", ip);
                }

                // Additional validation: ensure we have valid addresses
                let valid_addrs: Vec<IpAddr> = ip_addrs
                    .iter()
                    .filter(|ip| {
                        match ip {
                            IpAddr::V4(ipv4) => {
                                // Filter out localhost, private, and multicast addresses for seed nodes
                                !ipv4.is_loopback() && !ipv4.is_private() && !ipv4.is_multicast()
                            }
                            IpAddr::V6(ipv6) => {
                                // Filter out localhost and multicast addresses for seed nodes
                                !ipv6.is_loopback() && !ipv6.is_multicast()
                            }
                        }
                    })
                    .copied()
                    .collect();

                if valid_addrs.len() != ip_addrs.len() {
                    let filtered_count = ip_addrs.len() - valid_addrs.len();
                    log_verbose!("Filtered out {} non-public IP addresses", filtered_count);
                }

                Ok(valid_addrs)
            }
            Err(e) => {
                log_error!("DNS resolution failed for {}: {}", hostname, e);
                log_verbose!("This could be due to:");
                log_verbose!("  - Network connectivity issues");
                log_verbose!("  - DNS server problems");
                log_verbose!("  - Invalid hostname");
                log_verbose!("  - CNAME chain resolution issues");
                Err(e)
            }
        }
    }

    /// Select which nodes to probe this crawl round, prioritised (good first,
    /// then fewest attempts). Mutates only bookkeeping (blacklist-attempt reset)
    /// and returns the address list so the actual network probing can run
    /// WITHOUT holding the seeder lock. See [`start_crawling_with_shared_seeder`].
    async fn select_nodes_to_crawl(&mut self, verbose: bool) -> Vec<SocketAddr> {
        if self.nodes.is_empty() {
            log_verbose!("No nodes to crawl. Loading seed servers...");
            if let Err(e) = self.load_seed_servers().await {
                log_error!("Failed to load seed servers: {}", e);
            }
            return Vec::new();
        }

        let mut eligible_nodes: Vec<&Node> = self
            .nodes
            .values()
            .filter(|node| node.should_retry_connection())
            .collect();

        // Good nodes first, then fewest connection attempts (more reliable first)
        eligible_nodes.sort_by(|a, b| {
            use crate::bitcoin::protocol::NodeStatusReason;
            let a_is_good = matches!(a.get_status_reason(), NodeStatusReason::Good);
            let b_is_good = matches!(b.get_status_reason(), NodeStatusReason::Good);
            match (a_is_good, b_is_good) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.connection_attempts.cmp(&b.connection_attempts),
            }
        });

        let nodes_to_crawl: Vec<SocketAddr> = eligible_nodes
            .into_iter()
            .map(|node| node.address)
            .collect();

        if nodes_to_crawl.is_empty() {
            log_verbose!("No nodes available for crawling at this time.");
            return Vec::new();
        }

        // Reset connection attempts for blacklisted nodes getting a second chance
        // (they only became eligible again after the 24h blacklist window).
        for addr in &nodes_to_crawl {
            if let Some(node) = self.nodes.get_mut(addr)
                && node.connection_attempts > 5
            {
                log_verbose!(
                    "  → Resetting connection attempts for blacklisted node {} (was {})",
                    addr,
                    node.connection_attempts
                );
                node.reset_connection_attempts();
            }
        }

        if verbose {
            log_verbose!("Selected {} nodes for crawling", nodes_to_crawl.len());
        }
        nodes_to_crawl
    }

    /// Apply the outcome of a single node probe back into memory + the database.
    /// Called under the seeder lock, but only briefly per node.
    async fn apply_probe_result(&mut self, addr: SocketAddr, result: ProbeOutcome) {
        match result {
            Ok((version, peer_addrs)) => {
                self.add_or_update_node(addr, Some(&version)).await;
                let mut new_peer_count = 0;
                for peer_addr in peer_addrs {
                    if !self.nodes.contains_key(&peer_addr) {
                        self.add_or_update_node(peer_addr, None).await;
                        new_peer_count += 1;
                    }
                }
                if new_peer_count > 0 {
                    log_verbose!("  ✓ Discovered {} new peers from {}", new_peer_count, addr);
                }
            }
            Err(ProbeError::Connect(e)) => {
                log_verbose!("  ✗ Connection failed for {}: {}", addr, e);
                if let Some(node) = self.nodes.get_mut(&addr) {
                    node.record_connection_failure(e);
                }
            }
            Err(ProbeError::Handshake(e)) => {
                log_verbose!("  ✗ Handshake failed for {}: {}", addr, e);
                if let Some(node) = self.nodes.get_mut(&addr) {
                    node.record_handshake_failure(e);
                }
            }
        }
    }
}

impl Prober {
    fn new(network: Network) -> Self {
        Prober { network }
    }

    /// Connect to a node and run the handshake + getaddr exchange. Read-only
    /// (holds no Crawler state), so it can run concurrently outside the lock.
    async fn probe_node(&self, addr: SocketAddr) -> ProbeOutcome {
        use tokio::net::TcpStream;
        use tokio::time::{Duration, timeout};

        let stream = timeout(Duration::from_secs(10), TcpStream::connect(addr))
            .await
            .map_err(|_| ProbeError::Connect("TCP connection timeout".to_string()))?
            .map_err(|e| ProbeError::Connect(format!("TCP connection failed: {e}")))?;

        self.perform_async_handshake(stream, addr)
            .await
            .map_err(ProbeError::Handshake)
    }

    /// Perform async handshake with a peer and collect addresses
    async fn perform_async_handshake(
        &self,
        mut stream: tokio::net::TcpStream,
        addr: SocketAddr,
    ) -> Result<(crate::bitcoin::protocol::message::Version, Vec<SocketAddr>), String> {
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncWriteExt;
        use tokio::time::{Duration, timeout};

        log_verbose!("  → Performing async handshake with {}", addr);

        // Create and send version message
        let version_msg = self.create_version_message(addr);
        let version_bytes = self.serialize_version_message(&version_msg);

        // Wrap version in protocol message
        let magic_bytes = self.network.magic_bytes();
        let mut full_message = Vec::new();
        full_message.extend_from_slice(&magic_bytes);
        full_message.extend_from_slice(b"version\0\0\0\0\0");
        full_message.extend_from_slice(&(version_bytes.len() as u32).to_le_bytes());

        // Calculate checksum
        let mut hasher = Sha256::new();
        hasher.update(&version_bytes);
        let hash1 = hasher.finalize();
        let mut hasher2 = Sha256::new();
        hasher2.update(hash1);
        let hash2 = hasher2.finalize();
        let checksum = [hash2[0], hash2[1], hash2[2], hash2[3]];

        full_message.extend_from_slice(&checksum);
        full_message.extend_from_slice(&version_bytes);

        // Send version message
        timeout(Duration::from_secs(5), stream.write_all(&full_message))
            .await
            .map_err(|_| "Timeout sending version message".to_string())?
            .map_err(|e| format!("Failed to send version message: {e}"))?;

        log_verbose!("  → Version message sent, waiting for response...");

        // Read version response
        let received_version = self.read_version_response(&mut stream).await?;

        log_verbose!(
            "  ✓ Received version response (protocol: {})",
            received_version.version
        );

        // Send verack
        let mut verack_message = Vec::new();
        verack_message.extend_from_slice(&magic_bytes);
        verack_message.extend_from_slice(b"verack\0\0\0\0\0\0");
        verack_message.extend_from_slice(&0u32.to_le_bytes());

        // Empty payload checksum
        let mut hasher = Sha256::new();
        hasher.update([]);
        let hash1 = hasher.finalize();
        let mut hasher2 = Sha256::new();
        hasher2.update(hash1);
        let hash2 = hasher2.finalize();
        let empty_checksum = [hash2[0], hash2[1], hash2[2], hash2[3]];
        verack_message.extend_from_slice(&empty_checksum);

        timeout(Duration::from_secs(5), stream.write_all(&verack_message))
            .await
            .map_err(|_| "Timeout sending verack".to_string())?
            .map_err(|e| format!("Failed to send verack: {e}"))?;

        log_verbose!("  → Verack sent, requesting addresses...");

        // Request peer addresses
        let peer_addrs = self
            .request_peer_addresses(&mut stream)
            .await
            .unwrap_or_else(|e| {
                log_verbose!("  ⚠ Failed to collect peer addresses: {}", e);
                Vec::new()
            });

        Ok((received_version, peer_addrs))
    }

    /// Read version response from peer
    async fn read_version_response(
        &self,
        stream: &mut tokio::net::TcpStream,
    ) -> Result<crate::bitcoin::protocol::message::Version, String> {
        use tokio::io::AsyncReadExt;
        use tokio::time::{Duration, timeout};

        // Read message header (24 bytes)
        let mut header = [0u8; 24];
        timeout(Duration::from_secs(10), stream.read_exact(&mut header))
            .await
            .map_err(|_| "Timeout reading version response header".to_string())?
            .map_err(|e| format!("Failed to read version header: {e}"))?;

        // Validate magic bytes
        let magic_bytes = self.network.magic_bytes();
        let peer_magic = [header[0], header[1], header[2], header[3]];
        if peer_magic != magic_bytes {
            return Err(format!(
                "Invalid magic bytes! Expected {magic_bytes:02x?}, got {peer_magic:02x?}"
            ));
        }

        // Parse command
        let command = String::from_utf8_lossy(&header[4..16]);
        let command_str = command.trim_end_matches('\0');
        if command_str != "version" {
            return Err(format!("Expected 'version' response, got '{command_str}'"));
        }

        // Parse payload length
        let payload_length =
            u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;

        if payload_length > 1024 * 1024 {
            return Err("Message too large".to_string());
        }

        // Read payload
        let mut payload = vec![0u8; payload_length];
        timeout(Duration::from_secs(10), stream.read_exact(&mut payload))
            .await
            .map_err(|_| "Timeout reading version payload".to_string())?
            .map_err(|e| format!("Failed to read version payload: {e}"))?;

        // Parse version message
        self.parse_version_message(&payload)
    }

    /// Request peer addresses from connected peer
    async fn request_peer_addresses(
        &self,
        stream: &mut tokio::net::TcpStream,
    ) -> Result<Vec<SocketAddr>, String> {
        use sha2::{Digest, Sha256};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration, sleep, timeout};

        let magic_bytes = self.network.magic_bytes();

        // Send getaddr message
        let mut getaddr_message = Vec::new();
        getaddr_message.extend_from_slice(&magic_bytes);
        getaddr_message.extend_from_slice(b"getaddr\0\0\0\0\0");
        getaddr_message.extend_from_slice(&0u32.to_le_bytes());

        // Empty payload checksum
        let mut hasher = Sha256::new();
        hasher.update([]);
        let hash1 = hasher.finalize();
        let mut hasher2 = Sha256::new();
        hasher2.update(hash1);
        let hash2 = hasher2.finalize();
        let empty_checksum = [hash2[0], hash2[1], hash2[2], hash2[3]];
        getaddr_message.extend_from_slice(&empty_checksum);

        timeout(Duration::from_secs(5), stream.write_all(&getaddr_message))
            .await
            .map_err(|_| "Timeout sending getaddr".to_string())?
            .map_err(|e| format!("Failed to send getaddr: {e}"))?;

        log_verbose!("  → Getaddr sent, waiting for addr messages...");

        // Wait for addr messages
        let mut peer_addrs = Vec::new();
        let start_time = std::time::Instant::now();
        let timeout_duration = Duration::from_secs(10);

        while start_time.elapsed() < timeout_duration {
            let mut header = [0u8; 24];

            match timeout(Duration::from_secs(2), stream.read_exact(&mut header)).await {
                Ok(Ok(_)) => {
                    // Parse command from header
                    let command = String::from_utf8_lossy(&header[4..16]);
                    let command_str = command.trim_end_matches('\0');

                    let payload_length =
                        u32::from_le_bytes([header[16], header[17], header[18], header[19]])
                            as usize;

                    if payload_length > 50000 {
                        log_verbose!("  → Message too large, skipping");
                        break;
                    }

                    match command_str {
                        "addr" => {
                            if payload_length > 0 {
                                let mut payload = vec![0u8; payload_length];
                                timeout(Duration::from_secs(2), stream.read_exact(&mut payload))
                                    .await
                                    .map_err(|_| "Timeout reading addr payload".to_string())?
                                    .map_err(|e| format!("Failed to read addr payload: {e}"))?;

                                let addrs = self.parse_addr_message(&payload)?;
                                peer_addrs.extend(addrs);
                                log_verbose!(
                                    "  ✓ Received addr message with {} addresses",
                                    peer_addrs.len()
                                );
                                break; // Got what we need
                            }
                        }
                        "ping" => {
                            // Handle ping by sending pong
                            if payload_length > 0 {
                                let mut ping_payload = vec![0u8; payload_length];
                                timeout(
                                    Duration::from_secs(2),
                                    stream.read_exact(&mut ping_payload),
                                )
                                .await
                                .map_err(|_| "Timeout reading ping payload".to_string())?
                                .map_err(|e| format!("Failed to read ping payload: {e}"))?;

                                // Send pong response
                                let mut pong_message = Vec::new();
                                pong_message.extend_from_slice(&magic_bytes);
                                pong_message.extend_from_slice(b"pong\0\0\0\0\0\0\0\0");
                                pong_message
                                    .extend_from_slice(&(ping_payload.len() as u32).to_le_bytes());

                                let mut hasher = Sha256::new();
                                hasher.update(&ping_payload);
                                let hash1 = hasher.finalize();
                                let mut hasher2 = Sha256::new();
                                hasher2.update(hash1);
                                let hash2 = hasher2.finalize();
                                let checksum = [hash2[0], hash2[1], hash2[2], hash2[3]];

                                pong_message.extend_from_slice(&checksum);
                                pong_message.extend_from_slice(&ping_payload);

                                let _ = stream.write_all(&pong_message).await;
                                log_verbose!("  ↔ Responded to ping with pong");
                            }
                        }
                        _ => {
                            // Skip other messages
                            if payload_length > 0 {
                                let mut skip_buf = vec![0u8; payload_length];
                                timeout(Duration::from_secs(2), stream.read_exact(&mut skip_buf))
                                    .await
                                    .map_err(|_| format!("Timeout skipping {command_str} payload"))?
                                    .map_err(|e| {
                                        format!("Failed to skip {command_str} payload: {e}")
                                    })?;
                            }
                            log_verbose!(
                                "  → Received '{}' message, continuing to wait for addr...",
                                command_str
                            );
                        }
                    }
                }
                Ok(Err(_)) => break, // Connection closed
                Err(_) => {
                    // Timeout, try sending getaddr again
                    log_verbose!("  → Timeout waiting for addr, trying again...");
                    let _ = stream.write_all(&getaddr_message).await;
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }

        Ok(peer_addrs)
    }

    /// Create a version message for the Bitcoin protocol handshake
    fn create_version_message(
        &self,
        addr: SocketAddr,
    ) -> crate::bitcoin::protocol::message::Version {
        use std::time::SystemTime;

        crate::bitcoin::protocol::message::Version {
            version: self.network.min_protocol_version(), // Use the correct Peercoin protocol version
            services: 1,                                  // NODE_NETWORK
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            addr_recv: crate::bitcoin::protocol::message::NetworkAddress {
                services: 1,
                ip: match addr.ip() {
                    std::net::IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped().octets(),
                    std::net::IpAddr::V6(ipv6) => ipv6.octets(),
                },
                port: addr.port(),
            },
            addr_from: crate::bitcoin::protocol::message::NetworkAddress {
                services: 1,
                ip: [0u8; 16], // Unspecified
                port: 0,
            },
            nonce: rand::random::<u64>(),
            user_agent: "/peercoin-seeder-rust:0.1.0/".to_string(), // Bitcoin-style user agent format
            start_height: 0,
            relay: true,
        }
    }

    /// Serialize a version message to bytes for network transmission
    fn serialize_version_message(
        &self,
        version: &crate::bitcoin::protocol::message::Version,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Version (4 bytes, little endian)
        bytes.extend_from_slice(&version.version.to_le_bytes());

        // Services (8 bytes, little endian)
        bytes.extend_from_slice(&version.services.to_le_bytes());

        // Timestamp (8 bytes, little endian)
        bytes.extend_from_slice(&version.timestamp.to_le_bytes());

        // addr_recv NetworkAddress (26 bytes)
        bytes.extend_from_slice(&version.addr_recv.services.to_le_bytes());
        bytes.extend_from_slice(&version.addr_recv.ip);
        bytes.extend_from_slice(&version.addr_recv.port.to_be_bytes());

        // addr_from NetworkAddress (26 bytes)
        bytes.extend_from_slice(&version.addr_from.services.to_le_bytes());
        bytes.extend_from_slice(&version.addr_from.ip);
        bytes.extend_from_slice(&version.addr_from.port.to_be_bytes());

        // Nonce (8 bytes, little endian)
        bytes.extend_from_slice(&version.nonce.to_le_bytes());

        // User agent (variable length string)
        let user_agent_bytes = version.user_agent.as_bytes();
        bytes.push(user_agent_bytes.len() as u8); // Length prefix
        bytes.extend_from_slice(user_agent_bytes);

        // Start height (4 bytes, little endian)
        bytes.extend_from_slice(&version.start_height.to_le_bytes());

        // Relay flag (1 byte)
        bytes.push(if version.relay { 1 } else { 0 });

        bytes
    }

    /// Parse an addr message from a peer and extract socket addresses
    fn parse_addr_message(&self, payload: &[u8]) -> Result<Vec<SocketAddr>, String> {
        if payload.is_empty() {
            return Ok(Vec::new());
        }

        // Read the CompactSize (Bitcoin varint) address count. The previous code
        // read a single byte, which mis-parsed every addr message using the
        // 0xfd/0xfe/0xff multi-byte forms (i.e. any count >= 253 — standard nodes
        // send up to 1000 addrs), crippling peer discovery.
        let (addr_count, mut offset) = read_compact_size(payload)?;

        if addr_count > 1000 {
            return Err("addr count too large".to_string());
        }

        let mut addresses = Vec::new();

        for _ in 0..addr_count {
            if offset + 30 > payload.len() {
                break; // Not enough bytes for a complete address entry
            }

            // Skip timestamp (4 bytes)
            offset += 4;

            // Skip services (8 bytes)
            offset += 8;

            // Read IP address (16 bytes)
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&payload[offset..offset + 16]);
            offset += 16;

            // Read port (2 bytes, big endian)
            let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            offset += 2;

            // Convert to SocketAddr
            let ipv6_addr = std::net::Ipv6Addr::from(ip_bytes);
            let ip_addr = if ipv6_addr.to_ipv4().is_some() {
                std::net::IpAddr::V4(ipv6_addr.to_ipv4().unwrap())
            } else {
                std::net::IpAddr::V6(ipv6_addr)
            };
            // Only track nodes on the network's standard port. A DNS A record
            // carries no port, so a node on any other port can never be
            // advertised correctly (clients always dial the default port).
            // Gate at ingestion so off-port peers are never tracked, probed,
            // counted good, or served.
            if port == self.network.default_port() {
                addresses.push(SocketAddr::new(ip_addr, port));
            }
        }

        Ok(addresses)
    }

    /// Parse a version message response from a peer
    fn parse_version_message(
        &self,
        payload: &[u8],
    ) -> Result<crate::bitcoin::protocol::message::Version, String> {
        if payload.len() < 85 {
            return Err(format!(
                "Invalid version message - too short: {} bytes",
                payload.len()
            ));
        }

        let mut offset = 0;

        // Read version (4 bytes)
        let version = u32::from_le_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]);
        offset += 4;

        // Read services (8 bytes)
        let services = u64::from_le_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
            payload[offset + 4],
            payload[offset + 5],
            payload[offset + 6],
            payload[offset + 7],
        ]);
        offset += 8;

        // Read timestamp (8 bytes)
        let timestamp = i64::from_le_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
            payload[offset + 4],
            payload[offset + 5],
            payload[offset + 6],
            payload[offset + 7],
        ]);
        offset += 8;

        // Skip addr_recv (26 bytes)
        offset += 26;

        // Skip addr_from (26 bytes)
        offset += 26;

        // Read nonce (8 bytes)
        let nonce = u64::from_le_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
            payload[offset + 4],
            payload[offset + 5],
            payload[offset + 6],
            payload[offset + 7],
        ]);
        offset += 8;

        // Read user agent string
        if offset >= payload.len() {
            return Err("Missing user agent".to_string());
        }

        let user_agent_len = payload[offset] as usize;
        offset += 1;

        if offset + user_agent_len > payload.len() {
            return Err("Invalid user agent length".to_string());
        }

        let user_agent_slice = &payload[offset..offset + user_agent_len];
        let user_agent = String::from_utf8_lossy(user_agent_slice).to_string();
        offset += user_agent_len;

        // Read start height (4 bytes)
        let start_height = if offset + 4 <= payload.len() {
            i32::from_le_bytes([
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ])
        } else {
            0
        };
        offset += 4;

        // Read relay flag (1 byte)
        let relay = if offset < payload.len() {
            payload[offset] != 0
        } else {
            true
        };

        Ok(crate::bitcoin::protocol::message::Version {
            version,
            services,
            timestamp,
            addr_recv: crate::bitcoin::protocol::message::NetworkAddress {
                services: 1,
                ip: [0u8; 16],
                port: 0,
            },
            addr_from: crate::bitcoin::protocol::message::NetworkAddress {
                services: 1,
                ip: [0u8; 16],
                port: 0,
            },
            nonce,
            user_agent,
            start_height,
            relay,
        })
    }
}

pub async fn start_crawling_with_shared_seeder(
    shared_seeder: std::sync::Arc<tokio::sync::Mutex<Crawler>>,
    verbose: bool,
    crawl_interval_seconds: u64,
) {
    log_info!("Starting seed crawler with shared seeder");
    log_verbose!("Verbose logging enabled");

    // CRITICAL FIX: Load existing nodes from database first, then add seed servers
    {
        let mut seeder = shared_seeder.lock().await;

        // Load existing nodes from database into memory (fixes memory-database disconnect)
        if let Err(e) = seeder.load_nodes_from_database().await {
            log_error!("Failed to load nodes from database: {}", e);
            // Continue anyway, but this is a significant issue
        }

        // Then load seed servers (these will be added to any existing database nodes)
        if let Err(e) = seeder.load_seed_servers().await {
            log_error!("Failed to load seed servers: {}", e);
            return;
        }
    }

    // Start periodic stats reporting task (runs every 60 seconds independently of crawling)
    let stats_seeder = std::sync::Arc::clone(&shared_seeder);
    tokio::spawn(async move {
        loop {
            // Sleep for 60 seconds
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

            // Report periodic statistics every 60 seconds
            let seeder = stats_seeder.lock().await;
            let (good, bad) = seeder.get_node_stats();
            let total = seeder.nodes.len();
            let dns_queries = crate::logging::get_dns_query_count();
            let health_percentage = (good * 100).checked_div(total).unwrap_or(0);

            log_info!(
                "Stats: {} nodes ({} good, {} bad, {}% healthy), {} DNS queries served",
                total,
                good,
                bad,
                health_percentage,
                dns_queries
            );

            // In verbose mode, show additional details
            if crate::logging::is_verbose() {
                seeder.print_detailed_node_status();
            } else {
                seeder.print_node_summary();
            }
        }
    });

    // Network is fixed for the process; capture it once so probes don't need the lock.
    let prober = {
        let seeder = shared_seeder.lock().await;
        Prober::new(seeder.network())
    };

    // Bounded concurrency for probes. Node probing runs OUTSIDE the seeder lock,
    // so DNS serving, stats, and reloads are never blocked by a slow/dead peer.
    // ponytail: fixed cap of 32; tune if crawl throughput matters.
    const MAX_CONCURRENT_PROBES: usize = 32;

    // Start crawling process
    let mut crawl_count = 0;
    loop {
        crawl_count += 1;

        // Every 10 crawls (~10 hours), reload lost nodes from database
        if crawl_count % 10 == 0 {
            let reload_result = {
                let mut seeder = shared_seeder.lock().await;
                seeder.reload_lost_nodes().await
            };
            if let Err(e) = reload_result {
                log_error!("Failed to reload lost nodes: {}", e);
            }
        }

        // 1) Select nodes to crawl (brief lock).
        let nodes_to_crawl = {
            let mut seeder = shared_seeder.lock().await;
            seeder.select_nodes_to_crawl(verbose).await
        };

        // 2) Probe them concurrently, WITHOUT the lock. Apply each result under a
        //    short per-node lock as it completes.
        let mut set: tokio::task::JoinSet<(SocketAddr, ProbeOutcome)> = tokio::task::JoinSet::new();
        let mut pending = nodes_to_crawl.into_iter();

        for _ in 0..MAX_CONCURRENT_PROBES {
            if let Some(addr) = pending.next() {
                set.spawn(async move { (addr, prober.probe_node(addr).await) });
            } else {
                break;
            }
        }

        while let Some(joined) = set.join_next().await {
            let (addr, result) = match joined {
                Ok(pair) => pair,
                Err(e) => {
                    log_error!("Probe task failed to join: {}", e);
                    continue;
                }
            };

            {
                let mut seeder = shared_seeder.lock().await;
                seeder.apply_probe_result(addr, result).await;
            }

            if let Some(next_addr) = pending.next() {
                set.spawn(async move { (next_addr, prober.probe_node(next_addr).await) });
            }
        }

        // 3) Refresh the DNS-served reliable-node cache once per crawl.
        {
            let mut seeder = shared_seeder.lock().await;
            seeder.refresh_reliable_cache().await;
        }

        // Sleep before next crawl (default 1 hour is plenty for a DNS seeder).
        tokio::time::sleep(tokio::time::Duration::from_secs(crawl_interval_seconds)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer that completes enough to reach the addr loop, announces an addr
    /// payload, then stalls without sending it. Before the timeout fix this
    /// hung request_peer_addresses forever (holding the global seeder mutex,
    /// freezing stats + DNS). After the fix it must return within ~2s.
    #[tokio::test]
    async fn test_stalled_addr_payload_does_not_hang() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Malicious/broken peer: send a valid "addr" header claiming a 34-byte
        // payload, then send nothing and keep the connection open.
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut header = Vec::new();
            header.extend_from_slice(&[0u8; 4]); // magic (not validated here)
            header.extend_from_slice(b"addr\0\0\0\0\0\0\0\0"); // command
            header.extend_from_slice(&34u32.to_le_bytes()); // payload_length
            header.extend_from_slice(&[0u8; 4]); // checksum
            sock.write_all(&header).await.unwrap();
            // Withhold the payload; hold the connection open long past the
            // client's read timeout so a bare read_exact would block forever.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });

        let prober = Prober::new(Network::Testnet);
        let mut stream = TcpStream::connect(addr).await.unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            prober.request_peer_addresses(&mut stream),
        )
        .await;

        server.abort();
        assert!(
            result.is_ok(),
            "request_peer_addresses hung on a stalled addr payload"
        );
    }

    #[test]
    fn test_read_compact_size() {
        assert_eq!(read_compact_size(&[5]).unwrap(), (5, 1));
        // 0xfd => next 2 bytes LE. 1000 = 0x03E8
        assert_eq!(read_compact_size(&[0xfd, 0xe8, 0x03]).unwrap(), (1000, 3));
        // 0xfe => next 4 bytes LE
        assert_eq!(read_compact_size(&[0xfe, 1, 0, 0, 0]).unwrap(), (1, 5));
        // truncated multi-byte form must error, not panic
        assert!(read_compact_size(&[0xfd]).is_err());
    }

    /// Build a 30-byte addr entry for ::ffff:1.2.3.4 on `port`.
    #[cfg(test)]
    fn addr_entry(port: u16) -> Vec<u8> {
        let mut e = Vec::new();
        e.extend_from_slice(&[0u8; 4]); // timestamp
        e.extend_from_slice(&[0u8; 8]); // services
        e.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4]); // ::ffff:1.2.3.4
        e.extend_from_slice(&port.to_be_bytes());
        e
    }

    #[test]
    fn test_parse_addr_message_multibyte_varint() {
        // A count encoded with the 0xfd form (value 1) followed by one 30-byte
        // address entry. The old single-byte parser read 0xfd as count 253 and
        // mis-parsed the entry; the fixed parser must decode exactly one address.
        // Use the testnet default port so it survives the standard-port gate.
        let prober = Prober::new(Network::Testnet);
        let mut payload = vec![0xfd, 0x01, 0x00]; // CompactSize(1)
        payload.extend_from_slice(&addr_entry(9903));

        let addrs = prober.parse_addr_message(&payload).unwrap();
        assert_eq!(addrs, vec!["1.2.3.4:9903".parse().unwrap()]);
    }

    #[test]
    fn test_parse_addr_message_gates_nonstandard_port() {
        // Two entries: one on the standard port, one off-port. Only the
        // standard-port node may be tracked (DNS A records carry no port).
        let prober = Prober::new(Network::Testnet); // default 9903
        let mut payload = vec![0x02]; // CompactSize(2)
        payload.extend_from_slice(&addr_entry(9903)); // standard
        payload.extend_from_slice(&addr_entry(12345)); // off-port

        let addrs = prober.parse_addr_message(&payload).unwrap();
        assert_eq!(
            addrs,
            vec!["1.2.3.4:9903".parse().unwrap()],
            "off-port node must be dropped"
        );
    }

    #[tokio::test]
    async fn gossip_does_not_promote_unhandshaked_node_to_good() {
        // A node loaded from the DB carries a stored protocol_version but has not
        // been handshaked this session (status Unknown). When another peer gossips
        // its address (add_or_update_node with no version), it must NOT be promoted
        // to Good -- only a real handshake may do that. This was the bug that made
        // `good` snap to the full loaded count and serve unreachable nodes.
        let mut c = Crawler::new("127.0.0.1:0", Network::Testnet).unwrap();
        let addr: SocketAddr = "1.2.3.4:9903".parse().unwrap();

        let mut n = Node::new(addr, Network::Testnet);
        n.protocol_version = Some(70018); // as if loaded from DB
        c.nodes.insert(addr, n);
        assert_eq!(c.get_node_stats().0, 0, "precondition: not good yet");

        // Another peer's addr list mentions this node -- no version from it.
        c.add_or_update_node(addr, None).await;

        assert_eq!(
            c.get_node_stats().0,
            0,
            "gossip must not mark an un-handshaked node good"
        );
    }

    #[test]
    fn test_cname_resolution() {
        let seeder = Crawler::new("127.0.0.1:0", Network::Testnet).unwrap();

        // Test resolving a hostname that should work
        let result = seeder.resolve_hostname_with_cname_support("google.com");
        assert!(result.is_ok());

        let ips = result.unwrap();
        assert!(!ips.is_empty(), "Should resolve to at least one IP address");

        // Verify that all resolved IPs are public
        for ip in ips {
            match ip {
                std::net::IpAddr::V4(ipv4) => {
                    assert!(!ipv4.is_loopback());
                    assert!(!ipv4.is_private());
                    assert!(!ipv4.is_multicast());
                }
                std::net::IpAddr::V6(ipv6) => {
                    assert!(!ipv6.is_loopback());
                    assert!(!ipv6.is_multicast());
                }
            }
        }
    }

    #[tokio::test]
    async fn test_load_seed_servers() {
        let mut seeder = Crawler::new("127.0.0.1:0", Network::Testnet).unwrap();

        // This should load seed servers without error
        let result = seeder.load_seed_servers().await;
        assert!(result.is_ok());

        // Should have at least some nodes loaded (assuming network connectivity)
        // Note: This test might fail if there's no internet connectivity
        if !seeder.nodes.is_empty() {
            log_verbose!("Test: Loaded {} seed nodes", seeder.nodes.len());
        }
    }
}
