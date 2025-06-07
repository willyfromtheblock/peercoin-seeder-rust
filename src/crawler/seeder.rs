use crate::bitcoin::protocol::{message::Version, Network, Node};
use crate::db::NodeDatabase;
use crate::{log_error, log_info, log_verbose};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str;

pub struct Crawler {
    nodes: HashMap<SocketAddr, Node>,
    network: Network,
    database: Option<NodeDatabase>,
}

impl Crawler {
    pub fn new(_bind_addr: &str, network: Network) -> std::io::Result<Self> {
        Ok(Crawler {
            nodes: HashMap::new(),
            network,
            database: None,
        })
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
            // Handle nodes without version information
            let node_status = {
                let node = self.nodes.entry(address).or_insert_with(|| {
                    log_verbose!("Adding new node: {}", address);
                    Node::new(address, self.network)
                });

                log_verbose!("Updating last seen time for node: {}", address);
                node.update_last_seen();

                // For nodes without version info, we consider them for health check but mark as uncertain
                match node.get_status_reason() {
                    crate::bitcoin::protocol::NodeStatusReason::Good => {
                        log_verbose!("  Status: ✓ GOOD");
                        true
                    }
                    crate::bitcoin::protocol::NodeStatusReason::Unknown => {
                        log_verbose!("  Status: ? UNKNOWN");
                        // For unknown status, we don't record as successful or failed
                        return;
                    }
                    reason => {
                        log_verbose!("  Status: ✗ BAD - {}", reason);
                        false
                    }
                }
            };

            let (protocol_version, user_agent) = {
                let node = self.nodes.get(&address).unwrap();
                (node.protocol_version, node.user_agent.clone())
            };

            // Record health check for nodes we just pinged (without version data)
            if let Some(ref db) = self.database {
                let result = if node_status {
                    db.record_successful_check(address, protocol_version, user_agent, 30)
                        .await
                } else {
                    db.record_failed_check(address).await
                };

                if let Err(e) = result {
                    log_error!("Failed to record health check for {}: {}", address, e);
                }
            }
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

    /// Get the top N reliable nodes based on 30-day historical availability
    /// Falls back to current good nodes if database is not available
    pub async fn get_top_reliable_nodes(&self, count: usize) -> Vec<SocketAddr> {
        if let Some(ref db) = self.database {
            // Use minimum protocol version from the network configuration
            let min_protocol_version = self.network.min_protocol_version();

            match db.get_top_reliable_nodes(count, min_protocol_version).await {
                Ok(reliable_nodes) => {
                    if !reliable_nodes.is_empty() {
                        log_verbose!(
                            "Retrieved {} reliable nodes from database (30-day history)",
                            reliable_nodes.len()
                        );
                        return reliable_nodes;
                    } else {
                        log_verbose!("No reliable nodes found in database, falling back to current good nodes");
                    }
                }
                Err(e) => {
                    log_error!("Failed to get reliable nodes from database: {}, falling back to current good nodes", e);
                }
            }
        }

        // Fallback to existing logic
        self.get_top_good_nodes(count)
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
        let addr_with_dummy_port = format!("{}:0", hostname);
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

    pub async fn crawl_with_verbose(&mut self, verbose: bool) -> std::io::Result<()> {
        let (good, bad) = self.get_node_stats();

        if verbose {
            log_verbose!("=== Crawl Status ===");
            log_verbose!("Total nodes: {}", self.nodes.len());
            log_verbose!(
                "Good nodes: {} ({}%)",
                good,
                if !self.nodes.is_empty() {
                    good * 100 / self.nodes.len()
                } else {
                    0
                }
            );
            log_verbose!(
                "Bad nodes: {} ({}%)",
                bad,
                if !self.nodes.is_empty() {
                    bad * 100 / self.nodes.len()
                } else {
                    0
                }
            );
        }

        if self.nodes.is_empty() {
            log_verbose!("No nodes to crawl. Loading seed servers...");
            self.load_seed_servers().await?;
            return Ok(());
        }

        // Get a list of nodes to try connecting to - prioritize good nodes first
        let mut eligible_nodes: Vec<&Node> = self
            .nodes
            .values()
            .filter(|node| node.should_retry_connection())
            .collect();

        // Sort by priority: Good nodes first, then by connection attempts (fewer attempts = higher priority)
        eligible_nodes.sort_by(|a, b| {
            use crate::bitcoin::protocol::NodeStatusReason;
            let a_is_good = matches!(a.get_status_reason(), NodeStatusReason::Good);
            let b_is_good = matches!(b.get_status_reason(), NodeStatusReason::Good);

            // Primary sort: Good nodes first
            match (a_is_good, b_is_good) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => {
                    // Secondary sort: Fewer connection attempts first (more reliable nodes)
                    a.connection_attempts.cmp(&b.connection_attempts)
                }
            }
        });

        let nodes_to_crawl: Vec<SocketAddr> = eligible_nodes
            .into_iter()
            .map(|node| node.address)
            .collect();

        if nodes_to_crawl.is_empty() {
            log_verbose!("No nodes available for crawling at this time.");
            log_verbose!("Showing current node status:");
            if crate::logging::is_verbose() {
                self.print_detailed_node_status();
            }
            return Ok(());
        }

        // Log which nodes are being selected with their status
        if verbose {
            log_verbose!("Selected nodes for crawling (prioritized):");
            for addr in &nodes_to_crawl {
                if let Some(node) = self.nodes.get(addr) {
                    log_verbose!(
                        "  {} - Status: {} (attempts: {})",
                        addr,
                        node.get_status_reason(),
                        node.connection_attempts
                    );
                }
            }
        }

        log_verbose!(
            "Attempting to connect to {} nodes for peer discovery...",
            nodes_to_crawl.len()
        );

        for addr in nodes_to_crawl {
            log_verbose!("Connecting to node: {}", addr);
            match self.connect_and_discover_peers_async(addr).await {
                Ok(new_peers) => {
                    if new_peers > 0 {
                        log_verbose!("  ✓ Discovered {} new peers from {}", new_peers, addr);
                    } else {
                        log_verbose!("  - No new peers discovered from {}", addr);
                    }
                }
                Err(e) => {
                    log_verbose!("  ✗ Failed to connect to {}: {}", addr, e);
                    // Record the connection failure
                    if let Some(node) = self.nodes.get_mut(&addr) {
                        node.record_connection_failure(e.to_string());
                        log_verbose!(
                            "    → Connection failure recorded (attempt #{})",
                            node.connection_attempts
                        );
                    }
                }
            }
        }

        // Show summary after crawl
        let (good_after, bad_after) = self.get_node_stats();
        if good_after != good || bad_after != bad {
            log_verbose!(
                "Node status changed: {} good (+{}), {} bad (+{})",
                good_after,
                good_after as i32 - good as i32,
                bad_after,
                bad_after as i32 - bad as i32
            );
        }

        Ok(())
    }

    /// Async implementation for non-blocking peer discovery
    async fn connect_and_discover_peers_async(
        &mut self,
        addr: SocketAddr,
    ) -> std::io::Result<usize> {
        use tokio::net::TcpStream;
        use tokio::time::{timeout, Duration};

        log_verbose!("  Attempting async TCP connection to {}...", addr);

        // Use non-blocking connection with timeout
        match timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                log_verbose!("  ✓ Async TCP connection established to {}", addr);

                // Attempt async Bitcoin protocol handshake
                match self.perform_async_handshake(stream, addr).await {
                    Ok((version, peer_addrs)) => {
                        // Update the node with version info
                        self.add_or_update_node(addr, Some(&version)).await;
                        // Return the count of new peers discovered
                        let mut new_peer_count = 0;
                        for peer_addr in peer_addrs {
                            if !self.nodes.contains_key(&peer_addr) {
                                log_verbose!("    Found new peer: {}", peer_addr);
                                self.add_or_update_node(peer_addr, None).await;
                                new_peer_count += 1;
                            }
                        }
                        Ok(new_peer_count)
                    }
                    Err(e) => {
                        log_verbose!("  ✗ Async handshake failed: {}", e);
                        if let Some(node) = self.nodes.get_mut(&addr) {
                            node.record_handshake_failure(e.clone());
                        }
                        Err(std::io::Error::other(e))
                    }
                }
            }
            Ok(Err(e)) => {
                log_verbose!("  ✗ Async TCP connection failed to {}: {}", addr, e);
                Err(e)
            }
            Err(_) => {
                log_verbose!("  ✗ TCP connection timed out after 10 seconds: {}", addr);
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Connection timeout",
                ))
            }
        }
    }

    /// Perform async handshake with a peer and collect addresses
    async fn perform_async_handshake(
        &self,
        mut stream: tokio::net::TcpStream,
        addr: SocketAddr,
    ) -> Result<(crate::bitcoin::protocol::message::Version, Vec<SocketAddr>), String> {
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncWriteExt;
        use tokio::time::{timeout, Duration};

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
            .map_err(|e| format!("Failed to send version message: {}", e))?;

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
            .map_err(|e| format!("Failed to send verack: {}", e))?;

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
        use tokio::time::{timeout, Duration};

        // Read message header (24 bytes)
        let mut header = [0u8; 24];
        timeout(Duration::from_secs(10), stream.read_exact(&mut header))
            .await
            .map_err(|_| "Timeout reading version response header".to_string())?
            .map_err(|e| format!("Failed to read version header: {}", e))?;

        // Validate magic bytes
        let magic_bytes = self.network.magic_bytes();
        let peer_magic = [header[0], header[1], header[2], header[3]];
        if peer_magic != magic_bytes {
            return Err(format!(
                "Invalid magic bytes! Expected {:02x?}, got {:02x?}",
                magic_bytes, peer_magic
            ));
        }

        // Parse command
        let command = String::from_utf8_lossy(&header[4..16]);
        let command_str = command.trim_end_matches('\0');
        if command_str != "version" {
            return Err(format!(
                "Expected 'version' response, got '{}'",
                command_str
            ));
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
            .map_err(|e| format!("Failed to read version payload: {}", e))?;

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
        use tokio::time::{sleep, timeout, Duration};

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
            .map_err(|e| format!("Failed to send getaddr: {}", e))?;

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
                                stream
                                    .read_exact(&mut payload)
                                    .await
                                    .map_err(|e| format!("Failed to read addr payload: {}", e))?;

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
                                stream
                                    .read_exact(&mut ping_payload)
                                    .await
                                    .map_err(|e| format!("Failed to read ping payload: {}", e))?;

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
                                stream.read_exact(&mut skip_buf).await.map_err(|e| {
                                    format!("Failed to skip {} payload: {}", command_str, e)
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

        let mut offset = 0;

        // Read variable-length integer for address count
        if offset >= payload.len() {
            return Err("Invalid addr count encoding".to_string());
        }

        let addr_count = payload[offset] as usize;
        offset += 1;

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
            let socket_addr = SocketAddr::new(ip_addr, port);
            addresses.push(socket_addr);
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

    // Load seed servers for the network
    {
        let mut seeder = shared_seeder.lock().await;
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
            let health_percentage = if total > 0 { good * 100 / total } else { 0 };

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

    // Start crawling process
    loop {
        let crawl_result = {
            let mut seeder = shared_seeder.lock().await;
            seeder.crawl_with_verbose(verbose).await
        };

        if let Err(e) = crawl_result {
            log_error!("Crawling error: {}", e);
        }

        // Sleep before next crawl - configurable interval (default 1 hour is sufficient for DNS seeding)
        // since we're not a high-frequency trading system but a DNS service
        tokio::time::sleep(tokio::time::Duration::from_secs(crawl_interval_seconds)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
