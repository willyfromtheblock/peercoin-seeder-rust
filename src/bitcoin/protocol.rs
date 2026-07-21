/// Network configuration for Bitcoin/Peercoin
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    /// Get the default port for this network
    pub fn default_port(&self) -> u16 {
        match self {
            Network::Mainnet => 9901,
            Network::Testnet => 9903,
        }
    }

    /// Get the minimum protocol version required for this network
    pub fn min_protocol_version(&self) -> u32 {
        match self {
            Network::Mainnet => 70018,
            Network::Testnet => 70018,
        }
    }

    /// Get the seed servers for this network
    pub fn seed_servers(&self) -> &'static [&'static str] {
        match self {
            Network::Mainnet => &[
                "seed.peercoin.net",
                "seed2.peercoin.net",
                "seed.peercoin-library.org",
            ],
            Network::Testnet => &[
                "tseed.peercoin.net",
                "tseed2.peercoin.net",
                "tseed.peercoin-library.org",
            ],
        }
    }

    /// Get known good IP addresses for this network
    /// These are well-known nodes that don't require DNS resolution
    pub fn known_ips(&self) -> &'static [&'static str] {
        match self {
            Network::Mainnet => &[
                "161.35.95.39", // blockbook.peercoin.net
            ],
            Network::Testnet => &[
                "161.35.95.39", // tblockbook.peercoin.net
            ],
        }
    }

    /// Get the network magic bytes for protocol identification
    /// These are used in the Bitcoin/Peercoin protocol header to identify the network
    pub fn magic_bytes(&self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0xe6, 0xe8, 0xe9, 0xe5], // Peercoin mainnet magic
            Network::Testnet => [0xcb, 0xf2, 0xc0, 0xef], // Peercoin testnet magic
        }
    }
}

impl std::str::FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mainnet" => Ok(Network::Mainnet),
            "testnet" => Ok(Network::Testnet),
            _ => Err(format!("Unknown network: {s}")),
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet => write!(f, "testnet"),
        }
    }
}

pub mod message {
    #[derive(Debug, Clone)]
    pub struct Version {
        pub version: u32,
        pub services: u64,
        pub timestamp: i64,
        pub addr_recv: NetworkAddress,
        pub addr_from: NetworkAddress,
        pub nonce: u64,
        pub user_agent: String,
        pub start_height: i32,
        pub relay: bool,
    }

    #[derive(Debug, Clone)]
    pub struct NetworkAddress {
        pub services: u64,
        pub ip: [u8; 16], // IPv6 address (IPv4 mapped)
        pub port: u16,
    }
}

/// Status reason for why a node is considered bad or unknown
#[derive(Debug, Clone, PartialEq)]
pub enum NodeStatusReason {
    Unknown,
    ProtocolVersionTooOld(u32, u32), // (actual_version, required_version)
    ConnectionFailed(String),
    HandshakeFailed(String),
    NotRecentlySeen,
    Good,
}

impl std::fmt::Display for NodeStatusReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeStatusReason::Unknown => write!(f, "No version information received yet"),
            NodeStatusReason::ProtocolVersionTooOld(actual, required) => {
                write!(f, "Protocol version {actual} < required {required}")
            }
            NodeStatusReason::ConnectionFailed(err) => write!(f, "Connection failed: {err}"),
            NodeStatusReason::HandshakeFailed(err) => {
                write!(f, "Protocol handshake failed: {err}")
            }
            NodeStatusReason::NotRecentlySeen => write!(f, "Not seen recently (>2 hours ago)"),
            NodeStatusReason::Good => write!(f, "Meets all requirements"),
        }
    }
}

/// Represents a network node with its connection information and status
#[derive(Debug, Clone)]
pub struct Node {
    pub address: std::net::SocketAddr,
    pub network: Network,
    pub protocol_version: Option<u32>,
    pub services: Option<u64>,
    pub user_agent: Option<String>,
    pub start_height: Option<i32>,
    pub last_seen: std::time::SystemTime,
    pub connection_attempts: u32,
    pub last_connection_error: Option<String>,
    pub status_reason: NodeStatusReason,
    pub protocol_version_too_old_since: Option<std::time::SystemTime>,
}

impl Node {
    pub fn new(address: std::net::SocketAddr, network: Network) -> Self {
        Node {
            address,
            network,
            protocol_version: None,
            services: None,
            user_agent: None,
            start_height: None,
            last_seen: std::time::SystemTime::now(),
            connection_attempts: 0,
            last_connection_error: None,
            status_reason: NodeStatusReason::Unknown,
            protocol_version_too_old_since: None,
        }
    }

    /// Updates node information from a version message and determines if the node is good
    pub fn update_from_version(&mut self, version_msg: &message::Version) {
        self.protocol_version = Some(version_msg.version);
        self.services = Some(version_msg.services);
        self.user_agent = Some(version_msg.user_agent.clone());
        self.start_height = Some(version_msg.start_height);
        self.last_seen = std::time::SystemTime::now();

        // Update status based on protocol version
        self.update_status_reason();
    }

    /// Updates the status reason based on current node state
    pub fn update_status_reason(&mut self) {
        if !self.is_recently_seen() {
            self.status_reason = NodeStatusReason::NotRecentlySeen;
            // Clear protocol version too old timestamp when node becomes not recently seen
            self.protocol_version_too_old_since = None;
        } else if let Some(version) = self.protocol_version {
            let required_version = self.network.min_protocol_version();
            if version >= required_version {
                self.status_reason = NodeStatusReason::Good;
                // Clear protocol version too old timestamp when node becomes good
                self.protocol_version_too_old_since = None;
            } else {
                // Set timestamp when we first mark this node as having protocol version too old
                if !matches!(
                    self.status_reason,
                    NodeStatusReason::ProtocolVersionTooOld(_, _)
                ) {
                    self.protocol_version_too_old_since = Some(std::time::SystemTime::now());
                }
                self.status_reason =
                    NodeStatusReason::ProtocolVersionTooOld(version, required_version);
            }
        } else {
            self.status_reason = NodeStatusReason::Unknown;
            // Clear protocol version too old timestamp for unknown nodes
            self.protocol_version_too_old_since = None;
        }
    }

    /// Records a connection failure
    pub fn record_connection_failure(&mut self, error: String) {
        self.connection_attempts += 1;
        self.last_connection_error = Some(error.clone());
        self.status_reason = NodeStatusReason::ConnectionFailed(error);
        self.last_seen = std::time::SystemTime::now();
    }

    /// Records a handshake failure
    pub fn record_handshake_failure(&mut self, error: String) {
        self.connection_attempts += 1;
        self.last_connection_error = Some(error.clone());
        self.status_reason = NodeStatusReason::HandshakeFailed(error);
        self.last_seen = std::time::SystemTime::now();
    }

    /// Reset connection attempts (used when giving blacklisted nodes a second chance)
    pub fn reset_connection_attempts(&mut self) {
        self.connection_attempts = 0;
        self.last_connection_error = None;
    }

    /// Checks if the node is considered good for seeding
    pub fn is_good_node(&self) -> bool {
        matches!(self.status_reason, NodeStatusReason::Good) && self.is_recently_seen()
    }

    /// Checks if the node has been seen recently (within the last 2 hours)
    /// This provides buffer time for the 1-hour crawling interval
    pub fn is_recently_seen(&self) -> bool {
        match self.last_seen.elapsed() {
            Ok(elapsed) => elapsed.as_secs() < 7200, // 2 hours
            Err(_) => false,
        }
    }

    /// Gets the current status reason
    pub fn get_status_reason(&self) -> &NodeStatusReason {
        &self.status_reason
    }

    /// Checks if we should retry connecting to this node
    pub fn should_retry_connection(&self) -> bool {
        // CRITICAL FIX: Add time-based recovery for blacklisted nodes
        // Reset connection attempts after 24 hours to prevent permanent blacklisting
        if self.connection_attempts > 5 {
            if let Ok(elapsed) = self.last_seen.elapsed() {
                const TWENTY_FOUR_HOURS_IN_SECONDS: u64 = 24 * 60 * 60; // 24 hours
                if elapsed.as_secs() > TWENTY_FOUR_HOURS_IN_SECONDS {
                    // Node has been blacklisted for over 24 hours, allow retry
                    // Note: We can't mutate self here, but the next connection attempt will reset the counter
                    return true;
                }
            }
            return false; // Still within 24-hour blacklist period
        }

        // Check if this node has protocol version too old and if it's within the 12-hour cooldown period
        if matches!(
            self.status_reason,
            NodeStatusReason::ProtocolVersionTooOld(_, _)
        ) && let Some(too_old_since) = self.protocol_version_too_old_since
            && let Ok(elapsed) = too_old_since.elapsed()
        {
            const TWELVE_HOURS_IN_SECONDS: u64 = 12 * 60 * 60; // 12 hours
            if elapsed.as_secs() < TWELVE_HOURS_IN_SECONDS {
                return false; // Don't retry within 12 hours of being marked as protocol too old
            }
        }

        // Retry everything else. Crucially this includes ConnectionFailed and
        // HandshakeFailed: without them, a node that failed even once was excluded
        // forever (its attempt counter never grew past 1, so the 24h-blacklist
        // recovery path above was unreachable and its status was never re-aged to
        // NotRecentlySeen). That silently rotted every transiently-failing node to
        // permanently bad. The 1h crawl interval is the natural retry backoff, and
        // repeated failures still escalate to the attempts>5 blacklist above.
        matches!(
            self.status_reason,
            NodeStatusReason::Unknown
                | NodeStatusReason::NotRecentlySeen
                | NodeStatusReason::Good
                | NodeStatusReason::ConnectionFailed(_)
                | NodeStatusReason::HandshakeFailed(_)
        )
    }

    /// Gets the remaining cooldown time for nodes with protocol version too old
    /// Returns None if not in cooldown, or Some(remaining_seconds) if still in cooldown
    pub fn get_protocol_version_cooldown_remaining(&self) -> Option<u64> {
        if matches!(
            self.status_reason,
            NodeStatusReason::ProtocolVersionTooOld(_, _)
        ) && let Some(too_old_since) = self.protocol_version_too_old_since
            && let Ok(elapsed) = too_old_since.elapsed()
        {
            const TWELVE_HOURS_IN_SECONDS: u64 = 12 * 60 * 60; // 12 hours
            let elapsed_secs = elapsed.as_secs();
            if elapsed_secs < TWELVE_HOURS_IN_SECONDS {
                return Some(TWELVE_HOURS_IN_SECONDS - elapsed_secs);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node() -> Node {
        let addr: std::net::SocketAddr = "1.2.3.4:9901".parse().unwrap();
        Node::new(addr, Network::Mainnet)
    }

    #[test]
    fn failed_node_is_retried_not_permanently_blacklisted() {
        // Regression: a single connection failure must NOT sideline a node
        // forever. Before the fix, ConnectionFailed/HandshakeFailed were absent
        // from the retry set, so the node was never re-probed, its attempt
        // counter never grew, and the 24h-blacklist recovery was unreachable.
        let mut node = test_node();
        node.record_connection_failure("refused".to_string());
        assert!(
            node.should_retry_connection(),
            "node with a single connection failure must remain retryable"
        );

        let mut node = test_node();
        node.record_handshake_failure("bad version".to_string());
        assert!(
            node.should_retry_connection(),
            "node with a handshake failure must remain retryable"
        );
    }

    #[test]
    fn repeatedly_failed_node_is_blacklisted_then_recovers() {
        // >5 failures within 24h => blacklisted (not retried).
        let mut node = test_node();
        for _ in 0..6 {
            node.record_connection_failure("refused".to_string());
        }
        assert!(node.connection_attempts > 5);
        assert!(
            !node.should_retry_connection(),
            "node failing >5 times within 24h should be blacklisted"
        );

        // After 24h+ the blacklist lifts. record_* sets last_seen to now, so
        // simulate age by backdating last_seen past the 24h window.
        node.last_seen =
            std::time::SystemTime::now() - std::time::Duration::from_secs(25 * 60 * 60);
        assert!(
            node.should_retry_connection(),
            "blacklisted node should become retryable after 24h"
        );
    }
}
