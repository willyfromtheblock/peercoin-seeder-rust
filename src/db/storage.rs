use crate::{log_info, log_verbose};
use chrono::{DateTime, Utc};
use sqlx::{migrate::MigrateDatabase, Pool, Row, Sqlite, SqlitePool};
use std::net::SocketAddr;

/// Persistent storage for node statistics and health tracking
pub struct NodeDatabase {
    pool: Pool<Sqlite>,
}

/// Aggregated node availability metrics over the last 30 days
#[derive(Debug, Clone)]
pub struct NodeAvailabilityMetrics {
    pub address: SocketAddr,
    pub availability_score: f64, // 0.0 to 1.0 (percentage uptime)
    pub total_checks: i32,
    pub successful_checks: i32,
    pub days_seen: i32,
    pub last_protocol_version: Option<u32>,
    pub last_seen: DateTime<Utc>,
}

impl NodeDatabase {
    /// Create a new database connection and initialize tables
    pub async fn new(db_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        log_info!("Initializing node database at: {}", db_path);

        // Create database file if it doesn't exist
        if !Sqlite::database_exists(db_path).await.unwrap_or(false) {
            log_info!("Creating new SQLite database");
            Sqlite::create_database(db_path).await?;
        }

        let pool = SqlitePool::connect(db_path).await?;

        // Create tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS node_daily_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL,
                date TEXT NOT NULL,
                successful_checks INTEGER DEFAULT 0,
                failed_checks INTEGER DEFAULT 0,
                total_uptime_seconds INTEGER DEFAULT 0,
                protocol_version INTEGER,
                user_agent TEXT,
                last_seen TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(address, date)
            )
            "#,
        )
        .execute(&pool)
        .await?;

        // Create index for efficient queries
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_node_address_date 
            ON node_daily_stats(address, date DESC)
            "#,
        )
        .execute(&pool)
        .await?;

        // Create index for date-based cleanup
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_date 
            ON node_daily_stats(date)
            "#,
        )
        .execute(&pool)
        .await?;

        log_info!("Database initialization complete");

        Ok(NodeDatabase { pool })
    }

    /// Record a successful health check for a node
    pub async fn record_successful_check(
        &self,
        address: SocketAddr,
        protocol_version: Option<u32>,
        user_agent: Option<String>,
        uptime_seconds: i32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = Utc::now();
        let date = now.date_naive();
        let address_str = address.to_string();

        sqlx::query(
            r#"
            INSERT INTO node_daily_stats 
            (address, date, successful_checks, failed_checks, total_uptime_seconds, 
             protocol_version, user_agent, last_seen, updated_at)
            VALUES (?1, ?2, 1, 0, ?3, ?4, ?5, ?6, ?6)
            ON CONFLICT(address, date) DO UPDATE SET
                successful_checks = successful_checks + 1,
                total_uptime_seconds = total_uptime_seconds + ?3,
                protocol_version = COALESCE(?4, protocol_version),
                user_agent = COALESCE(?5, user_agent),
                last_seen = ?6,
                updated_at = ?6
            "#,
        )
        .bind(&address_str)
        .bind(&date.to_string())
        .bind(uptime_seconds)
        .bind(protocol_version.map(|v| v as i64))
        .bind(&user_agent)
        .bind(&now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        log_verbose!("Recorded successful check for {}", address);
        Ok(())
    }

    /// Record a failed health check for a node
    pub async fn record_failed_check(
        &self,
        address: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = Utc::now();
        let date = now.date_naive();
        let address_str = address.to_string();

        sqlx::query(
            r#"
            INSERT INTO node_daily_stats 
            (address, date, successful_checks, failed_checks, total_uptime_seconds, last_seen, updated_at)
            VALUES (?1, ?2, 0, 1, 0, ?3, ?3)
            ON CONFLICT(address, date) DO UPDATE SET
                failed_checks = failed_checks + 1,
                last_seen = ?3,
                updated_at = ?3
            "#,
        )
        .bind(&address_str)
        .bind(&date.to_string())
        .bind(&now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        log_verbose!("Recorded failed check for {}", address);
        Ok(())
    }

    /// Get availability metrics for all nodes over the last 30 days
    pub async fn get_availability_metrics(
        &self,
    ) -> Result<Vec<NodeAvailabilityMetrics>, Box<dyn std::error::Error>> {
        let thirty_days_ago = Utc::now() - chrono::Duration::days(30);
        let thirty_days_ago_str = thirty_days_ago.date_naive().to_string();

        let rows = sqlx::query(
            r#"
            SELECT 
                address,
                COUNT(DISTINCT date) as days_seen,
                SUM(successful_checks) as total_successful,
                SUM(failed_checks) as total_failed,
                SUM(total_uptime_seconds) as total_uptime,
                AVG(total_uptime_seconds * 1.0) as avg_uptime_per_day,
                protocol_version,
                user_agent,
                MAX(last_seen) as last_seen
            FROM node_daily_stats 
            WHERE date >= ?1
            GROUP BY address
            ORDER BY total_successful DESC, total_uptime DESC
            "#,
        )
        .bind(&thirty_days_ago_str)
        .fetch_all(&self.pool)
        .await?;

        let mut metrics = Vec::new();

        for row in rows {
            let address_str: String = row.get("address");
            let address: SocketAddr = address_str
                .parse()
                .map_err(|e| format!("Invalid address in DB: {}", e))?;

            let days_seen: i32 = row.get("days_seen");
            let total_successful: i32 = row.get("total_successful");
            let total_failed: i32 = row.get("total_failed");
            let total_checks = total_successful + total_failed;
            let _total_uptime: i32 = row.get("total_uptime");
            let _avg_uptime_per_day: f64 = row.get("avg_uptime_per_day");
            let protocol_version: Option<i64> = row.get("protocol_version");
            let _user_agent: Option<String> = row.get("user_agent");
            let last_seen_str: String = row.get("last_seen");

            // Calculate availability score based on successful checks and uptime
            let availability_score = if total_checks > 0 {
                (total_successful as f64) / (total_checks as f64)
            } else {
                0.0
            };

            let last_seen = DateTime::parse_from_rfc3339(&last_seen_str)?.with_timezone(&Utc);

            metrics.push(NodeAvailabilityMetrics {
                address,
                availability_score,
                total_checks,
                successful_checks: total_successful,
                days_seen,
                last_protocol_version: protocol_version.map(|v| v as u32),
                last_seen,
            });
        }

        log_verbose!("Retrieved availability metrics for {} nodes", metrics.len());
        Ok(metrics)
    }

    /// Get the top N most reliable nodes based on 30-day availability
    pub async fn get_top_reliable_nodes(
        &self,
        count: usize,
        min_protocol_version: u32,
    ) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
        let metrics = self.get_availability_metrics().await?;

        let mut reliable_nodes: Vec<_> = metrics
            .into_iter()
            .filter(|m| {
                // Filter by protocol version and recent activity
                m.last_protocol_version.unwrap_or(0) >= min_protocol_version &&
                m.availability_score > 0.7 && // At least 70% availability
                m.days_seen >= 3 && // Seen on at least 3 days
                m.total_checks >= 10 && // At least 10 checks
                // Seen within last 24 hours
                (Utc::now() - m.last_seen).num_hours() < 24
            })
            .collect();

        // Sort by availability score (highest first), then by days seen, then by total successful checks
        reliable_nodes.sort_by(|a, b| {
            b.availability_score
                .partial_cmp(&a.availability_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.days_seen.cmp(&a.days_seen))
                .then_with(|| b.successful_checks.cmp(&a.successful_checks))
        });

        let top_addresses: Vec<SocketAddr> = reliable_nodes
            .into_iter()
            .take(count)
            .map(|m| m.address)
            .collect();

        log_verbose!(
            "Found {} reliable nodes meeting criteria",
            top_addresses.len()
        );
        Ok(top_addresses)
    }

    /// Clean up old data (older than 30 days)
    pub async fn cleanup_old_data(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let thirty_days_ago = Utc::now() - chrono::Duration::days(30);
        let thirty_days_ago_str = thirty_days_ago.date_naive().to_string();

        let result = sqlx::query("DELETE FROM node_daily_stats WHERE date < ?1")
            .bind(&thirty_days_ago_str)
            .execute(&self.pool)
            .await?;

        let deleted_rows = result.rows_affected();
        if deleted_rows > 0 {
            log_info!("Cleaned up {} old database records", deleted_rows);
        }

        Ok(deleted_rows)
    }
}
