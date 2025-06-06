// Simple logging module for the Peercoin seeder

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static VERBOSE_MODE: AtomicBool = AtomicBool::new(false);
static DNS_QUERY_COUNT: AtomicU64 = AtomicU64::new(0);
static LAST_STATS_TIME: AtomicU64 = AtomicU64::new(0);

pub fn set_verbose_mode(verbose: bool) {
    VERBOSE_MODE.store(verbose, Ordering::Relaxed);
}

pub fn is_verbose() -> bool {
    VERBOSE_MODE.load(Ordering::Relaxed)
}

pub fn increment_dns_queries() {
    DNS_QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dns_query_count() -> u64 {
    DNS_QUERY_COUNT.load(Ordering::Relaxed)
}

pub fn should_report_stats() -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let last_stats = LAST_STATS_TIME.load(Ordering::Relaxed);

    // Report stats every 60 seconds (1 minute)
    if now - last_stats >= 60 {
        LAST_STATS_TIME.store(now, Ordering::Relaxed);
        true
    } else {
        false
    }
}

// Standard logging - always shown
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        println!($($arg)*);
    };
}

// Verbose logging - only shown when verbose mode is enabled
#[macro_export]
macro_rules! log_verbose {
    ($($arg:tt)*) => {
        if $crate::logging::is_verbose() {
            println!($($arg)*);
        }
    };
}

// Error logging - always shown
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        eprintln!($($arg)*);
    };
}
