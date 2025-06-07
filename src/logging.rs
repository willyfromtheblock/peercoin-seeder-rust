use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static VERBOSE_MODE: AtomicBool = AtomicBool::new(false);
static DNS_QUERY_COUNT: AtomicU64 = AtomicU64::new(0);

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
