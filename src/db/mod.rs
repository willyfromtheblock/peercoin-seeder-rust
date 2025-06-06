// Database module for persistent node statistics tracking
// This module handles SQLite database operations for storing and retrieving
// node availability metrics and health check data.

pub mod storage;

// Re-export main types and functions for easier access
pub use storage::NodeDatabase;
