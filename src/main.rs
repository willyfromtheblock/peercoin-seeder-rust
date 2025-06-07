use std::env;
use std::sync::Arc;

mod bitcoin;
mod crawler;
mod db;
mod dns;
mod logging;

use bitcoin::protocol::Network;
use crawler::seeder::Crawler;

struct Config {
    network: Network,
    hostname: Option<String>,
    nameserver: Option<String>,
    verbose: bool,
    help: bool,
    crawl_interval_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            network: Network::Mainnet,
            hostname: None,   // No default hostname - must be provided
            nameserver: None, // No default nameserver - must be provided
            verbose: false,
            help: false,
            crawl_interval_seconds: 3600, // Default to 1 hour
        }
    }
}

fn parse_args() -> Config {
    let args: Vec<String> = env::args().collect();
    let mut config = Config::default();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--testnet" => {
                config.network = Network::Testnet;
            }
            "--mainnet" => {
                config.network = Network::Mainnet;
            }
            "-h" | "--hostname" => {
                if i + 1 < args.len() {
                    config.hostname = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    eprintln!("Error: {} requires a value", args[i]);
                    config.help = true;
                }
            }
            "-n" | "--nameserver" => {
                if i + 1 < args.len() {
                    config.nameserver = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    eprintln!("Error: {} requires a value", args[i]);
                    config.help = true;
                }
            }
            "-v" | "--verbose" => {
                config.verbose = true;
            }
            "--crawl-interval" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse::<u64>() {
                        Ok(interval) => {
                            config.crawl_interval_seconds = interval;
                            i += 1;
                        }
                        Err(_) => {
                            eprintln!("Error: {} requires a valid number of seconds", args[i]);
                            config.help = true;
                        }
                    }
                } else {
                    eprintln!("Error: {} requires a value", args[i]);
                    config.help = true;
                }
            }
            "--help" => {
                config.help = true;
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                config.help = true;
            }
        }
        i += 1;
    }

    config
}

fn print_usage(program_name: &str) {
    println!("Usage: {} [OPTIONS]", program_name);
    println!();
    println!("Options:");
    println!("  --testnet              Use testnet mode");
    println!("  --mainnet              Use mainnet mode (default)");
    println!("  -h, --hostname <HOST>  Hostname to bind for DNS responses (REQUIRED)");
    println!("  -n, --nameserver <NS>  Nameserver hostname (REQUIRED)");
    println!("  -v, --verbose          Enable verbose logging");
    println!("  --crawl-interval <SEC> Crawling interval in seconds (default: 3600 = 1 hour)");
    println!("  --help                 Show this help message");
    println!();
    println!("Examples:");
    println!(
        "  {} --testnet -h tseed.peercoin.net -n nst.peercoin.net",
        program_name
    );
    println!(
        "  {} --mainnet -h seed.peercoin.net -n ns.peercoin.net",
        program_name
    );
    println!();
    println!("Note: Both hostname and nameserver must be provided for DNS server operation.");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let config = parse_args();

    if config.help {
        print_usage(&args[0]);
        return;
    }

    // Set verbose mode for logging
    logging::set_verbose_mode(config.verbose);

    // Use the new logging system
    crate::log_info!("Starting Peercoin seeder...");
    crate::log_info!("Using network: {}", config.network);

    if let Some(ref hostname) = config.hostname {
        crate::log_info!("DNS hostname: {}", hostname);
    }

    if let Some(ref nameserver) = config.nameserver {
        crate::log_info!("Nameserver: {}", nameserver);
    }

    // Create shared seeder instance
    let mut seeder = match Crawler::new("0.0.0.0:0", config.network) {
        Ok(s) => s,
        Err(e) => {
            crate::log_error!("Failed to initialize seeder: {}", e);
            return;
        }
    };

    // Initialize database for persistent node tracking
    // Create db directory if it doesn't exist
    if let Err(e) = std::fs::create_dir_all("db") {
        crate::log_error!("Failed to create db directory: {}", e);
    }

    let database_path = format!("db/nodes_{}.db", config.network.to_string().to_lowercase());
    if let Err(e) = seeder.init_database(&database_path).await {
        crate::log_error!("Failed to initialize database: {}", e);
        crate::log_info!(
            "Continuing without persistent storage - will use in-memory tracking only"
        );
    }

    let shared_seeder = Arc::new(tokio::sync::Mutex::new(seeder));

    // Start database cleanup task (runs every 24 hours)
    let cleanup_seeder = Arc::clone(&shared_seeder);
    tokio::spawn(async move {
        loop {
            // Wait 24 hours before first cleanup, then repeat every 24 hours
            tokio::time::sleep(tokio::time::Duration::from_secs(24 * 60 * 60)).await;

            let seeder = cleanup_seeder.lock().await;
            if let Some(ref db) = seeder.get_database() {
                match db.cleanup_old_data().await {
                    Ok(deleted_count) => {
                        crate::log_info!(
                            "Database cleanup completed: {} old records removed",
                            deleted_count
                        );
                    }
                    Err(e) => {
                        crate::log_error!("Database cleanup failed: {}", e);
                    }
                }
            }
        }
    });

    // Start the DNS server in a separate tokio task with access to seeder
    let dns_seeder = Arc::clone(&shared_seeder);
    let hostname_clone = config.hostname.clone();
    let nameserver_clone = config.nameserver.clone();

    // Spawn the DNS server in a separate tokio task
    tokio::spawn(async move {
        if let Err(e) =
            dns::start_dns_server_with_seeder(hostname_clone, nameserver_clone, dns_seeder).await
        {
            crate::log_error!("DNS server error: {}", e);
        }
    });

    // Start crawling seeds with the shared seeder instance in the main thread
    let crawler_seeder = Arc::clone(&shared_seeder);
    crawler::seeder::start_crawling_with_shared_seeder(
        crawler_seeder,
        config.verbose,
        config.crawl_interval_seconds,
    )
    .await;
}
