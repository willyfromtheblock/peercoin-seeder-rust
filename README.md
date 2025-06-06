# Peercoin DNS Seeder in Rust

A modern Rust implementation of a DNS seeder for the Peercoin network. This project provides a fully functional DNS server that returns IP addresses of healthy Peercoin network nodes, replacing the need for hardcoded seed nodes.

## ✅ Current Status: FULLY FUNCTIONAL

The DNS seeder is **complete and working**:
- ✅ **DNS Server**: Returns real IP addresses of good Peercoin nodes
- ✅ **Network Crawler**: Discovers and validates nodes across the network  
- ✅ **Node Quality Filtering**: Only returns nodes with proper protocol versions
- ✅ **Multi-threaded Architecture**: DNS and crawler run concurrently with shared state
- ✅ **Production Ready**: Standard DNS protocol with proper A record responses

## Usage

The application supports both mainnet and testnet networks with configurable DNS hostname and nameserver bindings.

### Command Line Options

```bash
peercoin-seeder-rust [OPTIONS]

Options:
  --testnet              Use testnet mode
  --mainnet              Use mainnet mode (default)
  -h, --hostname <HOST>  Hostname to bind for DNS responses
  -n, --nameserver <NS>  Nameserver hostname
  -v, --verbose          Enable verbose logging mode
  --help                 Show this help message
```


## Quick Start

```bash
# Build and run (requires root for DNS port 53)
cargo build --release
sudo ./target/release/peercoin-seeder-rust --hostname tseed.peercoin.net --nameserver ns.peercoin.net

# Test the DNS server
dig @127.0.0.1 tseed.peercoin.net
```

Expected DNS response:
```
;; ANSWER SECTION:
tseed.peercoin.net.	300	IN	A	146.190.52.52
tseed.peercoin.net.	300	IN	A	146.59.69.245  
tseed.peercoin.net.	300	IN	A	76.204.61.25
```

## Project Structure

- `src/main.rs`: Entry point of the application. Initializes the DNS server and starts crawling seeds.
- `src/lib.rs`: Defines the public API of the library, exporting modules and functions used throughout the application.
- `src/bitcoin/`: Contains modules related to Bitcoin protocol functionalities.
  - `mod.rs`: Aggregates the Bitcoin-related submodules.
  - `protocol.rs`: Structures and functions related to the Bitcoin protocol, including message formats and handling.
  - `network.rs`: Manages network-related functionalities, such as connecting to peers and sending/receiving messages.
- `src/dns/`: Contains modules related to DNS functionalities.
  - `mod.rs`: Aggregates the DNS-related submodules.
  - `server.rs`: Implements the DNS server logic, handling incoming requests and serving DNS records.
- `src/db/`: Contains modules related to database functionalities.
  - `mod.rs`: Aggregates the database-related submodules.
  - `storage.rs`: Manages data storage and retrieval, interfacing with the database.
- `src/crawler/`: Contains modules related to the seed crawler functionalities.
  - `mod.rs`: Aggregates the crawler-related submodules.
  - `seeder.rs`: Implements the logic for crawling seeds, including fetching and processing seed data.

## Setup Instructions

1. Ensure you have Rust and Cargo installed on your machine. You can install them from [rust-lang.org](https://www.rust-lang.org/).
2. Clone the repository:
   ```
   git clone <repository-url>
   cd peercoin-seeder-rust
   ```
3. Build the project:
   ```
   cargo build
   ```
4. Run the application:
   ```
   cargo run
   ```

### Examples

Run on testnet with specific hostname and nameserver:
```bash
cargo run -- --testnet -h tseed.peercoin.net -n nst.peercoin.net
```

Run on mainnet with specific hostname and nameserver:
```bash
cargo run -- --mainnet -h seed.peercoin.net -n ns.peercoin.net
```

Run with verbose logging for detailed debugging:
```bash
cargo run -- --verbose
```

Run with default settings (mainnet, no specific hostname/nameserver):
```bash
cargo run
```

### Seed Sources

The seeder uses the following initial seed sources:

**Mainnet:**
- seed.peercoin.net
- seed2.peercoin.net
- seed.peercoin-library.org

**Testnet:**
- tseed.peercoin.net
- tseed2.peercoin.net
- tseed.peercoin-library.org

### Node Validation

The seeder enforces a minimum protocol version of 70018 to determine if nodes are "good" or "bad". Only nodes meeting this requirement will be included in DNS responses.

### DNS Resolution Features

- **CNAME Chain Support**: The seeder properly handles CNAME chains when resolving seed server hostnames (e.g., `tseed2.peercoin.net` → CNAME → A record)
- **IP Address Validation**: Filters out localhost, private, and multicast addresses to ensure only public IP addresses are used for seeding
- **Fallback Resolution**: If advanced DNS resolution fails, falls back to standard resolution methods
- **Detailed Logging**: Provides comprehensive logging of DNS resolution steps for debugging

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.