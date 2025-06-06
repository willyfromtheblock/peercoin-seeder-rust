# 🌱 Peercoin DNS Seeder

<div align="center">

**A modern, high-performance DNS seeder for the Peercoin network written in Rust**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust Version](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)

*Provides reliable DNS responses with healthy Peercoin network nodes*

</div>

## ✨ Features

- 🚀 **High Performance**: Multi-threaded DNS server and network crawler
- 🔍 **Smart Node Discovery**: Automatically discovers and validates network nodes
- 📊 **Persistent Statistics**: 30-day node availability tracking with SQLite
- 🌐 **DNS Protocol Compliant**: Standard A record responses on port 53
- 🛡️ **Quality Filtering**: Only returns nodes with proper protocol versions
- 🐳 **Docker Ready**: Complete containerization with Docker Compose
- 📝 **Comprehensive Logging**: Configurable verbosity levels for debugging

## 🚀 Quick Start

### Option 1: Docker (Recommended)

```bash
# Copy and configure environment
cp .env.mainnet .env
# Edit .env with your hostname and nameserver

# Start the seeder
docker-compose up
```

📖 **See [docker-usage.md](docker-usage.md) for complete Docker setup instructions**  
🚀 **See [DEPLOYMENT.md](DEPLOYMENT.md) for production deployment guide**

### Option 2: Native Build

```bash
# Build the project
cargo build --release

# Run with your configuration (requires root for port 53)
sudo ./target/release/peercoin-seeder-rust \
  --hostname your-seed.example.com \
  --nameserver your-ns.example.com
```

### Validate Your Setup

```bash
# Test Docker configuration
./test-docker.sh

# Test DNS response (once running)
dig @your-server-ip your-hostname A
```

### Test Your Seeder

```bash
dig @your-server your-seed.example.com
```

Expected response:
```
;; ANSWER SECTION:
your-seed.example.com. 300 IN A 146.190.52.52
your-seed.example.com. 300 IN A 146.59.69.245  
your-seed.example.com. 300 IN A 76.204.61.25
```

## ⚙️ Configuration

### Command Line Options

| Option | Description | Required |
|--------|-------------|----------|
| `--mainnet` | Use mainnet (default) | No |
| `--testnet` | Use testnet | No |
| `-h, --hostname <HOST>` | DNS hostname to serve | **Yes** |
| `-n, --nameserver <NS>` | Nameserver hostname | **Yes** |
| `-v, --verbose` | Enable detailed logging | No |
| `--help` | Show help message | No |

### Examples

```bash
# Mainnet seeder
./peercoin-seeder-rust --hostname seed.peercoin.net --nameserver ns.peercoin.net

# Testnet seeder with verbose logging
./peercoin-seeder-rust --testnet --verbose \
  --hostname tseed.peercoin.net --nameserver tns.peercoin.net
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