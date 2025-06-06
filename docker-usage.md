# Docker Usage for Peercoin Seeder

## Quick Start

1. **Choose your network configuration:**
   ```bash
   # For mainnet
   cp .env.mainnet .env
   
   # For testnet  
   cp .env.testnet .env
   ```

2. **Create data directory:**
   ```bash
   mkdir -p data/
   ```

3. **Start the seeder:**
   ```bash
   # Using modern Docker Compose syntax
   docker compose up peercoin-seeder
   
   # Or using legacy syntax
   docker-compose up peercoin-seeder
   ```

**Note:** This guide uses `docker compose` (modern syntax). If you have the older `docker-compose` command, replace `docker compose` with `docker-compose` throughout.

## Environment Configuration

The seeder uses environment variables for configuration. Two pre-configured files are provided:

### `.env.mainnet` (Production):
```bash
NETWORK_FLAG=--mainnet
HOSTNAME=seed.peercoin.net
NAMESERVER=ns.peercoin.net
RUST_LOG=info
#VERBOSE_FLAG=--verbose
```

### `.env.testnet` (Testing):
```bash
NETWORK_FLAG=--testnet
HOSTNAME=tseed.peercoin.net
NAMESERVER=nst.peercoin.net
RUST_LOG=info
#VERBOSE_FLAG=--verbose
```

### Customization Options:

- **NETWORK_FLAG**: `--mainnet` or `--testnet`
- **HOSTNAME**: The hostname for your DNS seed (e.g., `seed.example.com`)
- **NAMESERVER**: The authoritative nameserver (e.g., `ns.example.com`)
- **RUST_LOG**: Logging level (`error`, `warn`, `info`, `debug`, `trace`)
- **VERBOSE_FLAG**: Uncomment `#VERBOSE_FLAG=--verbose` for detailed output

## Port Configuration

- **Port 53/UDP**: Standard DNS port (requires root privileges)
- **Capability**: `NET_BIND_SERVICE` capability is automatically added to allow binding to port 53

## Data Persistence

- Database and logs are stored in `./data/` directory
- Data persists across container restarts
- Database files: `./data/db/nodes_mainnet.db` or `./data/db/nodes_testnet.db`

## Commands

```bash
# Build the Docker image
docker compose build

# Run in foreground (with logs)
docker compose up peercoin-seeder

# Run in background (detached)
docker compose up -d peercoin-seeder

# View logs
docker compose logs -f peercoin-seeder

# Stop the service
docker compose down

# Check container status
docker compose ps

# Restart the service
docker compose restart peercoin-seeder

# Remove containers and images
docker compose down --rmi all
```

## Health Monitoring

The container includes a health check that verifies DNS functionality:

```bash
# Check health status
docker compose ps
# Look for "healthy" status

# Manual health check
docker compose exec peercoin-seeder dig @localhost seed.peercoin.net
```

## Troubleshooting

### Permission Issues
If you encounter permission errors with port 53:
```bash
# Check if port 53 is already in use
sudo netstat -nlp | grep :53

# Stop system DNS resolver (Ubuntu)
sudo systemctl stop systemd-resolved
```

### Database Issues
If the database becomes corrupted:
```bash
# Stop the container
docker-compose down

# Remove database files
rm -rf data/db/

# Restart (will recreate database)
docker-compose up -d peercoin-seeder
```

### Logs and Debugging
Enable verbose logging:
```bash
# Edit your .env file to uncomment:
VERBOSE_FLAG=--verbose

# Restart container
docker-compose restart peercoin-seeder

# View detailed logs
docker-compose logs -f peercoin-seeder
```
