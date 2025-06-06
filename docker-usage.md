# Docker Usage for Peercoin Seeder

## Quick Start

### For Mainnet (default):
```bash
# Create data directory
mkdir -p data/mainnet

# Start mainnet seeder
docker-compose up peercoin-seeder-mainnet
```

### For Testnet:
```bash
# Create data directory 
mkdir -p data/testnet

# Start testnet seeder
docker-compose --profile testnet up peercoin-seeder-testnet
```

## Configuration

The docker-compose.yml contains hardcoded values for:

### Mainnet:
- **Port**: 53/udp
- **Hostname**: seed.peercoin.net  
- **Nameserver**: ns.peercoin.net
- **Data**: ./data/mainnet

### Testnet:
- **Port**: 5353/udp (mapped to container port 53)
- **Hostname**: tseed.peercoin.net
- **Nameserver**: tns.peercoin.net  
- **Data**: ./data/testnet

## Important Notes

1. **Port 53 requires root privileges** - handled by `cap_add: NET_BIND_SERVICE`
2. **Mainnet and testnet cannot run simultaneously** on the same host using port 53
3. **Testnet uses port 5353** to avoid conflicts
4. **Data persists** in local directories `./data/mainnet` and `./data/testnet`

## Commands

```bash
# Build image
docker-compose build

# Run mainnet in background
docker-compose up -d peercoin-seeder-mainnet

# Run testnet in background  
docker-compose --profile testnet up -d peercoin-seeder-testnet

# View logs
docker-compose logs -f peercoin-seeder-mainnet
docker-compose logs -f peercoin-seeder-testnet

# Stop services
docker-compose down

# Check health
docker-compose ps
```

## Customization

To use different hostnames/nameservers, edit the `docker-compose.yml` file directly:

```yaml
command: [
  "--mainnet",
  "--hostname", "your-seed.example.com", 
  "--nameserver", "your-ns.example.com"
]
```
