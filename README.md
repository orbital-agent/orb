# orb

A CLI tool for managing Cloudflare Tunnels with Zero Trust access control and scheduled tasks.

## Features

- **Expose local services** through Cloudflare Tunnel with custom subdomains
- **Zero Trust access control** - public, private (owner-only), or group-based access
- **Temporary access** - grant time-limited group access that auto-reverts to private
- **Access groups** - manage who can access your services via Cloudflare Access
- **Database management** - create, manage, and expose databases via Docker containers
- **Scheduled tasks** - run scripts on a cron schedule with `orb schedule`
- **Health monitoring** - check service status and view logs
- **Configuration management** - easily view and edit orb settings
- **Diagnostics** - run `orb doctor` to troubleshoot common issues
- **Automatic DNS management** - creates/removes DNS records automatically

## Prerequisites

- Go 1.21 or later
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) (`cloudflared`) installed and configured
- Cloudflare API token with DNS and Access permissions
- A configured `cloudflared` config file

## Installation

All `orb` configuration lives in `~/.config/orb/` for easy management.

### Method 1: Using `go install` (Recommended)

```bash
# 1. Clone and install the binary
git clone https://github.com/yourusername/orb.git
cd orb
go install

# 2. Add Go bin to your PATH (if not already configured)
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

# 3. Create config directory and environment file
mkdir -p ~/.config/orb
nano ~/.config/orb/.env
```

Add your configuration to `~/.config/orb/.env`:
```bash
DOMAIN=yourdomain.com
CONFIG_PATH=/path/to/cloudflared/config.yml
CLOUDFLARE_API_TOKEN=your_api_token
CLOUDFLARE_ZONE_ID=your_zone_id
CLOUDFLARE_ACCOUNT_ID=your_account_id
OWNER_EMAIL=your_email@example.com
```

**Verify installation:**
```bash
orb --help
```

### Method 2: Build and Install Manually

```bash
# 1. Build and install binary
go build -o orb
sudo mv orb /usr/local/bin/

# 2. Create config directory and environment file
mkdir -p ~/.config/orb
nano ~/.config/orb/.env
```

Add your configuration to `~/.config/orb/.env` (same as above).

## Uninstallation

```bash
# Remove the binary
rm $(which orb)

# Remove all configuration
rm -rf ~/.config/orb
```

## Configuration

`orb` loads configuration from `~/.config/orb/.env` (created during installation).

**Configuration Priority:**
1. `~/.config/orb/.env`
2. Environment variables already set in your shell

### Getting Your Cloudflare Credentials

1. **API Token**: Create one at [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens) with:
   - DNS edit permissions
   - Access: Apps and Policies edit permissions
2. **Zone ID**: Found in your domain's Overview tab in the Cloudflare Dashboard
3. **Account ID**: Found in the URL when logged into Cloudflare (`dash.cloudflare.com/<account_id>/...`)

## Usage

### Tunnel Commands

#### Expose a Local Service

```bash
# Public access (anyone can access)
orb tunnel expose api 8080

# Private access (only you, via OWNER_EMAIL)
orb tunnel expose api 8080 --access private

# Group access (permanent)
orb tunnel expose api 8080 --access friends

# Temporary group access (reverts to private after 24 hours)
orb tunnel expose api 8080 --access friends --expires 24h

# TCP service (non-HTTP)
orb tunnel expose db 5432 --type tcp
```

#### Remove an Exposed Service

```bash
orb tunnel unexpose api
```

#### Revoke Group Access

```bash
# Manually revoke group access, revert to private (owner-only)
orb tunnel revoke-access api
```

#### List All Exposed Services

```bash
orb tunnel list
```

Output:
```
Exposed services:
┌─────────────────────────────┬─────────────────────────┬─────────┬─────────┐
│            URL              │         TARGET          │ ACCESS  │ STATUS  │
├─────────────────────────────┼─────────────────────────┼─────────┼─────────┤
│ https://api.yourdomain.com  │ http://localhost:8080   │ public  │ healthy │
│ https://db.yourdomain.com   │ tcp://localhost:5432    │ private │ healthy │
└─────────────────────────────┴─────────────────────────┴─────────┴─────────┘
```

#### Other Tunnel Commands

```bash
orb tunnel update api 9090        # Change port
orb tunnel health api             # Check service health
orb tunnel status                 # Show cloudflared status
orb tunnel logs                   # View cloudflared logs
orb tunnel logs api -f            # Follow logs for a subdomain
orb tunnel restart                # Restart cloudflared
```

### Access Group Commands

```bash
# Create an access group
orb access create friends "alice@example.com,bob@example.com"

# List all access groups
orb access list

# Show members of a group
orb access show friends

# Update group membership
orb access update friends --add user3@example.com
orb access update friends --remove user1@example.com
orb access update friends -a new@example.com -r old@example.com

# Delete an access group
orb access delete friends
```

### Schedule Commands

Run scripts on a cron schedule:

```bash
# Add a scheduled task
orb schedule add backup "0 2 * * *" "./scripts/backup.sh"      # Daily at 2am
orb schedule add sync "*/30 * * * *" "python sync.py"          # Every 30 minutes
orb schedule add weekly "0 9 * * 1" "/usr/local/bin/report"    # Mondays at 9am

# List all scheduled tasks
orb schedule list

# Remove a scheduled task
orb schedule remove backup
```

Cron format: `minute hour day month weekday`
- `* * * * *` = every minute
- `0 * * * *` = every hour
- `0 0 * * *` = daily at midnight
- `0 9 * * 1` = Mondays at 9am

### Database Commands

Create and manage database containers via Docker, and expose them through Cloudflare Tunnel:

#### Create and Manage Databases

```bash
# Create a new database container
orb db create postgres mydb
orb db create mysql app-db --port 3307
orb db create redis cache

# List all managed databases
orb db list

# Start/stop databases
orb db start mydb
orb db stop mydb

# View database logs
orb db logs mydb
orb db logs mydb -f              # Follow logs
orb db logs mydb -n 50           # Show last 50 lines

# Show connection info
orb db info mydb

# Open interactive shell
orb db shell mydb

# Delete a database
orb db delete mydb
orb db delete mydb --keep-data   # Keep data directory
```

#### Expose Databases

```bash
# Expose a database through Cloudflare Tunnel (private by default)
orb db expose postgres mydb
orb db expose postgres mydb --port 5433
orb db expose mysql app-db --access team
orb db expose redis cache --access team --expires 24h

# List supported database types
orb db types
```

Supported database types:
| Type | Description | Default Port |
|------|-------------|--------------|
| postgres | PostgreSQL | 5432 |
| mysql | MySQL/MariaDB | 3306 |
| redis | Redis | 6379 |
| mongodb | MongoDB | 27017 |
| memcached | Memcached | 11211 |
| mssql | Microsoft SQL Server | 1433 |
| clickhouse | ClickHouse | 9000 |
| cassandra | Cassandra | 9042 |

### Config Commands

Manage orb configuration stored in `~/.config/orb/.env`:

```bash
# List all configuration values
orb config list

# Get a specific value
orb config get DOMAIN

# Set a configuration value
orb config set DOMAIN mydomain.com

# Remove a configuration value
orb config unset SOME_KEY

# Create a new config file with template
orb config init
orb config init --force          # Overwrite existing

# Open config in your default editor
orb config edit

# Print the config file path
orb config path
```

### Doctor Command

Diagnose common issues with orb configuration:

```bash
orb doctor
```

Checks performed:
- Environment variables (DOMAIN, CONFIG_PATH, CLOUDFLARE_*)
- Config file existence and readability
- cloudflared binary installation
- cloudflared service status
- Cloudflare API token validity
- Zone and account access permissions
- Internet connectivity
- DNS resolution

## How It Works

### Tunnel Expose
1. **Validation**: Checks subdomain format and verifies the port is listening
2. **Config Update**: Modifies your `cloudflared` YAML configuration
3. **DNS Management**: Creates/updates DNS records via Cloudflare API
4. **Access Policy**: Creates Cloudflare Access policy (owner always has access)
5. **Service Restart**: Restarts `cloudflared` to apply changes
6. **Expiry Scheduling**: If `--expires` is set, schedules automatic revocation via systemd timer

### Schedule
- Schedules are stored in `~/.config/orb/schedules.json`
- Tasks are added to your user crontab with `# orb-schedule: <name>` markers
- Logs depend on the command (use output redirection like `>> /tmp/log.txt`)

## Project Structure

**Source code:**
```
orb/
├── cmd/                      # CLI commands (Cobra)
│   ├── root.go              # Root command
│   ├── tunnel.go            # Tunnel subcommands
│   ├── access.go            # Access group commands
│   ├── schedule.go          # Schedule commands
│   ├── db.go                # Database management commands
│   ├── config.go            # Configuration commands
│   └── doctor.go            # Diagnostics command
├── internal/
│   ├── dns/                 # Cloudflare API client
│   │   └── client.go        # DNS, Access policies, groups
│   ├── tunnel/              # Tunnel management logic
│   │   ├── config.go        # Config file management
│   │   ├── service.go       # Business logic
│   │   └── validation.go    # Input validation
│   ├── scheduler/           # Cron schedule management
│   │   └── service.go       # Add/remove/list schedules
│   ├── database/            # Database container management
│   │   └── service.go       # Docker database operations
│   ├── config/              # Configuration management
│   │   └── service.go       # .env file operations
│   └── doctor/              # Diagnostics
│       └── service.go       # Health checks
├── main.go                  # Entry point
└── go.mod
```

**Runtime configuration:**
```
~/.config/orb/
├── .env                     # Environment variables (API tokens, domain, etc.)
└── schedules.json           # Persisted scheduled tasks

~/.local/share/orb/
└── databases/               # Database container data (created by orb db)
```

## Development

### Build

```bash
go build -o orb
```

### Run Without Installing

```bash
go run . tunnel expose api 8080
```

## Troubleshooting

### "Nothing listening on 127.0.0.1:PORT"

Start your service first before exposing it:
```bash
# Start your service
./your-service &

# Then expose it
orb tunnel expose api 8080
```

### "Permission denied" errors

The cloudflared config file might require sudo access:
```bash
sudo orb tunnel expose api 8080
```

### "DOMAIN environment variable is required"

Make sure your `.env` file exists at `~/.config/orb/.env` and contains all required variables:
```bash
# Check if config exists
cat ~/.config/orb/.env

# Or create it if missing
mkdir -p ~/.config/orb
nano ~/.config/orb/.env
```

Alternatively, set them in your shell:
```bash
export DOMAIN=yourdomain.com
export CONFIG_PATH=/etc/cloudflared/config.yml
export CLOUDFLARE_API_TOKEN=your_token
export CLOUDFLARE_ZONE_ID=your_zone_id
export CLOUDFLARE_ACCOUNT_ID=your_account_id
export OWNER_EMAIL=your_email@example.com
```

## Contributing

Contributions are welcome :D Please feel free to submit a Pull Request.

## Acknowledgments

- Built with [Cobra](https://github.com/spf13/cobra) for CLI framework
- Uses [cloudflare-go](https://github.com/cloudflare/cloudflare-go) for API interaction
- Powered by [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
