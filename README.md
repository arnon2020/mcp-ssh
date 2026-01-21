# SSH MCP Tool

[![ISC License](https://img.shields.io/badge/License-ISC-718096?style=flat-square)](https://opensource.org/licenses/ISC)
[![Node.js](https://img.shields.io/badge/Node.js-18.x-339933?style=flat-square)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6?style=flat-square)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-1.6-0078d7?style=flat-square)](https://modelcontextprotocol.io/)

An SSH management tool built on the Model Context Protocol (MCP) that enables AI assistants to perform remote SSH operations through a standardized interface.

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Architecture](#architecture)
- [Security](#security)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

## Features

### Connection Management
- Create, update, delete, and list SSH connections
- Secure credential storage using keytar (native) or encrypted LokiJS (Docker)
- Connection status tracking (Connected, Connecting, Disconnected, Reconnecting, Error)
- Automatic reconnection with configurable attempts and delays
- Support for password and private key authentication
- Tag-based connection organization

### Command Execution
- Single and compound command execution (`&&`, `;` separated)
- Background task execution with configurable intervals
- Intelligent blocking detection (vim, nano, top, etc.)
- Working directory tracking
- Command timeout handling
- Sudo password protection via stdin (no command-line exposure)

### tmux Integration
- Create and manage persistent tmux sessions
- Send keystrokes to tmux sessions
- Capture session output with intelligent diff detection
- Automatic blocking detection and smart waiting (up to 10 minutes)

### File Operations
- Upload and download files with progress tracking
- Batch file transfer operations
- Automatic retry on transfer failures
- File size formatting and transfer statistics

### Terminal Sessions
- Interactive terminal session management
- Real-time data streaming
- Terminal resize support
- Session cleanup on disconnect

### SSH Tunnels
- Local port forwarding
- Tunnel management (create, close, list)
- Connection tracking

## Project Structure

```
mcp-ssh/
├── src/
│   ├── index.ts              # Main entry point, process management
│   ├── process-manager.ts    # Process lock and lifecycle management
│   └── tools/
│       ├── ssh.ts            # MCP tool definitions (24+ tools)
│       └── ssh-service.ts    # Core SSH service implementation
├── dist/                     # Compiled JavaScript
├── package.json
├── tsconfig.json
└── README.md
```

### Core Components

| Component | Description |
|-----------|-------------|
| `SshMCP` | Main MCP server class, handles tool registration and stdio transport |
| `SSHService` | Core SSH service, manages connections, commands, files, tunnels |
| `ProcessManager` | Single-instance lock management using `.mcp-ssh.lock` |

## Installation

### Prerequisites

- **Node.js 18+** - [Download](https://nodejs.org/)
- **Python 3.11+** (for bridging script)
- **tmux** (on remote servers)

### Install from GitHub

```bash
git clone https://github.com/arnon2020/mcp-ssh.git
cd mcp-ssh
npm install
npm run build
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEFAULT_SSH_PORT` | `22` | Default SSH port |
| `CONNECTION_TIMEOUT` | `10000` | Connection timeout in ms |
| `RECONNECT_ATTEMPTS` | `3` | Number of reconnection attempts |
| `SSH_DATA_PATH` | `~/.mcp-ssh` | Data directory path |
| `IS_DOCKER` | `false` | Enable Docker mode |
| `MCP_SSH_ENCRYPTION_KEY` | (required in Docker) | AES-256-GCM encryption key |

## Configuration

### Cursor MCP Setup

Create or edit `~/.cursor/mcp.json` (Windows: `%USERPROFILE%\.cursor\mcp.json`):

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "python3",
      "args": ["/absolute/path/to/mcp-ssh/bridging_ssh_mcp.py"]
    }
  }
}
```

### Docker Setup

```bash
# Build image
docker build -t mcp-ssh .

# Create data volume
docker volume create mcp-ssh-data

# Run with encryption key
docker run -it \
  -v mcp-ssh-data:/root/.mcp-ssh \
  -v ~/.ssh:/root/.ssh \
  -e MCP_SSH_ENCRYPTION_KEY="your-32-byte-encryption-key" \
  mcp-ssh
```

## Usage

### Basic Connection

```
Please help me create an SSH connection to my server at 192.168.1.100
```

The AI will prompt for:
- Host (IP or hostname)
- Port (default: 22)
- Username
- Password or private key path
- Connection name (optional)

### Execute Commands

```
Run "ls -la" on my server
```

```
Check disk usage with "df -h"
```

### tmux Session Management

```
Create a tmux session named "work" and run htop
```

```
Send "tail -f /var/log/syslog" to the tmux session
```

### File Transfer

```
Upload /local/file.txt to /remote/path/file.txt
```

```
Download /remote/config.json to my Downloads folder
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         AI/Cursor                           │
└──────────────────────────┬──────────────────────────────────┘
                           │ stdio
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  MCP Server (SshMCP)                                        │
│  - Tool Registration                                        │
│  - Request/Response Handling                                │
│  - Event Emission                                           │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  SSH Service (SSHService)                                   │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │ Connection Mgr  │  │ Command Executor│                  │
│  │ - keytar/LokiJS │  │ - Blocking Det. │                  │
│  │ - Status Track  │  │ - tmux Support  │                  │
│  └─────────────────┘  └─────────────────┘                  │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │  File Transfer  │  │  Tunnel Mgr     │                  │
│  │ - Progress      │  │ - Port Forward  │                  │
│  │ - Batch Ops     │  │ - Tracking      │                  │
│  └─────────────────┘  └─────────────────┘                  │
└──────────────────────────┬──────────────────────────────────┘
                           │ SSH2 / node-ssh
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Remote SSH Server                        │
└─────────────────────────────────────────────────────────────┘
```

## Security

### Recent Security Improvements

This fork includes several security enhancements over the original:

1. **Sudo Password Protection** (High Priority)
   - Sudo passwords are now passed via stdin instead of command-line arguments
   - For background tasks, temporary files with `600` permissions are used
   - Prevents password exposure in process listings

2. **Credential Encryption** (Medium Priority)
   - Docker mode now encrypts all stored credentials using AES-256-GCM
   - Encryption key configurable via `MCP_SSH_ENCRYPTION_KEY` environment variable
   - Each credential uses a unique IV for additional security

3. **Private Key Encryption** (Low Priority)
   - Private keys at rest are encrypted in Docker mode
   - Native mode uses keytar (OS-level keychain)

### Best Practices

- Always use SSH key authentication when possible
- Never commit credentials to version control
- Use strong encryption keys in Docker mode
- Keep the encryption key secure and separate from the container

## API Reference

### Connection Tools

| Tool | Description |
|------|-------------|
| `connect` | Establish new SSH connection |
| `disconnect` | Close SSH connection |
| `getConnection` | Get connection details |
| `listConnections` | List all saved connections |
| `updateConnection` | Update connection config |
| `deleteConnection` | Delete saved connection |

### Command Tools

| Tool | Description |
|------|-------------|
| `executeCommand` | Execute command on remote server |
| `backgroundExecute` | Execute command at intervals |
| `stopBackground` | Stop background execution |
| `getCurrentDirectory` | Get current working directory |

### File Tools

| Tool | Description |
|------|-------------|
| `uploadFile` | Upload file to remote server |
| `downloadFile` | Download file from remote server |
| `batchUploadFiles` | Upload multiple files |
| `batchDownloadFiles` | Download multiple files |
| `getFileTransferStatus` | Get transfer status |
| `listFileTransfers` | List recent transfers |

### Session Tools

| Tool | Description |
|------|-------------|
| `listActiveSessions` | List active SSH sessions |
| `listBackgroundTasks` | List running background tasks |
| `stopAllBackgroundTasks` | Stop all background tasks |

### Terminal Tools

| Tool | Description |
|------|-------------|
| `mcp_ssh_mcp_createTerminalSession` | Create interactive terminal |
| `mcp_ssh_mcp_writeToTerminal` | Write data to terminal |

### Tunnel Tools

| Tool | Description |
|------|-------------|
| `createTunnel` | Create SSH tunnel (port forward) |
| `closeTunnel` | Close SSH tunnel |
| `listTunnels` | List active tunnels |

## Contributing

Contributions are welcome! Please:

1. Check existing issues and PRs
2. Follow the project's code style
3. Add appropriate tests
4. Update documentation

## License

ISC License - See [LICENSE](LICENSE) for details.

---

## Acknowledgments

Forked from [shuakami/mcp-ssh](https://github.com/shuakami/mcp-ssh)

Built with:
- [@modelcontextprotocol/sdk](https://github.com/modelcontextprotocol/typescript-sdk) - MCP SDK
- [node-ssh](https://github.com/steelbrain/node-ssh) - SSH client
- [ssh2](https://github.com/mscdex/ssh2) - SSH2 protocol
- [LokiJS](https://github.com/LokiJS-Forge/LokiJS) - Embedded database
- [keytar](https://github.com/atom/node-keytar) - Credential storage

If this project helps you, please give it a Star ⭐️
