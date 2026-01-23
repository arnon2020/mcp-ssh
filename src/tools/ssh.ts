import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { SSHService, SSHConnectionConfig, ConnectionStatus, TerminalSession, FileTransferInfo, BatchTransferConfig, TunnelConfig, CommandResult } from './ssh-service.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createHash } from 'crypto';

export class SshMCP {
  private server: McpServer;
  private sshService: SSHService;
  private activeConnections: Map<string, Date> = new Map();
  private backgroundExecutions: Map<string, { interval: NodeJS.Timeout, lastCheck: Date }> = new Map();

  constructor() {
    // Initialize SSH service
    this.sshService = new SSHService();

    // Initialize MCP server
    this.server = new McpServer({
      name: "ssh-mcp",
      version: "1.0.0"
    });

    // Register tools
    this.registerTools();

    // Connect to standard input/output
    const transport = new StdioServerTransport();
    this.server.connect(transport).catch(err => {
      console.error('MCP transport connection error:', err);
    });
  }

  /**
   * Register all MCP tools
   */
  private registerTools(): void {
    // Connection management
    this.registerConnectionTools();

    // Command execution
    this.registerCommandTools();

    // File transfer
    this.registerFileTools();

    // Session management
    this.registerSessionTools();

    // Terminal interaction
    this.registerTerminalTools();

    // Tunnel management
    this.registerTunnelTools();
  }

  /**
   * Format connection info output
   */
  private formatConnectionInfo(connection: any, includePassword: boolean = false): string {
    const statusEmoji = {
      [ConnectionStatus.CONNECTED]: '🟢',
      [ConnectionStatus.CONNECTING]: '🟡',
      [ConnectionStatus.DISCONNECTED]: '⚪',
      [ConnectionStatus.RECONNECTING]: '🟠',
      [ConnectionStatus.ERROR]: '🔴'
    };

    const statusText = {
      [ConnectionStatus.CONNECTED]: 'Connected',
      [ConnectionStatus.CONNECTING]: 'Connecting',
      [ConnectionStatus.DISCONNECTED]: 'Disconnected',
      [ConnectionStatus.RECONNECTING]: 'Reconnecting',
      [ConnectionStatus.ERROR]: 'Error'
    };

    let info = `${statusEmoji[connection.status as ConnectionStatus]} ${connection.name || connection.id}\n`;
    info += `ID: ${connection.id}\n`;
    info += `Host: ${connection.config.host}:${connection.config.port || 22}\n`;
    info += `Username: ${connection.config.username}\n`;

    if (includePassword && connection.config.password) {
      info += `Password: ${'*'.repeat(connection.config.password.length)}\n`;
    }

    if (connection.config.privateKey) {
      info += `Private Key Auth: Yes\n`;
    }

    info += `Status: ${statusText[connection.status as ConnectionStatus]}\n`;

    if (connection.lastError) {
      info += `Last Error: ${connection.lastError}\n`;
    }

    if (connection.lastUsed) {
      info += `Last Used: ${connection.lastUsed.toLocaleString()}\n`;
    }

    if (connection.currentDirectory) {
      info += `Current Directory: ${connection.currentDirectory}\n`;
    }

    if (connection.tags && connection.tags.length > 0) {
      info += `Tags: ${connection.tags.join(', ')}\n`;
    }

    if (this.activeConnections.has(connection.id)) {
      const lastActive = this.activeConnections.get(connection.id);
      if (lastActive) {
        info += `Activity: ${this.formatTimeDifference(lastActive)}\n`;
      }
    }

    if (this.backgroundExecutions.has(connection.id)) {
      info += `Background Tasks: Active\n`;
    }
    
    return info;
  }
  
  /**
   * Format time difference
   */
  private formatTimeDifference(date: Date): string {
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();

    if (diffMs < 60000) {
      return 'Just active';
    } else if (diffMs < 3600000) {
      const minutes = Math.floor(diffMs / 60000);
      return `Active ${minutes} minutes ago`;
    } else if (diffMs < 86400000) {
      const hours = Math.floor(diffMs / 3600000);
      return `Active ${hours} hours ago`;
    } else {
      const days = Math.floor(diffMs / 86400000);
      return `Active ${days} days ago`;
    }
  }

  /**
   * Format file size
   */
  private formatFileSize(bytes: number): string {
    if (bytes < 1024) {
      return `${bytes} B`;
    } else if (bytes < 1024 * 1024) {
      return `${(bytes / 1024).toFixed(2)} KB`;
    } else if (bytes < 1024 * 1024 * 1024) {
      return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    } else {
      return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    }
  }

  /**
   * Stop background task execution
   */
  private stopBackgroundExecution(connectionId: string): void {
    const bgExec = this.backgroundExecutions.get(connectionId);
    if (bgExec) {
      clearInterval(bgExec.interval);
      this.backgroundExecutions.delete(connectionId);
    }
  }

  /**
   * Register connection management tools
   */
  private registerConnectionTools(): void {
    // Create new connection
    this.server.tool(
      "connect",
      "Establishes a new SSH connection to a server.",
      {
        host: z.string(),
        port: z.number().optional(),
        username: z.string(),
        password: z.string().optional(),
        privateKey: z.string().optional(),
        passphrase: z.string().optional(),
        name: z.string().optional(),
        rememberPassword: z.boolean().optional().default(true),
        tags: z.array(z.string()).optional()
      },
      async (params) => {
        try {
          // Build connection configuration
          const config: SSHConnectionConfig = {
            host: params.host,
            port: params.port || parseInt(process.env.DEFAULT_SSH_PORT || '22'),
            username: params.username,
            password: params.password,
            keepaliveInterval: 60000,
            readyTimeout: parseInt(process.env.CONNECTION_TIMEOUT || '10000'),
            reconnect: true,
            reconnectTries: parseInt(process.env.RECONNECT_ATTEMPTS || '3'),
            reconnectDelay: 5000
          };
          
          // If private key is provided, prioritize private key authentication
          if (params.privateKey) {
            config.privateKey = params.privateKey;
            config.passphrase = params.passphrase;
          }
          
          // Connect to server
          const connection = await this.sshService.connect(
            config, 
            params.name, 
            params.rememberPassword,
            params.tags
          );
          
          // Record active connection
          this.activeConnections.set(connection.id, new Date());
          
          return {
            content: [{
              type: "text",
              text: `Connection successful!\n\n${this.formatConnectionInfo(connection)}`
            }]
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Connection failed: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );
    
    // Disconnect
    this.server.tool(
      "disconnect",
      "Disconnects an active SSH connection.",
      {
        connectionId: z.string()
      },
      async ({ connectionId }) => {
        try {
          const connection = this.sshService.getConnection(connectionId);
          if (!connection) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connectionId} does not exist`
              }],
              isError: true
            };
          }
          
          // Stop background tasks first
          if (this.backgroundExecutions.has(connectionId)) {
            this.stopBackgroundExecution(connectionId);
          }
          
          const success = await this.sshService.disconnect(connectionId);
          
          // Remove active connection record
          this.activeConnections.delete(connectionId);
          
          if (success) {
            return {
              content: [{
                type: "text",
                text: `Successfully disconnected from ${connection.name || connectionId}`
              }]
            };
          } else {
            return {
              content: [{
                type: "text",
                text: `Failed to disconnect`
              }],
              isError: true
            };
          }
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error disconnecting: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );
    
    // Get all connections
    this.server.tool(
      "listConnections",
      "Lists all saved SSH connections.",
      {},
      async () => {
        try {
          const connections = await this.sshService.getAllConnections();
          
          if (connections.length === 0) {
            return {
              content: [{
                type: "text",
                text: "No saved connections"
              }]
            };
          }
          
          const formattedConnections = connections.map(conn => 
            this.formatConnectionInfo(conn)
          ).join("\n---\n");
          
          return {
            content: [{
              type: "text",
              text: `Saved connections:\n\n${formattedConnections}`
            }]
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error getting connection list: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );
    
    // Get connection details
    this.server.tool(
      "getConnection",
      "Gets detailed information about a specific SSH connection.",
      {
        connectionId: z.string()
      },
      ({ connectionId }) => {
        try {
          const connection = this.sshService.getConnection(connectionId);
          
          if (!connection) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connectionId} does not exist`
              }],
              isError: true
            };
          }
          
          return {
            content: [{
              type: "text",
              text: this.formatConnectionInfo(connection, true)
            }]
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error getting connection details: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );
    
    // Delete connection
    this.server.tool(
      "deleteConnection",
      "Deletes a saved SSH connection.",
      {
        connectionId: z.string()
      },
      async ({ connectionId }) => {
        try {
          const connection = this.sshService.getConnection(connectionId);
          
          if (!connection) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connectionId} does not exist`
              }],
              isError: true
            };
          }
          
          const name = connection.name || connectionId;
          
          // Stop background tasks
          if (this.backgroundExecutions.has(connectionId)) {
            this.stopBackgroundExecution(connectionId);
          }
          
          // Remove active connection record
          this.activeConnections.delete(connectionId);
          
          const success = await this.sshService.deleteConnection(connectionId);
          
          if (success) {
            return {
              content: [{
                type: "text",
                text: `Successfully deleted connection "${name}"`
              }]
            };
          } else {
            return {
              content: [{
                type: "text",
                text: `Failed to delete connection`
              }],
              isError: true
            };
          }
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error deleting connection: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );

    // Update connection configuration
    this.server.tool(
      "updateConnection",
      "Updates the configuration of an existing SSH connection. Can change host, port, credentials, etc. without deleting the connection. Credentials are securely stored using keytar when rememberPassword is true.",
      {
        connectionId: z.string(),
        host: z.string().optional(),
        port: z.number().optional(),
        username: z.string().optional(),
        password: z.string().optional(),
        privateKey: z.string().optional(),
        passphrase: z.string().optional(),
        name: z.string().optional(),
        rememberPassword: z.boolean().optional().default(false),
        reconnect: z.boolean().optional().default(false)
      },
      async ({ connectionId, host, port, username, password, privateKey, passphrase, name, rememberPassword, reconnect }) => {
        try {
          const connection = this.sshService.getConnection(connectionId);

          if (!connection) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connectionId} does not exist`
              }],
              isError: true
            };
          }

          const oldHost = connection.config.host;
          const oldName = connection.name || connectionId;

          // Build updated config (only include provided values)
          const updatedConfig: Partial<SSHConnectionConfig> = {};
          if (host !== undefined) updatedConfig.host = host;
          if (port !== undefined) updatedConfig.port = port;
          if (username !== undefined) updatedConfig.username = username;
          if (password !== undefined) updatedConfig.password = password;
          if (privateKey !== undefined) updatedConfig.privateKey = privateKey;
          if (passphrase !== undefined) updatedConfig.passphrase = passphrase;

          // Update connection (credentials saved to keytar if rememberPassword=true)
          const updatedConn = await this.sshService.updateConnection(
            connectionId,
            { ...updatedConfig, name },
            rememberPassword
          );

          // Clear sensitive data from memory after saving
          if (rememberPassword && (password !== undefined || passphrase !== undefined)) {
            updatedConn.config.password = undefined;
            updatedConn.config.passphrase = undefined;
          }

          // Reconnect if requested
          if (reconnect) {
            await this.sshService.connect(updatedConn.config, updatedConn.name, rememberPassword, updatedConn.tags);
          }

          let output = `Connection "${oldName}" updated:\n`;
          if (host && host !== oldHost) output += `  Host: ${oldHost} → ${host}\n`;
          if (port !== undefined) output += `  Port: ${updatedConn.config.port}\n`;
          if (username !== undefined) output += `  Username: ${username}\n`;
          if (name !== undefined && name !== oldName) output += `  Name: ${oldName} → ${name}\n`;
          if (rememberPassword && (password !== undefined || passphrase !== undefined)) {
            output += `  Credentials: Securely saved to keytar 🔒\n`;
          }
          output += `\n${this.formatConnectionInfo(updatedConn)}`;

          return {
            content: [{
              type: "text",
              text: output
            }]
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error updating connection: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );
  }

  /**
   * Register command execution tools
   */
  private registerCommandTools(): void {
    // Execute command
    this.server.tool(
      "executeCommand",
      "Executes a command on a remote server via SSH.",
      {
        connectionId: z.string(),
        command: z.string(),
        cwd: z.string().optional(),
        timeout: z.number().optional(),
        force: z.boolean().optional()
      },
      async ({ connectionId, command, cwd, timeout, force }) => {
        try {
          const connection = this.sshService.getConnection(connectionId);
          
          if (!connection) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connectionId} does not exist`
              }],
              isError: true
            };
          }
          
          if (connection.status !== ConnectionStatus.CONNECTED) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connection.name || connectionId} is not connected`
              }],
              isError: true
            };
          }
          
          // Update active time
          this.activeConnections.set(connectionId, new Date());

          // Parse tmux commands
          const tmuxSendKeysRegex = /tmux\s+send-keys\s+(?:-t\s+)?["']?([^"'\s]+)["']?\s+["']?(.+?)["']?\s+(?:Enter|C-m)/i;
          const tmuxCaptureRegex = /tmux\s+capture-pane\s+(?:-t\s+)["']?([^"'\s]+)["']?/i;
          const tmuxNewSessionRegex = /tmux\s+new-session\s+(?:-[ds]\s+)+(?:-s\s+)["']?([^"'\s]+)["']?/i;
          const tmuxKillSessionRegex = /tmux\s+kill-session\s+(?:-t\s+)["']?([^"'\s]+)["']?/i;
          const tmuxHasSessionRegex = /tmux\s+has-session\s+(?:-t\s+)["']?([^"'\s]+)["']?/i;

          // Check if tmux session content needs to be captured before execution (to compare before/after differences)
          let beforeCapture: CommandResult | undefined;
          let sessionName: string | null = null;

          if (tmuxSendKeysRegex.test(command)) {
            const match = command.match(tmuxSendKeysRegex);
            if (match) {
              sessionName = match[1];

              // Only check for blocking if not forced execution
              if (!force) {
                try {
                  // Capture current session content
                  const checkResult: CommandResult = await this.sshService.executeCommand(
                    connectionId,
                    `tmux list-panes -t ${sessionName} -F "#{pane_pid} #{pane_current_command}"`,
                    { cwd, timeout: 5000 }
                  );

                  if (checkResult?.stdout) {
                    const [panePid, currentCommand] = checkResult.stdout.trim().split(' ');

                    if (panePid) {
                      // Get process state
                      const processResult: CommandResult = await this.sshService.executeCommand(
                        connectionId,
                        `ps -o state= -p ${panePid}`,
                        { timeout: 3000 }
                      );

                      const processState = processResult?.stdout?.trim();

                      // Check if in blocked state
                      const isBlocked =
                        // Process state check
                        processState === 'D' || // Uninterruptible sleep
                        processState === 'T' || // Stopped
                        processState === 'W' || // Paging wait

                        // Common interactive programs
                        /^(vim|nano|less|more|top|htop|man)$/.test(currentCommand) ||

                        // Check if there are child processes running
                        ((await this.sshService.executeCommand(
                          connectionId,
                          `pgrep -P ${panePid}`,
                          { timeout: 3000 }
                        ) as CommandResult)?.stdout || '').trim() !== '';

                      if (isBlocked) {
                        // Get more detailed process information
                        const processInfo = await this.sshService.executeCommand(
                          connectionId,
                          `ps -o pid,ppid,stat,time,command -p ${panePid}`,
                          { timeout: 3000 }
                        );

                        // Get command line context
                        const contextOutput = await this.sshService.executeCommand(
                          connectionId,
                          `tmux capture-pane -p -t ${sessionName} -S -10`,
                          { timeout: 3000 }
                        );

                        return {
                          content: [{
                            type: "text",
                            text: `Warning: tmux session "${sessionName}" currently has a blocked process:\n\n` +
                                  `Current session context:\n${contextOutput.stdout}\n\n` +
                                  `Process info:\n${processInfo.stdout}\n\n` +
                                  `Suggested actions:\n` +
                                  `1. If it's an interactive program (vim/nano etc), please exit normally first\n` +
                                  `2. If it's a background task, you can:\n` +
                                  `   - Wait for task completion (run sleep <seconds> to wait)\n` +
                                  `   - Use Ctrl+C (tmux send-keys -t ${sessionName} C-c)\n` +
                                  `   - Use kill -TERM ${panePid} to terminate process\n\n` +
                                  `To avoid command conflict, this operation was cancelled. If you want to force execution, add force: true parameter.`
                          }],
                          isError: true
                        };
                      }
                    }
                  }
                } catch (error) {
                  console.error('Error checking tmux session status:', error);
                }
              }
            }
          }

          // Check if it's a tmux command
          const isTmuxSendKeys = tmuxSendKeysRegex.test(command);
          const isTmuxCapture = tmuxCaptureRegex.test(command);
          const isTmuxNewSession = tmuxNewSessionRegex.test(command);
          const isTmuxKillSession = tmuxKillSessionRegex.test(command);
          const isTmuxHasSession = tmuxHasSessionRegex.test(command);
          const isTmuxCommand = isTmuxSendKeys || isTmuxCapture || isTmuxNewSession || isTmuxKillSession || isTmuxHasSession;

          // Execute command
          const result = await this.sshService.executeCommand(connectionId, command, { cwd, timeout });

          // Build output
          let output = '';

          // Build command prompt
          const currentDir = connection.currentDirectory || '~';
          const promptPrefix = `[${connection.config.username}@${connection.config.host}`;

          if (result.stdout) {
            output += result.stdout;
          }

          if (result.stderr) {
            if (output) output += '\n';
            output += `Error output:\n${result.stderr}`;
          }

          if (result.code !== 0) {
            output += `\nCommand exit code: ${result.code}`;
          }

          // Add current directory prompt at end of output
          if (output) output += '\n';
          output += `\n${promptPrefix} ${currentDir}]$ `;

          // If tmux command executed successfully, enhance output information
          if (isTmuxCommand && result.code === 0 && (!output || output.trim() === '')) {
            try {
              // Identify command type and process

              // For send-keys command
              if (isTmuxSendKeys && sessionName && beforeCapture?.stdout) {
                // Wait for command to complete
                await new Promise(resolve => setTimeout(resolve, 300));
                
                // Capture current content of tmux session
                const afterCapture = await this.sshService.executeCommand(
                  connectionId,
                  `tmux capture-pane -p -t ${sessionName}`,
                  { cwd, timeout: 5000 }
                );

                if (afterCapture?.stdout && beforeCapture?.stdout) {
                  // Compare before/after differences, extract new content
                  const beforeLines = beforeCapture.stdout.trim().split('\n');
                  const afterLines = afterCapture.stdout.trim().split('\n');
                  
                  // Calculate content differences
                  let diffOutput = '';
                  
                  // Calculate number of common prefix lines
                  let commonPrefix = 0;
                  
                  // Method 1: Find first different line from end
                  if (beforeLines.length > 0 && afterLines.length > 0) {
                    // Find number of common prefix lines
                    while (commonPrefix < Math.min(beforeLines.length, afterLines.length) && 
                           beforeLines[commonPrefix] === afterLines[commonPrefix]) {
                      commonPrefix++;
                    }
                    
                    // Extract newly added lines
                    const newLines = afterLines.slice(commonPrefix);
                    
                    if (newLines.length > 0) {
                      diffOutput = newLines.join('\n');
                    }
                    
                    // If extraction fails or no difference, try method 2
                    if (!diffOutput) {
                      // Method 2: Simply compare before/after text length, if longer, take the added part
                      if (afterCapture.stdout.length > beforeCapture.stdout.length) {
                        const commonStart = beforeCapture.stdout.length;
                        // Extract added content
                        diffOutput = afterCapture.stdout.substring(commonStart);
                      }
                    }
                  }
                  
                  // If there's diff output, use it but add more context
                  if (diffOutput && diffOutput.trim()) {
                    // Get more context: find where the diff starts
                    let contextOutput = '';

                    // Look up 2-3 command prompt markers (usually $ or #) to provide context
                    const promptRegex = /^.*[\$#>]\s+/m;
                    let promptCount = 0;
                    let contextLines = [];

                    // Search up from the middle of the original output
                    const midPoint = Math.max(0, commonPrefix - 15);
                    for (let i = midPoint; i < afterLines.length; i++) {
                      contextLines.push(afterLines[i]);
                      // If we encounter a command prompt, increment count
                      if (promptRegex.test(afterLines[i])) {
                        promptCount++;
                      }

                      // If we've found 2 command prompts or reached the diff section, stop
                      if (promptCount >= 2 || i >= commonPrefix) {
                        break;
                      }
                    }

                    // Then add the diff section
                    contextOutput = contextLines.join('\n');
                    if (contextOutput && !contextOutput.endsWith('\n')) {
                      contextOutput += '\n';
                    }

                    // Add diff output
                    contextOutput += diffOutput.trim();

                    output = `Command sent to tmux session "${sessionName}" with context output:\n\n${contextOutput}`;
                  }
                  // If no diff found but content changed, show last part of session content (with context)
                  else if (beforeCapture.stdout !== afterCapture.stdout) {
                    // Try to get last few commands and output
                    const lastLines = afterLines.slice(-30).join('\n');

                    // Find command prompts to extract last few commands
                    const promptPositions = [];
                    const promptRegex = /^.*[\$#>]\s+/m;

                    // Find all command prompt positions
                    for (let i = Math.max(0, afterLines.length - 30); i < afterLines.length; i++) {
                      if (promptRegex.test(afterLines[i])) {
                        promptPositions.push(i);
                      }
                    }

                    // If we found at least one command prompt
                    if (promptPositions.length > 0) {
                      // Take last 3 commands (if available)
                      const startPosition = promptPositions.length > 3
                        ? promptPositions[promptPositions.length - 3]
                        : promptPositions[0];

                      const contextOutput = afterLines.slice(startPosition).join('\n');
                      output = `Command sent to tmux session "${sessionName}", recent commands and output:\n\n${contextOutput}`;
                    } else {
                      // If no command prompts found, use last 20 lines
                      output = `Command sent to tmux session "${sessionName}", recent content:\n\n${lastLines}`;
                    }
                  }
                  // No significant change
                  else {
                    output = `Command sent to tmux session "${sessionName}", but no output change detected`;
                  }
                }
              }
              // For new-session command
              else if (isTmuxNewSession) {
                const match = command.match(tmuxNewSessionRegex);
                if (match) {
                  const sessionName = match[1];
                  output = `Created new tmux session "${sessionName}"`;

                  // Check if session was actually created successfully
                  const checkResult = await this.sshService.executeCommand(
                    connectionId,
                    `tmux has-session -t ${sessionName} 2>/dev/null && echo "Session exists" || echo "Session creation failed"`,
                    { timeout: 3000 }
                  );

                  if (checkResult.stdout && checkResult.stdout.includes("Session exists")) {
                    output += `\nSession successfully started and running in background`;
                  }
                }
              }
              // For kill-session command
              else if (isTmuxKillSession) {
                const match = command.match(tmuxKillSessionRegex);
                if (match) {
                  const sessionName = match[1];
                  output = `Terminated tmux session "${sessionName}"`;
                }
              }
              // For has-session command
              else if (isTmuxHasSession) {
                const match = command.match(tmuxHasSessionRegex);
                if (match) {
                  const sessionName = match[1];
                  if (result.code === 0) {
                    output = `tmux session "${sessionName}" exists`;
                  } else {
                    output = `tmux session "${sessionName}" does not exist`;
                  }
                }
              }
              // For capture-pane command
              else if (isTmuxCapture) {
                // If it's directly a capture-pane command, output is its result, no special handling needed
                if (!output || output.trim() === '') {
                  const match = command.match(tmuxCaptureRegex);
                  if (match) {
                    const sessionName = match[1];
                    output = `tmux session "${sessionName}" content captured, but original command returned no output`;
                  }
                }
              }
              // For compound commands (containing multiple tmux commands)
              else if (command.includes("tmux") && (command.includes("&&") || command.includes(";"))) {
                // Try to extract the last tmux command's session name
                const tmuxCommands = command.split(/&&|;/).map(cmd => cmd.trim());
                let lastSessionName = null;

                for (const cmd of tmuxCommands) {
                  let match;
                  if ((match = cmd.match(tmuxNewSessionRegex)) ||
                      (match = cmd.match(tmuxKillSessionRegex)) ||
                      (match = cmd.match(tmuxHasSessionRegex)) ||
                      (match = cmd.match(tmuxSendKeysRegex)) ||
                      (match = cmd.match(tmuxCaptureRegex))) {
                    lastSessionName = match[1];
                  }
                }

                if (lastSessionName) {
                  // If last command creates a session, notify user that session was created
                  if (tmuxCommands[tmuxCommands.length-1].includes("new-session")) {
                    output = `Executed tmux compound command, last created session "${lastSessionName}"`;

                    // Wait for session creation to complete
                    await new Promise(resolve => setTimeout(resolve, 500));

                    // Check if session was actually created successfully
                    const checkResult = await this.sshService.executeCommand(
                      connectionId,
                      `tmux has-session -t ${lastSessionName} 2>/dev/null && echo "Session exists" || echo "Session creation failed"`,
                      { timeout: 3000 }
                    );

                    if (checkResult.stdout && checkResult.stdout.includes("Session exists")) {
                      output += `\nSession successfully started and running in background`;
                    }
                  }
                  // If last command is kill-session, notify user that session was terminated
                  else if (tmuxCommands[tmuxCommands.length-1].includes("kill-session")) {
                    output = `Executed tmux compound command, last terminated session "${lastSessionName}"`;
                  }
                  // For other compound commands, try to capture the last session's content
                  else {
                    await new Promise(resolve => setTimeout(resolve, 500));

                    // Wait for session blocking to clear or timeout (max 10 minutes)
                    let isBlocked = true;
                    let waitStartTime = Date.now();
                    const maxWaitTime = 10 * 60 * 1000; // 10 minutes
                    
                    while (isBlocked && (Date.now() - waitStartTime < maxWaitTime)) {
                      try {
                        // Check if session is in blocked state
                        const checkResult = await this.sshService.executeCommand(
                          connectionId,
                          `tmux list-panes -t ${lastSessionName} -F "#{pane_pid} #{pane_current_command}"`,
                          { cwd, timeout: 5000 }
                        );
                        
                        if (checkResult?.stdout) {
                          const [panePid, currentCommand] = checkResult.stdout.trim().split(' ');
                          
                          if (panePid) {
                            // Get process status
                            const processResult = await this.sshService.executeCommand(
                              connectionId,
                              `ps -o state= -p ${panePid}`,
                              { timeout: 3000 }
                            );

                            const processState = processResult?.stdout?.trim();

                            // Check if in blocked state
                            isBlocked =
                              // Process state check
                              processState === 'D' || // Uninterruptible sleep
                              processState === 'T' || // Stopped
                              processState === 'W' || // Paging wait

                              // Common interactive programs
                              /^(vim|nano|less|more|top|htop|man)$/.test(currentCommand) ||

                              // Check if there are child processes running
                              ((await this.sshService.executeCommand(
                                connectionId,
                                `pgrep -P ${panePid}`,
                                { timeout: 3000 }
                              ))?.stdout || '').trim() !== '';

                            if (!isBlocked) {
                              // Blocking cleared, exit loop
                              break;
                            }

                            // Wait before checking again
                            await new Promise(resolve => setTimeout(resolve, 5000));
                          } else {
                            // No valid process ID, assume no blocking
                            isBlocked = false;
                          }
                        } else {
                          // Cannot get session info, assume no blocking
                          isBlocked = false;
                        }
                      } catch (error) {
                        console.error('Error checking session blocking status:', error);
                        // Assume no blocking on error to avoid infinite loop
                        isBlocked = false;
                      }
                    }

                    // Check if loop exited due to timeout
                    if (isBlocked && (Date.now() - waitStartTime >= maxWaitTime)) {
                      // Get current status info
                      try {
                        const processInfo = await this.sshService.executeCommand(
                          connectionId,
                          `tmux list-panes -t ${lastSessionName} -F "#{pane_pid}" | xargs ps -o pid,ppid,stat,time,command -p`,
                          { timeout: 5000 }
                        );

                        const contextOutput = await this.sshService.executeCommand(
                          connectionId,
                          `tmux capture-pane -p -t ${lastSessionName} -S -10`,
                          { timeout: 3000 }
                        );

                        output = `Executed tmux compound command, but session "${lastSessionName}" is still blocked after 10 minutes:\n\n` +
                                `Current session context:\n${contextOutput.stdout}\n\n` +
                                `Process info:\n${processInfo.stdout}\n\n` +
                                `If this is normal, please run sleep <seconds> command to wait`;
                      } catch (error) {
                        output = `Executed tmux compound command, but session "${lastSessionName}" is still blocked after 10 minutes. Cannot get detailed info.`;
                      }
                    } else {
                      // Blocking cleared or session doesn't exist, get session content
                      try {
                        const captureResult = await this.sshService.executeCommand(
                          connectionId,
                          `tmux has-session -t ${lastSessionName} 2>/dev/null && tmux capture-pane -p -t ${lastSessionName} || echo "Session does not exist"`,
                          { cwd, timeout: 5000 }
                        );

                        if (captureResult.stdout && !captureResult.stdout.includes("Session does not exist")) {
                          // Extract last 40 lines
                          const lines = captureResult.stdout.split('\n');
                          const lastLines = lines.slice(-40).join('\n');

                          output = `Executed tmux compound command, session "${lastSessionName}" current content:\n\n${lastLines}`;
                        } else {
                          output = `Executed tmux compound command, but session "${lastSessionName}" does not exist or cannot capture content`;
                        }
                      } catch (err) {
                        output = `Executed tmux compound command, involving session "${lastSessionName}"`;
                      }
                    }
                  }
                } else {
                  output = "Executed tmux compound command";
                }
              }
            } catch (captureError) {
              console.error('Error processing tmux command output:', captureError);
              // If capture fails, use original output
              output = `tmux command executed, but cannot get additional info: ${captureError instanceof Error ? captureError.message : String(captureError)}`;
            }
          }

          // Handle output length limit
          output = this.limitOutputLength(output);

          return {
            content: [{
              type: "text",
              text: output || 'Command executed successfully, no output'
            }]
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error executing command: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );

    // Execute command in background
    this.server.tool(
      "backgroundExecute",
      "Executes a command in the background on a remote server at a specified interval.",
      {
        connectionId: z.string(),
        command: z.string(),
        interval: z.number().optional(),
        cwd: z.string().optional()
      },
      async ({ connectionId, command, interval = 10000, cwd }) => {
        try {
          const connection = this.sshService.getConnection(connectionId);
          
          if (!connection) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connectionId} does not exist`
              }],
              isError: true
            };
          }
          
          if (connection.status !== ConnectionStatus.CONNECTED) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connection.name || connectionId} is not connected`
              }],
              isError: true
            };
          }

          // If background task exists, stop it first
          if (this.backgroundExecutions.has(connectionId)) {
            this.stopBackgroundExecution(connectionId);
          }

          // Update active time
          this.activeConnections.set(connectionId, new Date());

          // Execute command once first
          await this.sshService.executeCommand(connectionId, command, { cwd });

          // Set up timer
          const timer = setInterval(async () => {
            try {
              const conn = this.sshService.getConnection(connectionId);
              if (conn && conn.status === ConnectionStatus.CONNECTED) {
                await this.sshService.executeCommand(connectionId, command, { cwd });

                // Update last check time
                const bgExec = this.backgroundExecutions.get(connectionId);
                if (bgExec) {
                  bgExec.lastCheck = new Date();
                }
              } else {
                // If connection is not available, stop background task
                this.stopBackgroundExecution(connectionId);
              }
            } catch (error) {
              console.error(`Error executing background command:`, error);
              // Don't stop task, continue with next attempt
            }
          }, interval);

          // Record background task
          this.backgroundExecutions.set(connectionId, {
            interval: timer,
            lastCheck: new Date()
          });

          return {
            content: [{
              type: "text",
              text: `Started command in background: ${command}\nInterval: ${interval / 1000}s\nConnection: ${connection.name || connectionId}\n\nUse stopBackground tool to stop this background task.`
            }]
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error setting up background task: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );

    // Stop background execution
    this.server.tool(
      "stopBackground",
      "Stops a background command execution on a specific connection.",
      {
        connectionId: z.string()
      },
      ({ connectionId }) => {
        try {
          const connection = this.sshService.getConnection(connectionId);
          
          if (!connection) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connectionId} does not exist`
              }],
              isError: true
            };
          }
          
          if (!this.backgroundExecutions.has(connectionId)) {
            return {
              content: [{
                type: "text",
                text: `Connection ${connection.name || connectionId} has no running background tasks`
              }]
            };
          }

          // Stop background task
          this.stopBackgroundExecution(connectionId);
          
          return {
            content: [{
              type: "text",
              text: `Stopped background tasks for connection ${connection.name || connectionId}`
            }]
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error stopping background task: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );

    // Get current directory tool
    this.server.tool(
      "getCurrentDirectory",
      "Gets the current working directory of an SSH connection.",
      {
        connectionId: z.string()
      },
      async ({ connectionId }) => {
        try {
          const connection = this.sshService.getConnection(connectionId);
          
          if (!connection) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connectionId} does not exist`
              }],
              isError: true
            };
          }
          
          if (connection.status !== ConnectionStatus.CONNECTED) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connection.name || connectionId} is not connected`
              }],
              isError: true
            };
          }

          // Update active time
          this.activeConnections.set(connectionId, new Date());

          // Get current directory
          const result = await this.sshService.executeCommand(connectionId, 'pwd');
          
          return {
            content: [{
              type: "text",
              text: result.stdout.trim()
            }]
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error getting current directory: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );
  }

  /**
   * Register file transfer tools
   */
  private registerFileTools(): void {
    // Upload file
    this.server.tool(
      "uploadFile",
      "Uploads a local file to a remote server.",
      {
        connectionId: z.string(),
        localPath: z.string(),
        remotePath: z.string()
      },
      async ({ connectionId, localPath, remotePath }) => {
        try {
          const connection = this.sshService.getConnection(connectionId);
          
          if (!connection) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connectionId} does not exist`
              }],
              isError: true
            };
          }
          
          if (connection.status !== ConnectionStatus.CONNECTED) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connection.name || connectionId} is not connected`
              }],
              isError: true
            };
          }

          // Check if local file exists
          if (!fs.existsSync(localPath)) {
            return {
              content: [{
                type: "text",
                text: `Error: Local file "${localPath}" does not exist`
              }],
              isError: true
            };
          }

          // Update active time
          this.activeConnections.set(connectionId, new Date());

          // Upload file and get transfer ID
          const transferInfo = await this.sshService.uploadFile(connectionId, localPath, remotePath);
          const transferId = transferInfo.id;

          // Listen to transfer progress
          const unsubscribe = this.sshService.onTransferProgress((info: FileTransferInfo) => {
            // Only send updates when progress changes by more than 5%, avoid too many events
            if (info.progress % 5 === 0 || info.status === 'completed' || info.status === 'failed') {
              (this.server as any).sendEvent('file_transfer_progress', {
                transferId: info.id,
                progress: Math.round(info.progress),
                status: info.status,
                human: `File transfer ${info.id} - ${info.status}: ${Math.round(info.progress)}% (${this.formatFileSize(info.bytesTransferred)}/${this.formatFileSize(info.size)})`
              });
            }
          });

          try {
            // Get final result
            const result = this.sshService.getTransferInfo(transferId);
            
            if (result && result.status === 'failed') {
              return {
                content: [{
                  type: "text",
                  text: `File upload failed: ${result.error || 'Unknown error'}`
                }],
                isError: true,
                transferId
              };
            }
            
            const fileName = path.basename(localPath);
            
            return {
              content: [{
                type: "text",
                text: `File "${fileName}" uploaded successfully\nLocal path: ${localPath}\nRemote path: ${remotePath}`
              }],
              transferId
            };
          } finally {
            // Ensure we always unsubscribe
            unsubscribe();
          }
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error uploading file: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );

    // Download file
    this.server.tool(
      "downloadFile",
      "Downloads a file from a remote server to the local machine.",
      {
        connectionId: z.string(),
        remotePath: z.string(),
        localPath: z.string().optional()
      },
      async ({ connectionId, remotePath, localPath }) => {
        try {
          const connection = this.sshService.getConnection(connectionId);
          
          if (!connection) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connectionId} does not exist`
              }],
              isError: true
            };
          }
          
          if (connection.status !== ConnectionStatus.CONNECTED) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connection.name || connectionId} is not connected`
              }],
              isError: true
            };
          }

          // Determine local save path
          let savePath = localPath;
          if (!savePath) {
            const fileName = path.basename(remotePath);
            savePath = path.join(os.homedir(), 'Downloads', fileName);

            // Ensure directory exists
            const saveDir = path.dirname(savePath);
            if (!fs.existsSync(saveDir)) {
              fs.mkdirSync(saveDir, { recursive: true });
            }
          }

          // Update active time
          this.activeConnections.set(connectionId, new Date());

          // Download file and get transfer ID
          const transferInfo = await this.sshService.downloadFile(connectionId, remotePath, savePath);
          const transferId = transferInfo.id;

          // Listen to transfer progress
          const unsubscribe = this.sshService.onTransferProgress((info: FileTransferInfo) => {
            // Only send updates when progress changes by more than 5%, avoid too many events
            if (info.progress % 5 === 0 || info.status === 'completed' || info.status === 'failed') {
              (this.server as any).sendEvent('file_transfer_progress', {
                transferId: info.id,
                progress: Math.round(info.progress),
                status: info.status,
                human: `File transfer ${info.id} - ${info.status}: ${Math.round(info.progress)}% (${this.formatFileSize(info.bytesTransferred)}/${this.formatFileSize(info.size)})`
              });
            }
          });

          try {
            // Get final result
            const result = this.sshService.getTransferInfo(transferId);
            
            if (result && result.status === 'failed') {
              return {
                content: [{
                  type: "text",
                  text: `File download failed: ${result.error || 'Unknown error'}`
                }],
                isError: true,
                transferId
              };
            }
            
            const fileName = path.basename(remotePath);
            
            return {
              content: [{
                type: "text",
                text: `File "${fileName}" downloaded successfully\nRemote path: ${remotePath}\nLocal path: ${savePath}`
              }],
              transferId
            };
          } finally {
            // Ensure we always unsubscribe
            unsubscribe();
          }
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error downloading file: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );

    // Batch upload files
    this.server.tool(
      "batchUploadFiles",
      "Uploads multiple local files to a remote server.",
      {
        connectionId: z.string(),
        files: z.array(z.object({
          localPath: z.string(),
          remotePath: z.string()
        }))
      },
      async ({ connectionId, files }) => {
        try {
          const connection = this.sshService.getConnection(connectionId);

          if (!connection) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connectionId} does not exist`
              }],
              isError: true
            };
          }

          if (connection.status !== ConnectionStatus.CONNECTED) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connection.name || connectionId} is not connected`
              }],
              isError: true
            };
          }

          // Check if all local files exist
          const missingFiles = files.filter(file => !fs.existsSync(file.localPath));
          if (missingFiles.length > 0) {
            return {
              content: [{
                type: "text",
                text: `Error: The following local files do not exist:\n${missingFiles.map(f => f.localPath).join('\n')}`
              }],
              isError: true
            };
          }

          // Update active time
          this.activeConnections.set(connectionId, new Date());

          // Batch transfer files
          const transferIds = await this.sshService.batchTransfer({
            connectionId,
            items: files,
            direction: 'upload'
          });

          if (transferIds.length === 0) {
            return {
              content: [{
                type: "text",
                text: `No files were uploaded`
              }],
              isError: true
            };
          }

          // Get transfer info
          const transferInfos = transferIds.map(id => this.sshService.getTransferInfo(id)).filter(Boolean) as FileTransferInfo[];

          // Set up batch transfer progress listeners
          const listeners: (() => void)[] = [];

          for (const transferId of transferIds) {
            const unsubscribe = this.sshService.onTransferProgress((info: FileTransferInfo) => {
              if (info.id === transferId && (info.progress % 10 === 0 || info.status === 'completed' || info.status === 'failed')) {
                (this.server as any).sendEvent('batch_transfer_progress', {
                  transferId: info.id,
                  progress: Math.round(info.progress),
                  status: info.status,
                  direction: 'upload',
                  human: `Batch upload - File: ${path.basename(info.localPath)} - ${info.status}: ${Math.round(info.progress)}%`
                });
              }
            });

            listeners.push(unsubscribe);
          }

          try {
            // Wait for all transfers to complete
            await new Promise<void>((resolve) => {
              const checkInterval = setInterval(() => {
                const allDone = transferIds.every(id => {
                  const info = this.sshService.getTransferInfo(id);
                  return info && (info.status === 'completed' || info.status === 'failed');
                });

                if (allDone) {
                  clearInterval(checkInterval);
                  resolve();
                }
              }, 500);
            });

            // Calculate success and failure counts
            const successCount = transferInfos.filter(info => info.status === 'completed').length;
            const failedCount = transferInfos.filter(info => info.status === 'failed').length;

            return {
              content: [{
                type: "text",
                text: `Batch upload completed\nSuccessful: ${successCount} files\nFailed: ${failedCount} files`
              }],
              transferIds
            };
          } finally {
            // Clean up all listeners
            listeners.forEach(unsubscribe => unsubscribe());
          }
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error during batch upload: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );

    // Batch download files
    this.server.tool(
      "batchDownloadFiles",
      "Downloads multiple files from a remote server.",
      {
        connectionId: z.string(),
        files: z.array(z.object({
          remotePath: z.string(),
          localPath: z.string().optional()
        }))
      },
      async ({ connectionId, files }) => {
        try {
          const connection = this.sshService.getConnection(connectionId);
          
          if (!connection) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connectionId} does not exist`
              }],
              isError: true
            };
          }
          
          if (connection.status !== ConnectionStatus.CONNECTED) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connection.name || connectionId} is not connected`
              }],
              isError: true
            };
          }

          // Process local paths
          const normalizedFiles = files.map(file => {
            if (!file.remotePath) {
              return null; // Skip invalid items
            }

            // If no local path provided, generate a default path
            if (!file.localPath) {
              const fileName = path.basename(file.remotePath);
              const localPath = path.join(os.homedir(), 'Downloads', fileName);

              // Ensure directory exists
              const saveDir = path.dirname(localPath);
              if (!fs.existsSync(saveDir)) {
                fs.mkdirSync(saveDir, { recursive: true });
              }

              return { remotePath: file.remotePath, localPath };
            }
            return file;
          }).filter(item => item !== null) as { remotePath: string, localPath: string }[];

          if (normalizedFiles.length === 0) {
            return {
              content: [{
                type: "text",
                text: `Error: No valid file transfer items`
              }],
              isError: true
            };
          }

          // Update active time
          this.activeConnections.set(connectionId, new Date());

          // Start batch download
          const transferIds = await this.sshService.batchTransfer({
            connectionId,
            items: normalizedFiles,
            direction: 'download'
          });

          if (transferIds.length === 0) {
            return {
              content: [{
                type: "text",
                text: `No files were downloaded`
              }],
              isError: true
            };
          }

          // Get transfer info
          const transferInfos = transferIds.map(id => this.sshService.getTransferInfo(id)).filter(Boolean) as FileTransferInfo[];

          // Set up batch transfer progress listeners
          const listeners: (() => void)[] = [];

          for (const transferId of transferIds) {
            const unsubscribe = this.sshService.onTransferProgress((info: FileTransferInfo) => {
              if (info.id === transferId && (info.progress % 10 === 0 || info.status === 'completed' || info.status === 'failed')) {
                (this.server as any).sendEvent('batch_transfer_progress', {
                  transferId: info.id,
                  progress: Math.round(info.progress),
                  status: info.status,
                  direction: 'download',
                  human: `Batch download - File: ${path.basename(info.remotePath)} - ${info.status}: ${Math.round(info.progress)}%`
                });
              }
            });

            listeners.push(unsubscribe);
          }

          try {
            // Wait for all transfers to complete
            await new Promise<void>((resolve) => {
              const checkInterval = setInterval(() => {
                const allDone = transferIds.every(id => {
                  const info = this.sshService.getTransferInfo(id);
                  return info && (info.status === 'completed' || info.status === 'failed');
                });

                if (allDone) {
                  clearInterval(checkInterval);
                  resolve();
                }
              }, 500);
            });

            // Calculate success and failure counts
            const successCount = transferInfos.filter(info => info.status === 'completed').length;
            const failedCount = transferInfos.filter(info => info.status === 'failed').length;

            return {
              content: [{
                type: "text",
                text: `Batch download completed\nSuccessful: ${successCount} files\nFailed: ${failedCount} files`
              }],
              transferIds
            };
          } finally {
            // Clean up all listeners
            listeners.forEach(unsubscribe => unsubscribe());
          }
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error during batch download: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );

    // Get file transfer status
    this.server.tool(
      "getFileTransferStatus",
      "Gets the status of a specific file transfer.",
      {
        transferId: z.string()
      },
      async ({ transferId }) => {
        try {
          const transfer = this.sshService.getTransferInfo(transferId);
          
          if (!transfer) {
            return {
              content: [{
                type: "text",
                text: `Error: Transfer ${transferId} does not exist`
              }],
              isError: true
            };
          }

          let statusText;
          switch (transfer.status) {
            case 'pending':
              statusText = 'Pending';
              break;
            case 'in-progress':
              statusText = 'In progress';
              break;
            case 'completed':
              statusText = 'Completed';
              break;
            case 'failed':
              statusText = 'Failed';
              break;
            default:
              statusText = transfer.status;
          }

          const directionText = transfer.direction === 'upload' ? 'Upload' : 'Download';
          const fileName = transfer.direction === 'upload'
            ? path.basename(transfer.localPath)
            : path.basename(transfer.remotePath);

          let output = `File ${directionText} status:\n`;
          output += `ID: ${transfer.id}\n`;
          output += `File name: ${fileName}\n`;
          output += `Status: ${statusText}\n`;
          output += `Progress: ${Math.round(transfer.progress)}%\n`;
          output += `Size: ${this.formatFileSize(transfer.size)}\n`;
          output += `Transferred: ${this.formatFileSize(transfer.bytesTransferred)}\n`;

          if (transfer.startTime) {
            output += `Start time: ${transfer.startTime.toLocaleString()}\n`;
          }

          if (transfer.endTime) {
            output += `End time: ${transfer.endTime.toLocaleString()}\n`;

            // Calculate transfer speed
            const duration = (transfer.endTime.getTime() - transfer.startTime.getTime()) / 1000;
            if (duration > 0) {
              const speed = transfer.bytesTransferred / duration;
              output += `Average speed: ${this.formatFileSize(speed)}/s\n`;
            }
          }

          if (transfer.error) {
            output += `Error: ${transfer.error}\n`;
          }

          return {
            content: [{
              type: "text",
              text: output
            }],
            transfer
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error getting file transfer status: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );

    // List all file transfers
    this.server.tool(
      "listFileTransfers",
      "Lists all recent file transfers.",
      {},
      async () => {
        try {
          const transfers = this.sshService.getAllTransfers();

          if (transfers.length === 0) {
            return {
              content: [{
                type: "text",
                text: "No file transfer records"
              }]
            };
          }

          let output = `File transfer records (${transfers.length}):\n\n`;

          for (const transfer of transfers) {
            const fileName = transfer.direction === 'upload'
              ? path.basename(transfer.localPath)
              : path.basename(transfer.remotePath);

            let status;
            switch (transfer.status) {
              case 'pending':
                status = '⏳ Pending';
                break;
              case 'in-progress':
                status = '🔄 In progress';
                break;
              case 'completed':
                status = '✅ Completed';
                break;
              case 'failed':
                status = '❌ Failed';
                break;
              default:
                status = transfer.status;
            }

            output += `${status} ${transfer.direction === 'upload' ? '⬆️' : '⬇️'} ${fileName}\n`;
            output += `ID: ${transfer.id}\n`;
            output += `Progress: ${Math.round(transfer.progress)}% (${this.formatFileSize(transfer.bytesTransferred)}/${this.formatFileSize(transfer.size)})\n`;

            if (transfer.startTime) {
              output += `Start: ${transfer.startTime.toLocaleString()}\n`;
            }

            if (transfer.endTime) {
              output += `End: ${transfer.endTime.toLocaleString()}\n`;
            }

            if (transfer.error) {
              output += `Error: ${transfer.error}\n`;
            }

            output += '\n';
          }

          return {
            content: [{
              type: "text",
              text: output
            }],
            transfers
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error getting file transfer list: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );
  }

  /**
   * Register session management tools
   */
  private registerSessionTools(): void {
    // List active sessions
    this.server.tool(
      "listActiveSessions",
      "Lists all currently active SSH sessions.",
      {},
      async () => {
        try {
          if (this.activeConnections.size === 0) {
            return {
              content: [{
                type: "text",
                text: "No active sessions"
              }]
            };
          }

          let output = "Active sessions:\n\n";

          for (const [id, lastActive] of this.activeConnections.entries()) {
            const connection = this.sshService.getConnection(id);
            if (connection) {
              output += this.formatConnectionInfo(connection);
              output += `Last active: ${this.formatTimeDifference(lastActive)}\n`;

              if (this.backgroundExecutions.has(id)) {
                const bgExec = this.backgroundExecutions.get(id);
                if (bgExec) {
                  output += `Background tasks: Active, last executed: ${this.formatTimeDifference(bgExec.lastCheck)}\n`;
                }
              }

              output += "\n---\n\n";
            }
          }

          return {
            content: [{
              type: "text",
              text: output
            }]
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error getting active sessions: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );

    // List background tasks
    this.server.tool(
      "listBackgroundTasks",
      "Lists all background tasks currently running.",
      {},
      () => {
        try {
          if (this.backgroundExecutions.size === 0) {
            return {
              content: [{
                type: "text",
                text: "No running background tasks"
              }]
            };
          }

          let output = "Running background tasks:\n\n";

          for (const [id, info] of this.backgroundExecutions.entries()) {
            const connection = this.sshService.getConnection(id);
            if (connection) {
              output += `Connection: ${connection.name || connection.id}\n`;
              output += `Host: ${connection.config.host}\n`;
              output += `User: ${connection.config.username}\n`;
              output += `Status: ${connection.status}\n`;
              output += `Last executed: ${this.formatTimeDifference(info.lastCheck)}\n`;
              output += "\n---\n\n";
            }
          }

          return {
            content: [{
              type: "text",
              text: output
            }]
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error getting background tasks: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );

    // Stop all background tasks
    this.server.tool(
      "stopAllBackgroundTasks",
      "Stops all running background tasks.",
      {},
      () => {
        try {
          const count = this.backgroundExecutions.size;

          if (count === 0) {
            return {
              content: [{
                type: "text",
                text: "No running background tasks"
              }]
            };
          }

          // Stop all background tasks
          for (const id of this.backgroundExecutions.keys()) {
            this.stopBackgroundExecution(id);
          }

          return {
            content: [{
              type: "text",
              text: `Stopped all ${count} background tasks`
            }]
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error stopping all background tasks: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );
  }

  /**
   * Register terminal interaction tools
   */
  private registerTerminalTools() {
    // Create terminal session
    this.server.tool(
      "mcp_ssh_mcp_createTerminalSession",
      "Creates a new interactive terminal session.",
      {
        connectionId: z.string(),
        rows: z.number().optional(),
        cols: z.number().optional(),
        term: z.string().optional(),
      },
      async (params) => {
        try {
          const { connectionId, rows, cols, term } = params;
          const sessionId = await this.sshService.createTerminalSession(connectionId, { rows, cols, term });

          // Set up terminal data listener
          const unsubscribeData = this.sshService.onTerminalData((event) => {
            if (event.sessionId === sessionId) {
              // Apply output length limit
              const limitedData = this.limitOutputLength(event.data);

              (this.server as any).sendEvent('terminal_data', {
                sessionId: event.sessionId,
                data: limitedData,
                human: limitedData
              });
            }
          });

          // When terminal closes, unsubscribe
          const unsubscribeClose = this.sshService.onTerminalClose((event) => {
            if (event.sessionId === sessionId) {
              unsubscribeData();
              unsubscribeClose(); // Also unsubscribe itself
              (this.server as any).sendEvent('terminal_closed', {
                sessionId: event.sessionId,
                human: `Terminal session ${sessionId} closed`
              });
            }
          });

          return {
            content: [{
              type: "text",
              text: `Created terminal session ${sessionId}`
            }],
            sessionId
          };
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          console.error(`Failed to create terminal session:`, error);
          return {
            content: [{
              type: "text",
              text: `Failed to create terminal session: ${errorMessage}`
            }],
            isError: true
          };
        }
      }
    );

    // Write data to terminal
    this.server.tool(
      "mcp_ssh_mcp_writeToTerminal",
      "Writes data to an interactive terminal session.",
      {
        sessionId: z.string(),
        data: z.string()
      },
      async (params) => {
        try {
          const { sessionId, data } = params;
          const success = await this.sshService.writeToTerminal(sessionId, data);

          return {
            content: [{
              type: "text",
              text: success ? `Data sent to terminal ${sessionId}` : `Failed to send data`
            }],
            success
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error writing data to terminal: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );
  }

  /**
   * Register tunnel management tools
   */
  private registerTunnelTools(): void {
    // Create tunnel
    this.server.tool(
      "createTunnel",
      "Creates an SSH tunnel (port forwarding).",
      {
        connectionId: z.string(),
        localPort: z.number(),
        remoteHost: z.string(),
        remotePort: z.number(),
        description: z.string().optional()
      },
      async ({ connectionId, localPort, remoteHost, remotePort, description }) => {
        try {
          const connection = this.sshService.getConnection(connectionId);

          if (!connection) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connectionId} does not exist`
              }],
              isError: true
            };
          }

          if (connection.status !== ConnectionStatus.CONNECTED) {
            return {
              content: [{
                type: "text",
                text: `Error: Connection ${connection.name || connectionId} is not connected`
              }],
              isError: true
            };
          }

          // Create tunnel
          const tunnelId = await this.sshService.createTunnel({
            connectionId,
            localPort,
            remoteHost,
            remotePort,
            description
          });

          return {
            content: [{
              type: "text",
              text: `Tunnel created\nLocal port: ${localPort}\nRemote: ${remoteHost}:${remotePort}\nTunnel ID: ${tunnelId}`
            }],
            tunnelId
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error creating tunnel: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );

    // Close tunnel
    this.server.tool(
      "closeTunnel",
      "Closes an active SSH tunnel.",
      {
        tunnelId: z.string()
      },
      async ({ tunnelId }) => {
        try {
          const success = await this.sshService.closeTunnel(tunnelId);

          if (success) {
            return {
              content: [{
                type: "text",
                text: `Tunnel ${tunnelId} closed`
              }]
            };
          } else {
            return {
              content: [{
                type: "text",
                text: `Failed to close tunnel ${tunnelId}`
              }],
              isError: true
            };
          }
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error closing tunnel: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );

    // List all tunnels
    this.server.tool(
      "listTunnels",
      "Lists all active SSH tunnels.",
      {},
      () => {
        try {
          const tunnels = this.sshService.getTunnels();

          if (tunnels.length === 0) {
            return {
              content: [{
                type: "text",
                text: "No active tunnels"
              }]
            };
          }

          let output = "Active tunnels:\n\n";

          for (const tunnel of tunnels) {
            const connection = this.sshService.getConnection(tunnel.connectionId);
            output += `ID: ${tunnel.id}\n`;
            output += `Local port: ${tunnel.localPort}\n`;
            output += `Remote: ${tunnel.remoteHost}:${tunnel.remotePort}\n`;

            if (connection) {
              output += `Connection: ${connection.name || connection.id} (${connection.config.host})\n`;
            }

            if (tunnel.description) {
              output += `Description: ${tunnel.description}\n`;
            }

            output += "\n---\n\n";
          }

          return {
            content: [{
              type: "text",
              text: output
            }],
            tunnels
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `Error getting tunnel list: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      }
    );
  }

  /**
   * Close all connections and clean up resources
   */
  public async close(): Promise<void> {
    try {
      // Stop all background tasks
      for (const id of this.backgroundExecutions.keys()) {
        this.stopBackgroundExecution(id);
      }

      // Close all tunnels
      const tunnels = this.sshService.getTunnels();
      for (const tunnel of tunnels) {
        await this.sshService.closeTunnel(tunnel.id!);
      }

      // Close all terminal sessions
      const sessions = this.sshService.getAllTerminalSessions();
      for (const session of sessions) {
        await this.sshService.closeTerminalSession(session.id);
      }

      // Disconnect all connections
      const connections = await this.sshService.getAllConnections();
      for (const connection of connections) {
        if (connection.status === ConnectionStatus.CONNECTED) {
          await this.sshService.disconnect(connection.id);
        }
      }

      // Close SSH service
      await this.sshService.close();

      // Clear active connection records
      this.activeConnections.clear();
      this.backgroundExecutions.clear();
    } catch (error) {
      console.error('Error closing SSH MCP:', error);
      throw error;
    }
  }

  /**
   * Handle long text output, truncate to front and back parts when exceeding limit
   */
  private limitOutputLength(text: string, maxLength: number = 10000, targetLength: number = 6000): string {
    if (text.length <= maxLength) {
      return text;
    }

    // Calculate length to keep for front and back parts
    const halfTargetLength = Math.floor(targetLength / 2);
    
    // Extract front and back parts
    const prefix = text.substring(0, halfTargetLength);
    const suffix = text.substring(text.length - halfTargetLength);
    
    // Add omission indicator and hints for getting complete output
    const omittedLength = text.length - targetLength;
    const omittedMessage = `\n\n... ${omittedLength} characters omitted ...\n` +
                           `To view complete output, you can:\n` +
                           `- Use > output.txt to save output to file\n` +
                           `- Use | head -n number to view first few lines\n` +
                           `- Use | tail -n number to view last few lines\n` +
                           `- Use | grep "keyword" to filter lines containing specific content\n\n`;
    
    // Combine output
    return prefix + omittedMessage + suffix;
  }
}