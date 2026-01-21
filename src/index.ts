#!/usr/bin/env node

import { SshMCP } from './tools/ssh.js';
import { config } from 'dotenv';
import { ProcessManager } from './process-manager.js';

// Load environment variables
config();

// Main function
async function main() {
  // Initialize process manager
  const processManager = new ProcessManager();
  if (!await processManager.checkAndCreateLock()) {
    console.error('Cannot create process lock, exiting');
    process.exit(1);
  }

  // Instantiate SSH MCP
  const sshMCP = new SshMCP();

  // Handle process exit
  process.on('SIGINT', async () => {
    console.log('Shutting down SSH MCP service...');
    await sshMCP.close();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    console.log('Shutting down SSH MCP service...');
    await sshMCP.close();
    process.exit(0);
  });

  // Handle uncaught exceptions to prevent crashes
  process.on('uncaughtException', (err) => {
    console.error('Uncaught exception:', err);
    // Don't exit process, keep SSH service running
  });

  process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Promise rejection:', reason);
    // Don't exit process, keep SSH service running
  });

  console.log('SSH MCP service started');
}

// Start application
main().catch(error => {
  console.error('Startup failed:', error);
  process.exit(1);
}); 