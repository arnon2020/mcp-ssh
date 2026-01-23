import * as fs from 'fs';
import * as path from 'path';

// Lock file path configuration
const LOCK_FILE = path.join(process.cwd(), '.mcp-ssh.lock');

export class ProcessManager {
  private instanceId: string;

  constructor() {
    // Generate unique instance ID
    this.instanceId = Date.now().toString();
    
    // Register process exit handler
    this.registerCleanup();
  }

  private registerCleanup(): void {
    // Register multiple signals to ensure cleanup
    process.on('SIGINT', () => this.cleanup());
    process.on('SIGTERM', () => this.cleanup());
    process.on('exit', () => this.cleanup());
  }

  private cleanup(): void {
    try {
      if (fs.existsSync(LOCK_FILE)) {
        const lockData = JSON.parse(fs.readFileSync(LOCK_FILE, 'utf8'));
        // Only clean up own lock file
        if (lockData.instanceId === this.instanceId) {
          fs.rmSync(LOCK_FILE, { force: true });
        }
      }
    } catch (error) {
      console.error('Error cleaning up lock file:', error);
    }
  }

  private async waitForProcessExit(pid: number, maxWaitTime: number = 5000): Promise<boolean> {
    const startTime = Date.now();
    while (Date.now() - startTime < maxWaitTime) {
      try {
        process.kill(pid, 0);
        // If process is still running, wait 100ms and check again
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (e) {
        // Process has exited
        return true;
      }
    }
    return false;
  }

  public async checkAndCreateLock(): Promise<boolean> {
    try {
      // Check if lock file exists
      if (fs.existsSync(LOCK_FILE)) {
        const lockData = JSON.parse(fs.readFileSync(LOCK_FILE, 'utf8'));
        
        try {
          // Check if process is still running
          process.kill(lockData.pid, 0);
          console.log('Found existing MCP-SSH instance, terminating old process...');
          
          // Send termination signal to old process
          process.kill(lockData.pid, 'SIGTERM');
          
          // Wait for old process to exit
          const exited = await this.waitForProcessExit(lockData.pid);
          if (!exited) {
            console.error('Timeout waiting for old process to exit');
            return false;
          }
          
          // Delete old lock file
          fs.rmSync(LOCK_FILE, { force: true });
        } catch (e) {
          // Process does not exist, delete old lock file
          console.log('Found old lock file but process does not exist, cleaning up...');
          fs.rmSync(LOCK_FILE, { force: true });
        }
      }

      // Create new lock file
      fs.writeFileSync(LOCK_FILE, JSON.stringify({
        pid: process.pid,
        instanceId: this.instanceId,
        timestamp: Date.now()
      }));

      console.log('MCP-SSH process lock created successfully');
      return true;
    } catch (error) {
      console.error('Error handling lock file:', error);
      return false;
    }
  }
} 