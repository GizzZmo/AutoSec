/**
 * iptables/netfilter Integration
 * Provides integration with Linux iptables for network filtering and monitoring
 */

const { spawn, exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const logger = require('../config/logger');

class IptablesIntegration {
  constructor(config = {}) {
    this.config = {
      sudo: config.sudo !== false, // Use sudo by default
      iptablesPath: config.iptablesPath || '/sbin/iptables',
      ip6tablesPath: config.ip6tablesPath || '/sbin/ip6tables',
      timeout: config.timeout || 30000,
      backupPath: config.backupPath || '/tmp/autosec-iptables-backup',
      customChain: config.customChain || 'AUTOSEC',
      logPrefix: config.logPrefix || 'AutoSec: ',
    };
    
    this.ruleCache = new Map();
    this.backupFiles = [];
  }

  /**
   * Initialize iptables integration
   */
  async initialize() {
    try {
      // Test iptables availability
      await this.testCommand();
      
      // Create custom chains
      await this.createCustomChains();
      
      // Setup logging chain
      await this.setupLoggingChain();

      logger.info('iptables integration initialized successfully');
      return { success: true, timestamp: new Date() };
    } catch (error) {
      logger.error('Error initializing iptables integration:', error);
      throw error;
    }
  }

  /**
   * Block an IP address
   */
  async blockIP(ipAddress, reason = 'AutoSec Security Block', duration = null) {
    try {
      const isIPv6 = this.isIPv6(ipAddress);
      const iptablesCmd = isIPv6 ? this.config.ip6tablesPath : this.config.iptablesPath;
      
      // Create backup before making changes
      await this.createBackup();
      
      // Add to INPUT chain (incoming traffic)
      await this.executeCommand([
        iptablesCmd,
        '-I', this.config.customChain,
        '-s', ipAddress,
        '-j', 'DROP',
        '-m', 'comment',
        '--comment', `"${reason}"`
      ]);

      // Add to OUTPUT chain (outgoing traffic)
      await this.executeCommand([
        iptablesCmd,
        '-I', this.config.customChain,
        '-d', ipAddress,
        '-j', 'DROP',
        '-m', 'comment',
        '--comment', `"${reason}"`
      ]);

      // Log the block
      await this.logRule('BLOCK', ipAddress, reason);

      // Schedule automatic unblock if duration is specified
      if (duration && duration > 0) {
        setTimeout(async () => {
          try {
            await this.unblockIP(ipAddress);
            logger.info(`Automatically unblocked IP after ${duration}ms: ${ipAddress}`);
          } catch (error) {
            logger.error(`Error auto-unblocking IP ${ipAddress}:`, error);
          }
        }, duration);
      }

      logger.info('Successfully blocked IP address with iptables', {
        ipAddress,
        reason,
        duration,
        isIPv6,
      });

      return {
        success: true,
        ipAddress,
        action: 'blocked',
        method: 'iptables',
        timestamp: new Date(),
        duration,
      };
    } catch (error) {
      logger.error('Error blocking IP with iptables:', error);
      await this.restoreBackup(); // Attempt to restore on failure
      throw error;
    }
  }

  /**
   * Unblock an IP address
   */
  async unblockIP(ipAddress) {
    try {
      const isIPv6 = this.isIPv6(ipAddress);
      const iptablesCmd = isIPv6 ? this.config.ip6tablesPath : this.config.iptablesPath;
      
      // Create backup before making changes
      await this.createBackup();
      
      // Remove from INPUT chain
      await this.executeCommand([
        iptablesCmd,
        '-D', this.config.customChain,
        '-s', ipAddress,
        '-j', 'DROP'
      ]);

      // Remove from OUTPUT chain
      await this.executeCommand([
        iptablesCmd,
        '-D', this.config.customChain,
        '-d', ipAddress,
        '-j', 'DROP'
      ]);

      // Log the unblock
      await this.logRule('UNBLOCK', ipAddress, 'Unblocked by AutoSec');

      logger.info('Successfully unblocked IP address with iptables', {
        ipAddress,
        isIPv6,
      });

      return {
        success: true,
        ipAddress,
        action: 'unblocked',
        method: 'iptables',
        timestamp: new Date(),
      };
    } catch (error) {
      logger.error('Error unblocking IP with iptables:', error);
      throw error;
    }
  }

  /**
   * Create a custom firewall rule
   */
  async createRule(ruleConfig) {
    try {
      const {
        chain = 'INPUT',
        protocol,
        sourceIP,
        sourcePort,
        destinationIP,
        destinationPort,
        action = 'DROP',
        comment = 'AutoSec custom rule',
        position = null,
      } = ruleConfig;

      // Build iptables command
      const cmd = [this.config.iptablesPath];
      
      if (position) {
        cmd.push('-I', chain, position.toString());
      } else {
        cmd.push('-A', chain);
      }

      if (protocol) {
        cmd.push('-p', protocol);
      }

      if (sourceIP) {
        cmd.push('-s', sourceIP);
      }

      if (destinationIP) {
        cmd.push('-d', destinationIP);
      }

      if (sourcePort) {
        cmd.push('--sport', sourcePort.toString());
      }

      if (destinationPort) {
        cmd.push('--dport', destinationPort.toString());
      }

      cmd.push('-j', action);

      if (comment) {
        cmd.push('-m', 'comment', '--comment', `"${comment}"`);
      }

      // Create backup and execute
      await this.createBackup();
      await this.executeCommand(cmd);

      logger.info('Successfully created iptables rule', ruleConfig);

      return {
        success: true,
        rule: ruleConfig,
        action: 'created',
        timestamp: new Date(),
      };
    } catch (error) {
      logger.error('Error creating iptables rule:', error);
      await this.restoreBackup();
      throw error;
    }
  }

  /**
   * Get current iptables rules
   */
  async getRules(chain = null) {
    try {
      const cmd = [this.config.iptablesPath, '-L'];
      
      if (chain) {
        cmd.push(chain);
      }
      
      cmd.push('-n', '-v', '--line-numbers');

      const output = await this.executeCommand(cmd);
      const rules = this.parseRulesOutput(output);

      logger.info('Retrieved iptables rules', {
        chain,
        count: rules.length,
      });

      return rules;
    } catch (error) {
      logger.error('Error getting iptables rules:', error);
      throw error;
    }
  }

  /**
   * Get blocked IPs from AutoSec chain
   */
  async getBlockedIPs() {
    try {
      const rules = await this.getRules(this.config.customChain);
      
      const blockedIPs = rules
        .filter(rule => rule.target === 'DROP' || rule.target === 'REJECT')
        .map(rule => ({
          ip: rule.source || rule.destination,
          target: rule.target,
          packets: rule.packets,
          bytes: rule.bytes,
          comment: rule.comment,
        }))
        .filter(item => item.ip && item.ip !== '0.0.0.0/0');

      logger.info('Retrieved blocked IPs', {
        count: blockedIPs.length,
      });

      return blockedIPs;
    } catch (error) {
      logger.error('Error getting blocked IPs:', error);
      throw error;
    }
  }

  /**
   * Monitor iptables logs
   */
  async getFirewallLogs(filters = {}) {
    try {
      const {
        lines = 100,
        follow = false,
        grep = this.config.logPrefix,
      } = filters;

      let cmd;
      if (follow) {
        cmd = `tail -f /var/log/kern.log | grep "${grep}"`;
      } else {
        cmd = `tail -n ${lines} /var/log/kern.log | grep "${grep}"`;
      }

      const output = await this.executeShellCommand(cmd);
      const logs = this.parseLogOutput(output);

      logger.info('Retrieved firewall logs', {
        count: logs.length,
        follow,
      });

      return logs;
    } catch (error) {
      logger.error('Error getting firewall logs:', error);
      throw error;
    }
  }

  /**
   * Get connection tracking information
   */
  async getConnectionTracking() {
    try {
      const output = await this.executeShellCommand('cat /proc/net/nf_conntrack');
      const connections = this.parseConntrackOutput(output);

      logger.info('Retrieved connection tracking info', {
        count: connections.length,
      });

      return connections;
    } catch (error) {
      logger.error('Error getting connection tracking:', error);
      throw error;
    }
  }

  /**
   * Helper methods
   */
  async testCommand() {
    try {
      await this.executeCommand([this.config.iptablesPath, '--version']);
      return true;
    } catch (error) {
      throw new Error('iptables not available or insufficient permissions');
    }
  }

  async createCustomChains() {
    try {
      // Create AutoSec chain if it doesn't exist
      await this.executeCommand([
        this.config.iptablesPath,
        '-N', this.config.customChain
      ]);
    } catch (error) {
      // Chain might already exist, which is fine
      if (!error.message.includes('Chain already exists')) {
        logger.warn('Chain creation warning:', error.message);
      }
    }

    // Link custom chain to INPUT and OUTPUT
    try {
      await this.executeCommand([
        this.config.iptablesPath,
        '-I', 'INPUT',
        '-j', this.config.customChain
      ]);
    } catch (error) {
      // Rule might already exist
    }

    try {
      await this.executeCommand([
        this.config.iptablesPath,
        '-I', 'OUTPUT',
        '-j', this.config.customChain
      ]);
    } catch (error) {
      // Rule might already exist
    }
  }

  async setupLoggingChain() {
    const logChain = `${this.config.customChain}_LOG`;
    
    try {
      // Create logging chain
      await this.executeCommand([
        this.config.iptablesPath,
        '-N', logChain
      ]);

      // Add logging rule
      await this.executeCommand([
        this.config.iptablesPath,
        '-A', logChain,
        '-j', 'LOG',
        '--log-prefix', this.config.logPrefix,
        '--log-level', '4'
      ]);

      // Add drop rule after logging
      await this.executeCommand([
        this.config.iptablesPath,
        '-A', logChain,
        '-j', 'DROP'
      ]);
    } catch (error) {
      // Chain might already exist
      logger.debug('Log chain setup warning:', error.message);
    }
  }

  async createBackup() {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const backupFile = `${this.config.backupPath}-${timestamp}`;
      
      const output = await this.executeCommand([
        this.config.iptablesPath + '-save'
      ]);
      
      await fs.writeFile(backupFile, output);
      this.backupFiles.push(backupFile);
      
      // Keep only last 10 backups
      if (this.backupFiles.length > 10) {
        const oldBackup = this.backupFiles.shift();
        try {
          await fs.unlink(oldBackup);
        } catch (error) {
          logger.warn('Could not delete old backup:', error.message);
        }
      }

      logger.debug('Created iptables backup:', backupFile);
    } catch (error) {
      logger.warn('Could not create iptables backup:', error.message);
    }
  }

  async restoreBackup() {
    if (this.backupFiles.length === 0) {
      logger.warn('No backups available for restore');
      return;
    }

    try {
      const latestBackup = this.backupFiles[this.backupFiles.length - 1];
      const backupContent = await fs.readFile(latestBackup, 'utf8');
      
      await this.executeShellCommand(`echo "${backupContent}" | ${this.config.iptablesPath}-restore`);
      
      logger.info('Restored iptables from backup:', latestBackup);
    } catch (error) {
      logger.error('Error restoring iptables backup:', error);
    }
  }

  async logRule(action, ip, reason) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      action,
      ip,
      reason,
      method: 'iptables',
    };

    logger.info('iptables rule action:', logEntry);
    
    // Could also write to a specific log file if needed
    try {
      const logFile = '/var/log/autosec-iptables.log';
      await fs.appendFile(logFile, JSON.stringify(logEntry) + '\n');
    } catch (error) {
      logger.debug('Could not write to iptables log file:', error.message);
    }
  }

  parseRulesOutput(output) {
    const rules = [];
    const lines = output.split('\n');
    
    let currentChain = null;
    let inRulesSection = false;

    for (const line of lines) {
      if (line.startsWith('Chain ')) {
        currentChain = line.match(/Chain (\S+)/)[1];
        inRulesSection = false;
        continue;
      }

      if (line.startsWith('num ') || line.trim() === '') {
        inRulesSection = true;
        continue;
      }

      if (inRulesSection && line.trim()) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 6) {
          rules.push({
            chain: currentChain,
            num: parts[0],
            packets: parseInt(parts[1]) || 0,
            bytes: parseInt(parts[2]) || 0,
            target: parts[3],
            protocol: parts[4],
            opt: parts[5],
            source: parts[6] || '',
            destination: parts[7] || '',
            extra: parts.slice(8).join(' '),
            comment: this.extractComment(line),
          });
        }
      }
    }

    return rules;
  }

  parseLogOutput(output) {
    const logs = [];
    const lines = output.split('\n').filter(line => line.trim());

    for (const line of lines) {
      const logMatch = line.match(/(\w+\s+\d+\s+\d+:\d+:\d+).*?AutoSec:\s*(.*?)SRC=(\S+).*?DST=(\S+).*?PROTO=(\S+)/);
      
      if (logMatch) {
        logs.push({
          timestamp: new Date(logMatch[1]),
          message: logMatch[2] || '',
          sourceIP: logMatch[3],
          destinationIP: logMatch[4],
          protocol: logMatch[5],
          rawLine: line,
        });
      }
    }

    return logs;
  }

  parseConntrackOutput(output) {
    const connections = [];
    const lines = output.split('\n').filter(line => line.trim());

    for (const line of lines) {
      const parts = line.split(/\s+/);
      if (parts.length >= 5) {
        const connection = {
          protocol: parts[0],
          state: parts[3],
          source: this.extractIPFromConntrack(line, 'src'),
          destination: this.extractIPFromConntrack(line, 'dst'),
          sourcePort: this.extractPortFromConntrack(line, 'sport'),
          destinationPort: this.extractPortFromConntrack(line, 'dport'),
        };
        connections.push(connection);
      }
    }

    return connections;
  }

  extractComment(line) {
    const commentMatch = line.match(/\/\*\s*(.+?)\s*\*\//);
    return commentMatch ? commentMatch[1] : '';
  }

  extractIPFromConntrack(line, type) {
    const match = line.match(new RegExp(`${type}=([\\d.]+)`));
    return match ? match[1] : '';
  }

  extractPortFromConntrack(line, type) {
    const match = line.match(new RegExp(`${type}=(\\d+)`));
    return match ? parseInt(match[1]) : null;
  }

  isIPv6(ip) {
    return ip.includes(':');
  }

  async executeCommand(cmd) {
    return new Promise((resolve, reject) => {
      const fullCmd = this.config.sudo ? ['sudo', ...cmd] : cmd;
      const process = spawn(fullCmd[0], fullCmd.slice(1), { 
        timeout: this.config.timeout 
      });

      let stdout = '';
      let stderr = '';

      process.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      process.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      process.on('close', (code) => {
        if (code === 0) {
          resolve(stdout);
        } else {
          reject(new Error(`Command failed with code ${code}: ${stderr || stdout}`));
        }
      });

      process.on('error', (error) => {
        reject(error);
      });
    });
  }

  async executeShellCommand(cmd) {
    return new Promise((resolve, reject) => {
      const fullCmd = this.config.sudo ? `sudo ${cmd}` : cmd;
      
      exec(fullCmd, { timeout: this.config.timeout }, (error, stdout, stderr) => {
        if (error) {
          reject(error);
        } else {
          resolve(stdout);
        }
      });
    });
  }

  /**
   * Test connection and permissions
   */
  async testConnection() {
    try {
      await this.testCommand();
      
      // Test if we can read current rules
      const rules = await this.getRules();
      
      logger.info('Successfully connected to iptables', {
        rulesCount: rules.length,
        hasPermissions: true,
      });

      return {
        success: true,
        rulesCount: rules.length,
        hasPermissions: true,
        sudoEnabled: this.config.sudo,
        connectedAt: new Date(),
      };
    } catch (error) {
      logger.error('Failed to connect to iptables:', error);
      return {
        success: false,
        error: error.message,
        hasPermissions: false,
        testedAt: new Date(),
      };
    }
  }

  /**
   * Clean up old rules and backups
   */
  async cleanup(options = {}) {
    const {
      removeAutoSecRules = false,
      removeBackups = false,
      olderThanDays = 7,
    } = options;

    try {
      let cleanedCount = 0;

      if (removeAutoSecRules) {
        // Flush AutoSec chain
        await this.executeCommand([
          this.config.iptablesPath,
          '-F', this.config.customChain
        ]);
        cleanedCount++;
        logger.info('Flushed AutoSec iptables chain');
      }

      if (removeBackups) {
        const cutoffDate = new Date(Date.now() - (olderThanDays * 24 * 60 * 60 * 1000));
        
        for (const backupFile of this.backupFiles) {
          try {
            const stats = await fs.stat(backupFile);
            if (stats.mtime < cutoffDate) {
              await fs.unlink(backupFile);
              cleanedCount++;
            }
          } catch (error) {
            logger.debug('Error cleaning backup file:', error.message);
          }
        }
        
        // Remove cleaned files from tracking
        this.backupFiles = this.backupFiles.filter(async (file) => {
          try {
            await fs.access(file);
            return true;
          } catch {
            return false;
          }
        });
      }

      logger.info('Cleanup completed', {
        cleanedCount,
        removeAutoSecRules,
        removeBackups,
        olderThanDays,
      });

      return {
        success: true,
        cleanedCount,
        timestamp: new Date(),
      };
    } catch (error) {
      logger.error('Error during cleanup:', error);
      throw error;
    }
  }
}

module.exports = IptablesIntegration;