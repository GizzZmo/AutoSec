/**
 * Asset Discovery Service
 * Automated asset discovery and inventory management for attack surface assessment
 */

const logger = require('../config/logger');
const Asset = require('../models/Asset');
const axios = require('axios');
const { spawn } = require('child_process');
const dns = require('dns').promises;
const net = require('net');

class AssetDiscoveryService {
  constructor() {
    this.config = this.loadConfiguration();
    this.discoveryMethods = new Map();
    this.activeScanJobs = new Map();
    this.assetCache = new Map();
    this.discoveryHistory = [];
  }

  /**
   * Load asset discovery configurations
   */
  loadConfiguration() {
    return {
      networkDiscovery: {
        enabled: process.env.NETWORK_DISCOVERY_ENABLED !== 'false',
        subnets: (process.env.DISCOVERY_SUBNETS || '').split(',').filter(Boolean),
        excludeRanges: (process.env.DISCOVERY_EXCLUDE_RANGES || '').split(',').filter(Boolean),
        portScanRanges: process.env.DISCOVERY_PORT_RANGES || '22,80,443,3389,5432,3306',
        timeout: parseInt(process.env.DISCOVERY_TIMEOUT) || 5000,
        maxConcurrent: parseInt(process.env.DISCOVERY_MAX_CONCURRENT) || 50,
      },
      dnsDiscovery: {
        enabled: process.env.DNS_DISCOVERY_ENABLED !== 'false',
        domains: (process.env.DISCOVERY_DOMAINS || '').split(',').filter(Boolean),
        subdomainWordlist: process.env.SUBDOMAIN_WORDLIST || '/usr/share/wordlists/subdomains.txt',
        dnsServers: (process.env.DNS_SERVERS || '8.8.8.8,1.1.1.1').split(','),
      },
      serviceDiscovery: {
        enabled: process.env.SERVICE_DISCOVERY_ENABLED !== 'false',
        webServices: process.env.WEB_SERVICE_DISCOVERY === 'true',
        databaseServices: process.env.DATABASE_SERVICE_DISCOVERY === 'true',
        cloudServices: process.env.CLOUD_SERVICE_DISCOVERY === 'true',
      },
      cloudDiscovery: {
        aws: {
          enabled: process.env.AWS_DISCOVERY_ENABLED === 'true',
          regions: (process.env.AWS_REGIONS || 'us-east-1,us-west-2').split(','),
          accessKeyId: process.env.AWS_ACCESS_KEY_ID,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        },
        azure: {
          enabled: process.env.AZURE_DISCOVERY_ENABLED === 'true',
          subscriptions: (process.env.AZURE_SUBSCRIPTIONS || '').split(',').filter(Boolean),
          clientId: process.env.AZURE_CLIENT_ID,
          clientSecret: process.env.AZURE_CLIENT_SECRET,
          tenantId: process.env.AZURE_TENANT_ID,
        },
        gcp: {
          enabled: process.env.GCP_DISCOVERY_ENABLED === 'true',
          projects: (process.env.GCP_PROJECTS || '').split(',').filter(Boolean),
          serviceAccountKey: process.env.GCP_SERVICE_ACCOUNT_KEY,
        },
      },
      scheduling: {
        interval: parseInt(process.env.DISCOVERY_INTERVAL) || 24, // hours
        fullScanInterval: parseInt(process.env.FULL_SCAN_INTERVAL) || 168, // hours (weekly)
      },
    };
  }

  /**
   * Initialize asset discovery service
   */
  async initialize() {
    try {
      logger.info('Initializing Asset Discovery Service...');

      // Register discovery methods
      this.registerDiscoveryMethods();

      // Start scheduled discovery
      this.startScheduledDiscovery();

      // Perform initial discovery
      if (process.env.INITIAL_DISCOVERY === 'true') {
        await this.performFullDiscovery();
      }

      logger.info('Asset Discovery Service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize Asset Discovery Service:', error);
      throw error;
    }
  }

  /**
   * Perform full asset discovery
   */
  async performFullDiscovery(options = {}) {
    const discoveryId = `discovery-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
    
    try {
      logger.info(`Starting full asset discovery: ${discoveryId}`);

      const discoveryJob = {
        id: discoveryId,
        startTime: new Date(),
        status: 'running',
        methods: [],
        assetsFound: 0,
        assetsUpdated: 0,
        errors: [],
      };

      this.activeScanJobs.set(discoveryId, discoveryJob);

      const discoveredAssets = new Map();

      // Network discovery
      if (this.config.networkDiscovery.enabled) {
        logger.info('Starting network discovery...');
        const networkAssets = await this.performNetworkDiscovery(discoveryJob);
        this.mergeAssets(discoveredAssets, networkAssets);
        discoveryJob.methods.push('network');
      }

      // DNS discovery
      if (this.config.dnsDiscovery.enabled) {
        logger.info('Starting DNS discovery...');
        const dnsAssets = await this.performDNSDiscovery(discoveryJob);
        this.mergeAssets(discoveredAssets, dnsAssets);
        discoveryJob.methods.push('dns');
      }

      // Service discovery
      if (this.config.serviceDiscovery.enabled) {
        logger.info('Starting service discovery...');
        const serviceAssets = await this.performServiceDiscovery(discoveredAssets, discoveryJob);
        this.mergeAssets(discoveredAssets, serviceAssets);
        discoveryJob.methods.push('service');
      }

      // Cloud discovery
      if (this.config.cloudDiscovery.aws.enabled || 
          this.config.cloudDiscovery.azure.enabled || 
          this.config.cloudDiscovery.gcp.enabled) {
        logger.info('Starting cloud discovery...');
        const cloudAssets = await this.performCloudDiscovery(discoveryJob);
        this.mergeAssets(discoveredAssets, cloudAssets);
        discoveryJob.methods.push('cloud');
      }

      // Store discovered assets
      await this.storeDiscoveredAssets(discoveredAssets, discoveryJob);

      discoveryJob.status = 'completed';
      discoveryJob.endTime = new Date();
      discoveryJob.duration = discoveryJob.endTime - discoveryJob.startTime;

      this.discoveryHistory.push({
        ...discoveryJob,
        timestamp: discoveryJob.startTime,
      });

      logger.info(`Asset discovery completed: ${discoveryId} - Found ${discoveryJob.assetsFound} assets`);
      
      return discoveryJob;
    } catch (error) {
      logger.error(`Asset discovery failed: ${discoveryId}`, error);
      
      const job = this.activeScanJobs.get(discoveryId);
      if (job) {
        job.status = 'failed';
        job.endTime = new Date();
        job.error = error.message;
      }
      
      throw error;
    } finally {
      // Clean up after 1 hour
      setTimeout(() => {
        this.activeScanJobs.delete(discoveryId);
      }, 60 * 60 * 1000);
    }
  }

  /**
   * Perform network discovery
   */
  async performNetworkDiscovery(discoveryJob) {
    const assets = new Map();
    const subnets = this.config.networkDiscovery.subnets;

    if (subnets.length === 0) {
      logger.warn('No subnets configured for network discovery');
      return assets;
    }

    for (const subnet of subnets) {
      try {
        logger.debug(`Scanning subnet: ${subnet}`);
        const subnetAssets = await this.scanSubnet(subnet);
        
        for (const [ip, asset] of subnetAssets) {
          assets.set(ip, asset);
        }
      } catch (error) {
        logger.error(`Failed to scan subnet ${subnet}:`, error);
        discoveryJob.errors.push({ subnet, error: error.message });
      }
    }

    return assets;
  }

  /**
   * Scan subnet for active hosts
   */
  async scanSubnet(subnet) {
    const assets = new Map();
    const [network, cidr] = subnet.split('/');
    const maskBits = parseInt(cidr);
    
    if (maskBits < 16 || maskBits > 30) {
      throw new Error(`Subnet ${subnet} is too large or invalid`);
    }

    const ipRange = this.generateIPRange(network, maskBits);
    const chunks = this.chunkArray(ipRange, this.config.networkDiscovery.maxConcurrent);

    for (const chunk of chunks) {
      const promises = chunk.map(ip => this.scanHost(ip));
      const results = await Promise.allSettled(promises);

      for (let i = 0; i < results.length; i++) {
        const result = results[i];
        const ip = chunk[i];

        if (result.status === 'fulfilled' && result.value) {
          assets.set(ip, result.value);
        }
      }
    }

    return assets;
  }

  /**
   * Scan individual host
   */
  async scanHost(ip) {
    try {
      // Basic ping check
      const isAlive = await this.pingHost(ip);
      if (!isAlive) return null;

      const asset = {
        type: 'host',
        ipAddress: ip,
        hostname: null,
        operatingSystem: null,
        services: [],
        ports: [],
        lastSeen: new Date(),
        discoveryMethod: 'network_scan',
        metadata: {},
      };

      // Reverse DNS lookup
      try {
        const hostnames = await dns.reverse(ip);
        if (hostnames.length > 0) {
          asset.hostname = hostnames[0];
        }
      } catch (error) {
        // Ignore DNS resolution errors
      }

      // Port scanning
      const openPorts = await this.scanPorts(ip);
      asset.ports = openPorts;

      // Service detection
      for (const port of openPorts) {
        const service = await this.detectService(ip, port);
        if (service) {
          asset.services.push(service);
        }
      }

      // OS detection (basic)
      asset.operatingSystem = await this.detectOperatingSystem(ip, openPorts);

      return asset;
    } catch (error) {
      logger.debug(`Failed to scan host ${ip}:`, error);
      return null;
    }
  }

  /**
   * Ping host to check if it's alive
   */
  async pingHost(ip) {
    return new Promise((resolve) => {
      const ping = spawn('ping', ['-c', '1', '-W', '2', ip]);
      
      ping.on('close', (code) => {
        resolve(code === 0);
      });

      // Timeout after 5 seconds
      setTimeout(() => {
        ping.kill();
        resolve(false);
      }, 5000);
    });
  }

  /**
   * Scan ports on a host
   */
  async scanPorts(ip) {
    const ports = this.config.networkDiscovery.portScanRanges.split(',').map(p => parseInt(p.trim()));
    const openPorts = [];
    const timeout = this.config.networkDiscovery.timeout;

    const scanPromises = ports.map(port => 
      this.checkPort(ip, port, timeout).then(isOpen => isOpen ? port : null)
    );

    const results = await Promise.allSettled(scanPromises);
    
    for (const result of results) {
      if (result.status === 'fulfilled' && result.value !== null) {
        openPorts.push(result.value);
      }
    }

    return openPorts.sort((a, b) => a - b);
  }

  /**
   * Check if a specific port is open
   */
  async checkPort(ip, port, timeout) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      
      socket.setTimeout(timeout);
      
      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });

      socket.on('error', () => {
        resolve(false);
      });

      socket.connect(port, ip);
    });
  }

  /**
   * Detect service running on a port
   */
  async detectService(ip, port) {
    const serviceMap = {
      22: 'SSH',
      23: 'Telnet',
      25: 'SMTP',
      53: 'DNS',
      80: 'HTTP',
      110: 'POP3',
      143: 'IMAP',
      443: 'HTTPS',
      993: 'IMAPS',
      995: 'POP3S',
      3306: 'MySQL',
      3389: 'RDP',
      5432: 'PostgreSQL',
      5900: 'VNC',
      6379: 'Redis',
      27017: 'MongoDB',
    };

    const serviceName = serviceMap[port] || 'Unknown';
    
    // Try to get banner/version info
    let banner = null;
    let version = null;

    try {
      if (port === 80) {
        banner = await this.getHTTPBanner(ip, port);
      } else if (port === 443) {
        banner = await this.getHTTPSBanner(ip, port);
      } else {
        banner = await this.getTCPBanner(ip, port);
      }
    } catch (error) {
      // Ignore banner grab errors
    }

    return {
      port,
      protocol: 'tcp',
      service: serviceName,
      banner,
      version,
      state: 'open',
    };
  }

  /**
   * Get HTTP banner
   */
  async getHTTPBanner(ip, port) {
    try {
      const response = await axios.get(`http://${ip}:${port}`, {
        timeout: 3000,
        maxRedirects: 0,
        validateStatus: () => true,
      });
      
      return {
        server: response.headers.server,
        statusCode: response.status,
        title: this.extractTitle(response.data),
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Get HTTPS banner
   */
  async getHTTPSBanner(ip, port) {
    try {
      const response = await axios.get(`https://${ip}:${port}`, {
        timeout: 3000,
        maxRedirects: 0,
        validateStatus: () => true,
        httpsAgent: new (require('https').Agent)({
          rejectUnauthorized: false
        })
      });
      
      return {
        server: response.headers.server,
        statusCode: response.status,
        title: this.extractTitle(response.data),
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Get TCP banner
   */
  async getTCPBanner(ip, port) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let banner = '';
      
      socket.setTimeout(3000);
      
      socket.on('connect', () => {
        // Send a simple probe
        socket.write('\r\n');
      });

      socket.on('data', (data) => {
        banner += data.toString();
        if (banner.length > 512) {
          socket.destroy();
          resolve(banner.substring(0, 512));
        }
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve(banner || null);
      });

      socket.on('error', () => {
        resolve(null);
      });

      socket.connect(port, ip);
      
      // Close after 3 seconds if no data
      setTimeout(() => {
        socket.destroy();
        resolve(banner || null);
      }, 3000);
    });
  }

  /**
   * Detect operating system
   */
  async detectOperatingSystem(ip, openPorts) {
    // Simple OS detection based on open ports
    if (openPorts.includes(3389)) {
      return 'Windows';
    } else if (openPorts.includes(22)) {
      return 'Linux/Unix';
    } else if (openPorts.includes(80) || openPorts.includes(443)) {
      return 'Web Server';
    }
    return 'Unknown';
  }

  /**
   * Perform DNS discovery
   */
  async performDNSDiscovery(discoveryJob) {
    const assets = new Map();
    const domains = this.config.dnsDiscovery.domains;

    for (const domain of domains) {
      try {
        logger.debug(`Performing DNS discovery for domain: ${domain}`);
        
        // Subdomain enumeration
        const subdomains = await this.enumerateSubdomains(domain);
        
        for (const subdomain of subdomains) {
          try {
            const addresses = await dns.resolve4(subdomain);
            
            for (const ip of addresses) {
              const asset = {
                type: 'domain',
                hostname: subdomain,
                ipAddress: ip,
                domain: domain,
                lastSeen: new Date(),
                discoveryMethod: 'dns_enumeration',
                metadata: {
                  dnsRecords: await this.getDNSRecords(subdomain),
                },
              };
              
              assets.set(subdomain, asset);
            }
          } catch (error) {
            // Ignore DNS resolution errors for individual subdomains
          }
        }
      } catch (error) {
        logger.error(`Failed DNS discovery for domain ${domain}:`, error);
        discoveryJob.errors.push({ domain, error: error.message });
      }
    }

    return assets;
  }

  /**
   * Enumerate subdomains
   */
  async enumerateSubdomains(domain) {
    const subdomains = new Set();
    
    // Common subdomains
    const commonSubs = ['www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev', 'staging', 'prod'];
    
    for (const sub of commonSubs) {
      try {
        await dns.resolve4(`${sub}.${domain}`);
        subdomains.add(`${sub}.${domain}`);
      } catch (error) {
        // Subdomain doesn't exist
      }
    }

    // Add the base domain
    subdomains.add(domain);

    return Array.from(subdomains);
  }

  /**
   * Get DNS records for a domain
   */
  async getDNSRecords(domain) {
    const records = {};
    
    try {
      records.a = await dns.resolve4(domain);
    } catch (error) {}
    
    try {
      records.aaaa = await dns.resolve6(domain);
    } catch (error) {}
    
    try {
      records.mx = await dns.resolveMx(domain);
    } catch (error) {}
    
    try {
      records.txt = await dns.resolveTxt(domain);
    } catch (error) {}
    
    try {
      records.cname = await dns.resolveCname(domain);
    } catch (error) {}

    return records;
  }

  /**
   * Perform service discovery
   */
  async performServiceDiscovery(existingAssets, discoveryJob) {
    const assets = new Map();

    // Enhance existing assets with service information
    for (const [key, asset] of existingAssets) {
      if (asset.ipAddress && asset.services) {
        for (const service of asset.services) {
          if (service.service === 'HTTP' || service.service === 'HTTPS') {
            const webInfo = await this.discoverWebService(asset.ipAddress, service.port);
            if (webInfo) {
              service.webInfo = webInfo;
            }
          } else if (['MySQL', 'PostgreSQL', 'MongoDB'].includes(service.service)) {
            const dbInfo = await this.discoverDatabaseService(asset.ipAddress, service.port, service.service);
            if (dbInfo) {
              service.databaseInfo = dbInfo;
            }
          }
        }
      }
    }

    return assets;
  }

  /**
   * Discover web service details
   */
  async discoverWebService(ip, port) {
    try {
      const protocol = port === 443 ? 'https' : 'http';
      const response = await axios.get(`${protocol}://${ip}:${port}`, {
        timeout: 5000,
        maxRedirects: 5,
        validateStatus: () => true,
        httpsAgent: protocol === 'https' ? new (require('https').Agent)({
          rejectUnauthorized: false
        }) : undefined,
      });

      return {
        statusCode: response.status,
        server: response.headers.server,
        contentType: response.headers['content-type'],
        title: this.extractTitle(response.data),
        technologies: this.detectTechnologies(response),
        size: response.data?.length || 0,
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Extract title from HTML
   */
  extractTitle(html) {
    if (typeof html !== 'string') return null;
    const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    return match ? match[1].trim() : null;
  }

  /**
   * Detect web technologies
   */
  detectTechnologies(response) {
    const technologies = [];
    const headers = response.headers;
    const body = response.data || '';

    // Server header
    if (headers.server) {
      if (headers.server.includes('Apache')) technologies.push('Apache');
      if (headers.server.includes('nginx')) technologies.push('Nginx');
      if (headers.server.includes('IIS')) technologies.push('IIS');
    }

    // X-Powered-By header
    if (headers['x-powered-by']) {
      technologies.push(headers['x-powered-by']);
    }

    // Content analysis
    if (body.includes('wp-content')) technologies.push('WordPress');
    if (body.includes('Drupal')) technologies.push('Drupal');
    if (body.includes('joomla')) technologies.push('Joomla');

    return technologies;
  }

  /**
   * Discover database service details
   */
  async discoverDatabaseService(ip, port, serviceType) {
    // Placeholder - in production, implement proper database fingerprinting
    return {
      type: serviceType,
      accessible: false, // Don't attempt to connect
      fingerprint: null,
    };
  }

  /**
   * Perform cloud discovery
   */
  async performCloudDiscovery(discoveryJob) {
    const assets = new Map();

    // AWS discovery
    if (this.config.cloudDiscovery.aws.enabled) {
      try {
        const awsAssets = await this.discoverAWSAssets();
        this.mergeAssets(assets, awsAssets);
      } catch (error) {
        logger.error('AWS discovery failed:', error);
        discoveryJob.errors.push({ provider: 'aws', error: error.message });
      }
    }

    // Placeholder for Azure and GCP discovery
    return assets;
  }

  /**
   * Discover AWS assets (placeholder)
   */
  async discoverAWSAssets() {
    // Placeholder - implement AWS SDK integration
    logger.info('AWS asset discovery not implemented (placeholder)');
    return new Map();
  }

  /**
   * Store discovered assets in database
   */
  async storeDiscoveredAssets(discoveredAssets, discoveryJob) {
    let newAssets = 0;
    let updatedAssets = 0;

    for (const [key, assetData] of discoveredAssets) {
      try {
        // Find existing asset by IP or hostname
        const query = assetData.ipAddress ? 
          { ipAddress: assetData.ipAddress } : 
          { hostname: assetData.hostname };

        const existingAsset = await Asset.findOne(query);

        if (existingAsset) {
          // Update existing asset
          Object.assign(existingAsset, assetData);
          existingAsset.lastSeen = new Date();
          await existingAsset.save();
          updatedAssets++;
        } else {
          // Create new asset
          const asset = new Asset(assetData);
          await asset.save();
          newAssets++;
        }
      } catch (error) {
        logger.error(`Failed to store asset ${key}:`, error);
        discoveryJob.errors.push({ asset: key, error: error.message });
      }
    }

    discoveryJob.assetsFound = newAssets;
    discoveryJob.assetsUpdated = updatedAssets;

    logger.info(`Stored ${newAssets} new assets and updated ${updatedAssets} existing assets`);
  }

  /**
   * Utility methods
   */
  generateIPRange(network, maskBits) {
    const ip = network.split('.').map(Number);
    const hostBits = 32 - maskBits;
    const numHosts = Math.pow(2, hostBits) - 2; // Exclude network and broadcast
    
    const baseIP = (ip[0] << 24) + (ip[1] << 16) + (ip[2] << 8) + ip[3];
    const networkAddress = baseIP & (0xFFFFFFFF << hostBits);
    
    const ips = [];
    for (let i = 1; i <= numHosts && i <= 1000; i++) { // Limit to 1000 IPs
      const hostIP = networkAddress + i;
      const ipStr = [
        (hostIP >>> 24) & 0xFF,
        (hostIP >>> 16) & 0xFF,
        (hostIP >>> 8) & 0xFF,
        hostIP & 0xFF
      ].join('.');
      ips.push(ipStr);
    }
    
    return ips;
  }

  chunkArray(array, chunkSize) {
    const chunks = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }

  mergeAssets(target, source) {
    for (const [key, asset] of source) {
      target.set(key, asset);
    }
  }

  registerDiscoveryMethods() {
    logger.info('Asset discovery methods registered');
  }

  startScheduledDiscovery() {
    const interval = this.config.scheduling.interval * 60 * 60 * 1000; // Convert hours to ms
    
    setInterval(async () => {
      try {
        logger.info('Starting scheduled asset discovery');
        await this.performFullDiscovery();
      } catch (error) {
        logger.error('Scheduled asset discovery failed:', error);
      }
    }, interval);

    logger.info(`Scheduled asset discovery every ${this.config.scheduling.interval} hours`);
  }

  /**
   * Get discovery status
   */
  getDiscoveryStatus() {
    return {
      activeJobs: Array.from(this.activeScanJobs.values()),
      recentHistory: this.discoveryHistory.slice(-10),
      configuration: this.config,
    };
  }

  /**
   * Get asset inventory
   */
  async getAssetInventory(filters = {}) {
    try {
      const query = {};
      
      if (filters.type) {
        query.type = filters.type;
      }
      
      if (filters.lastSeenAfter) {
        query.lastSeen = { $gte: new Date(filters.lastSeenAfter) };
      }

      const assets = await Asset.find(query)
        .sort({ lastSeen: -1 })
        .limit(filters.limit || 1000);

      return {
        total: assets.length,
        assets: assets,
        filters: filters,
      };
    } catch (error) {
      logger.error('Failed to get asset inventory:', error);
      throw error;
    }
  }
}

module.exports = new AssetDiscoveryService();