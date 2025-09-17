/**
 * Enhanced Threat Intelligence Service
 * Provides comprehensive threat intelligence integration with multiple feeds
 */

const axios = require('axios');
const https = require('https');
const logger = require('../config/logger');
const IOC = require('../models/IOC');
const ThreatEvent = require('../models/ThreatEvent');

class ThreatIntelligenceService {
  constructor() {
    this.config = this.loadConfiguration();
    this.integrations = new Map();
    this.lastUpdate = null;
    this.indicators = new Map();
    this.feeds = new Map();
  }

  /**
   * Load threat intelligence configurations
   */
  loadConfiguration() {
    return {
      misp: {
        enabled: process.env.MISP_ENABLED === 'true',
        url: process.env.MISP_URL,
        apiKey: process.env.MISP_API_KEY,
        verifyCert: process.env.MISP_VERIFY_CERT !== 'false',
        tags: (process.env.MISP_TAGS || '').split(',').filter(Boolean),
      },
      taxii: {
        enabled: process.env.TAXII_ENABLED === 'true',
        discoveryUrl: process.env.TAXII_DISCOVERY_URL,
        username: process.env.TAXII_USERNAME,
        password: process.env.TAXII_PASSWORD,
        collections: (process.env.TAXII_COLLECTIONS || '').split(',').filter(Boolean),
      },
      otx: {
        enabled: process.env.OTX_ENABLED === 'true',
        apiKey: process.env.OTX_API_KEY,
        url: process.env.OTX_URL || 'https://otx.alienvault.com/api/v1',
      },
      customFeeds: {
        enabled: process.env.CUSTOM_FEEDS_ENABLED === 'true',
        urls: (process.env.CUSTOM_FEED_URLS || '').split(',').filter(Boolean),
      },
    };
  }

  /**
   * Initialize threat intelligence integrations
   */
  async initialize() {
    try {
      logger.info('Initializing threat intelligence integrations...');

      if (this.config.misp.enabled) {
        await this.initializeMISP();
      }

      if (this.config.taxii.enabled) {
        await this.initializeTAXII();
      }

      if (this.config.otx.enabled) {
        await this.initializeOTX();
      }

      if (this.config.customFeeds.enabled) {
        await this.initializeCustomFeeds();
      }

      logger.info('Threat intelligence integrations initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize threat intelligence integrations:', error);
      throw error;
    }
  }

  /**
   * Initialize MISP integration
   */
  async initializeMISP() {
    try {
      const httpClient = axios.create({
        baseURL: this.config.misp.url,
        headers: {
          'Authorization': this.config.misp.apiKey,
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
        httpsAgent: new https.Agent({
          rejectUnauthorized: this.config.misp.verifyCert
        })
      });

      this.integrations.set('misp', {
        type: 'misp',
        client: httpClient,
        lastSync: null,
      });

      logger.info('MISP integration initialized');
    } catch (error) {
      logger.error('Failed to initialize MISP integration:', error);
      throw error;
    }
  }

  /**
   * Initialize TAXII integration
   */
  async initializeTAXII() {
    try {
      const httpClient = axios.create({
        baseURL: this.config.taxii.discoveryUrl,
        auth: {
          username: this.config.taxii.username,
          password: this.config.taxii.password,
        },
        headers: {
          'Accept': 'application/taxii+json;version=2.1',
          'Content-Type': 'application/taxii+json;version=2.1',
        }
      });

      this.integrations.set('taxii', {
        type: 'taxii',
        client: httpClient,
        lastSync: null,
      });

      logger.info('TAXII integration initialized');
    } catch (error) {
      logger.error('Failed to initialize TAXII integration:', error);
      throw error;
    }
  }

  /**
   * Initialize AlienVault OTX integration
   */
  async initializeOTX() {
    try {
      const httpClient = axios.create({
        baseURL: this.config.otx.url,
        headers: {
          'X-OTX-API-KEY': this.config.otx.apiKey,
          'Accept': 'application/json',
        }
      });

      this.integrations.set('otx', {
        type: 'otx',
        client: httpClient,
        lastSync: null,
      });

      logger.info('AlienVault OTX integration initialized');
    } catch (error) {
      logger.error('Failed to initialize OTX integration:', error);
      throw error;
    }
  }

  /**
   * Initialize custom threat feeds
   */
  async initializeCustomFeeds() {
    try {
      for (const feedUrl of this.config.customFeeds.urls) {
        const httpClient = axios.create({
          baseURL: feedUrl,
          timeout: 30000,
        });

        this.integrations.set(`custom-${feedUrl}`, {
          type: 'custom',
          client: httpClient,
          url: feedUrl,
          lastSync: null,
        });
      }

      logger.info('Custom threat feeds initialized');
    } catch (error) {
      logger.error('Failed to initialize custom feeds:', error);
      throw error;
    }
  }

  /**
   * Fetch threat intelligence from all configured sources
   */
  async fetchThreatFeeds() {
    logger.info('[Threat Intelligence Service] Fetching threat feeds...');
    
    const results = {
      maliciousIps: [],
      maliciousDomains: [],
      maliciousHashes: [],
      campaigns: [],
      signatures: [],
      totalIndicators: 0,
      sources: [],
      errors: []
    };

    try {
      const fetchPromises = [];

      for (const [name, integration] of this.integrations) {
        fetchPromises.push(this.fetchFromSource(name, integration, results));
      }

      await Promise.allSettled(fetchPromises);

      // Remove duplicates and update database
      await this.processAndStoreIndicators(results);

      this.lastUpdate = Date.now();
      logger.info(`[Threat Intelligence Service] Updated ${results.totalIndicators} indicators from ${results.sources.length} sources`);

      return results;
    } catch (error) {
      logger.error('Error fetching threat feeds:', error);
      throw error;
    }
  }

  /**
   * Fetch indicators from a specific source
   */
  async fetchFromSource(name, integration, results) {
    try {
      logger.debug(`Fetching indicators from ${name}...`);

      switch (integration.type) {
        case 'misp':
          await this.fetchFromMISP(integration, results);
          break;
        case 'taxii':
          await this.fetchFromTAXII(integration, results);
          break;
        case 'otx':
          await this.fetchFromOTX(integration, results);
          break;
        case 'custom':
          await this.fetchFromCustomFeed(integration, results);
          break;
      }

      integration.lastSync = Date.now();
      results.sources.push(name);
    } catch (error) {
      logger.error(`Error fetching from ${name}:`, error);
      results.errors.push({ source: name, error: error.message });
    }
  }

  /**
   * Fetch indicators from MISP
   */
  async fetchFromMISP(integration, results) {
    const response = await integration.client.get('/attributes/restSearch', {
      params: {
        type: ['ip-src', 'ip-dst', 'domain', 'hostname', 'md5', 'sha1', 'sha256'],
        tags: this.config.misp.tags,
        last: '7d', // Last 7 days
        limit: 1000,
        to_ids: 1, // Only IOCs marked for detection
      }
    });

    const attributes = response.data.response.Attribute || [];
    
    for (const attr of attributes) {
      const indicator = {
        type: attr.type,
        value: attr.value,
        source: 'misp',
        confidence: this.calculateConfidence(attr),
        tags: attr.Tag ? attr.Tag.map(t => t.name) : [],
        firstSeen: new Date(attr.timestamp * 1000),
        lastSeen: new Date(),
        context: {
          eventId: attr.event_id,
          category: attr.category,
          comment: attr.comment,
        }
      };

      this.categorizeIndicator(indicator, results);
    }
  }

  /**
   * Fetch indicators from TAXII
   */
  async fetchFromTAXII(integration, results) {
    // Get discovery information
    const discoveryResponse = await integration.client.get('/');
    const apiRoots = discoveryResponse.data.api_roots || [];

    for (const apiRoot of apiRoots.slice(0, 1)) { // Limit to first API root
      try {
        // Get collections
        const collectionsResponse = await integration.client.get(`${apiRoot}/collections/`);
        const collections = collectionsResponse.data.collections || [];

        for (const collection of collections) {
          if (this.config.taxii.collections.length === 0 || 
              this.config.taxii.collections.includes(collection.id)) {
            
            // Get objects from collection
            const objectsResponse = await integration.client.get(
              `${apiRoot}/collections/${collection.id}/objects/`,
              {
                params: {
                  added_after: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(), // Last 7 days
                  limit: 1000,
                }
              }
            );

            const objects = objectsResponse.data.objects || [];
            this.parseSTIXObjects(objects, results);
          }
        }
      } catch (error) {
        logger.error(`Error processing TAXII API root ${apiRoot}:`, error);
      }
    }
  }

  /**
   * Fetch indicators from AlienVault OTX
   */
  async fetchFromOTX(integration, results) {
    const response = await integration.client.get('/indicators/export', {
      params: {
        types: ['IPv4', 'IPv6', 'domain', 'hostname', 'FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256'],
        modified_since: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
      }
    });

    const indicators = response.data.results || [];
    
    for (const otxIndicator of indicators) {
      const indicator = {
        type: this.mapOTXType(otxIndicator.type),
        value: otxIndicator.indicator,
        source: 'otx',
        confidence: otxIndicator.pulse_info?.count ? Math.min(10, otxIndicator.pulse_info.count) / 10 : 0.5,
        tags: otxIndicator.pulse_info?.pulses?.map(p => p.name) || [],
        firstSeen: new Date(otxIndicator.created),
        lastSeen: new Date(otxIndicator.modified),
        context: {
          pulseInfo: otxIndicator.pulse_info,
          description: otxIndicator.description,
        }
      };

      this.categorizeIndicator(indicator, results);
    }
  }

  /**
   * Fetch indicators from custom feed
   */
  async fetchFromCustomFeed(integration, results) {
    const response = await integration.client.get('');
    const content = response.data;

    // Parse based on content type
    if (typeof content === 'string') {
      // Assume it's a text file with one indicator per line
      const lines = content.split('\n').filter(line => line.trim() && !line.startsWith('#'));
      
      for (const line of lines) {
        const value = line.trim();
        const indicator = {
          type: this.detectIndicatorType(value),
          value: value,
          source: `custom-${integration.url}`,
          confidence: 0.7, // Default confidence for custom feeds
          tags: ['custom-feed'],
          firstSeen: new Date(),
          lastSeen: new Date(),
          context: {
            feedUrl: integration.url,
          }
        };

        this.categorizeIndicator(indicator, results);
      }
    }
  }

  /**
   * Parse STIX objects and extract indicators
   */
  parseSTIXObjects(objects, results) {
    for (const obj of objects) {
      if (obj.type === 'indicator') {
        const pattern = obj.pattern;
        const indicators = this.extractIndicatorsFromSTIXPattern(pattern);
        
        for (const indicatorValue of indicators) {
          const indicator = {
            type: this.detectIndicatorType(indicatorValue),
            value: indicatorValue,
            source: 'taxii',
            confidence: obj.confidence ? obj.confidence / 100 : 0.5,
            tags: obj.labels || [],
            firstSeen: new Date(obj.created),
            lastSeen: new Date(obj.modified),
            context: {
              stixId: obj.id,
              pattern: pattern,
              description: obj.name,
            }
          };

          this.categorizeIndicator(indicator, results);
        }
      }
    }
  }

  /**
   * Extract indicators from STIX pattern
   */
  extractIndicatorsFromSTIXPattern(pattern) {
    const indicators = [];
    
    // Simple regex patterns for common indicator types
    const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const domainPattern = /\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b/g;
    const hashPattern = /\b[a-fA-F0-9]{32,64}\b/g;

    const matches = [
      ...(pattern.match(ipPattern) || []),
      ...(pattern.match(domainPattern) || []),
      ...(pattern.match(hashPattern) || [])
    ];

    return [...new Set(matches)]; // Remove duplicates
  }

  /**
   * Categorize indicator by type
   */
  categorizeIndicator(indicator, results) {
    switch (indicator.type) {
      case 'ip':
      case 'ip-src':
      case 'ip-dst':
        results.maliciousIps.push(indicator);
        break;
      case 'domain':
      case 'hostname':
        results.maliciousDomains.push(indicator);
        break;
      case 'md5':
      case 'sha1':
      case 'sha256':
      case 'hash':
        results.maliciousHashes.push(indicator);
        break;
    }
    
    results.totalIndicators++;
  }

  /**
   * Process and store indicators in database
   */
  async processAndStoreIndicators(results) {
    const allIndicators = [
      ...results.maliciousIps,
      ...results.maliciousDomains,
      ...results.maliciousHashes
    ];

    for (const indicator of allIndicators) {
      try {
        await IOC.findOneAndUpdate(
          { type: indicator.type, value: indicator.value },
          {
            $set: {
              source: indicator.source,
              confidence: indicator.confidence,
              tags: indicator.tags,
              lastSeen: indicator.lastSeen,
              context: indicator.context,
            },
            $setOnInsert: {
              firstSeen: indicator.firstSeen,
              createdAt: new Date(),
            }
          },
          { upsert: true, new: true }
        );
      } catch (error) {
        logger.error('Error storing IOC:', error);
      }
    }
  }

  /**
   * Check if an indicator matches known IOCs
   */
  async checkIOC(type, value) {
    try {
      const ioc = await IOC.findOne({ type, value });
      
      if (ioc) {
        logger.warn(`IOC match found: ${type}=${value} from ${ioc.source}`);
        
        // Create threat event for the match
        await this.createThreatEventForIOC(ioc, { type, value });
        
        return {
          match: true,
          ioc: ioc,
          confidence: ioc.confidence,
          source: ioc.source,
          tags: ioc.tags,
        };
      }

      return { match: false };
    } catch (error) {
      logger.error('Error checking IOC:', error);
      return { match: false, error: error.message };
    }
  }

  /**
   * Create threat event for IOC match
   */
  async createThreatEventForIOC(ioc, matchedIndicator) {
    try {
      const threatEvent = new ThreatEvent({
        eventId: `ioc-match-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        eventType: 'threat_intelligence_match',
        severity: this.calculateSeverityFromConfidence(ioc.confidence),
        title: `IOC Match: ${ioc.type} ${ioc.value}`,
        description: `Threat intelligence match found for ${ioc.type}: ${ioc.value} from source: ${ioc.source}`,
        source: {
          system: 'threat_intel',
          detector: 'ioc_correlation',
        },
        entities: {
          networks: ioc.type.includes('ip') ? [{ ipAddress: ioc.value }] : [],
        },
        evidence: {
          indicators: [{
            type: ioc.type,
            value: ioc.value,
            source: ioc.source,
            confidence: ioc.confidence,
          }],
        },
        riskScore: Math.round(ioc.confidence * 100),
        timestamp: new Date(),
      });

      await threatEvent.save();
      logger.info(`Created threat event for IOC match: ${ioc.value}`);
    } catch (error) {
      logger.error('Error creating threat event for IOC:', error);
    }
  }

  /**
   * Get IOC statistics
   */
  async getIOCStats() {
    try {
      const stats = await IOC.aggregate([
        {
          $group: {
            _id: '$type',
            count: { $sum: 1 },
            avgConfidence: { $avg: '$confidence' },
            sources: { $addToSet: '$source' },
          }
        }
      ]);

      const totalCount = await IOC.countDocuments();
      const recentCount = await IOC.countDocuments({
        lastSeen: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      });

      return {
        total: totalCount,
        recent24h: recentCount,
        byType: stats,
        lastUpdate: this.lastUpdate,
      };
    } catch (error) {
      logger.error('Error getting IOC stats:', error);
      return null;
    }
  }

  /**
   * Utility methods
   */
  calculateConfidence(attr) {
    let confidence = 0.5; // Default confidence
    
    if (attr.to_ids) confidence += 0.2;
    if (attr.Tag && attr.Tag.length > 0) confidence += 0.1;
    if (attr.category === 'Network activity') confidence += 0.1;
    
    return Math.min(1, confidence);
  }

  calculateSeverityFromConfidence(confidence) {
    if (confidence >= 0.8) return 'high';
    if (confidence >= 0.6) return 'medium';
    if (confidence >= 0.4) return 'low';
    return 'info';
  }

  mapOTXType(otxType) {
    const typeMap = {
      'IPv4': 'ip',
      'IPv6': 'ip',
      'domain': 'domain',
      'hostname': 'hostname',
      'FileHash-MD5': 'md5',
      'FileHash-SHA1': 'sha1',
      'FileHash-SHA256': 'sha256',
    };
    return typeMap[otxType] || 'unknown';
  }

  detectIndicatorType(value) {
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
    if (/^[a-fA-F0-9]{32}$/.test(value)) return 'md5';
    if (/^[a-fA-F0-9]{40}$/.test(value)) return 'sha1';
    if (/^[a-fA-F0-9]{64}$/.test(value)) return 'sha256';
    if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(value)) return 'domain';
    return 'unknown';
  }
}

// Create singleton instance
const threatIntelService = new ThreatIntelligenceService();

// Legacy function for backward compatibility
const fetchThreatFeeds = () => threatIntelService.fetchThreatFeeds();

module.exports = {
  threatIntelService,
  fetchThreatFeeds,
};