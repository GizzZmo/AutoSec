const NetworkBehavior = require('../models/NetworkBehavior');
const ThreatEvent = require('../models/ThreatEvent');
const Log = require('../models/Log');
const logger = require('../config/logger');
const geoIpService = require('./geoIpService');

class NetworkBehaviorAnalyzer {
  constructor() {
    this.profileWindow = 7; // days for network analysis
    this.anomalyThresholds = {
      trafficSpike: 5, // times normal traffic
      newDestinationRisk: 0.6,
      portScanThreshold: 10, // unique ports accessed
      suspiciousProtocolRatio: 0.1,
    };
  }

  /**
   * Analyze network behavior for an IP address or network identifier
   * @param {string} identifier - IP address, MAC, or subnet to analyze
   * @param {string} identifierType - Type of identifier (ip, mac, subnet, device)
   * @param {Date} endDate - End date for analysis period
   */
  async analyzeNetworkBehavior(identifier, identifierType, endDate = new Date()) {
    try {
      const startDate = new Date(endDate.getTime() - (this.profileWindow * 24 * 60 * 60 * 1000));
      
      logger.info(`Analyzing network behavior for ${identifierType} ${identifier}`, {
        identifier,
        identifierType,
        startDate,
        endDate,
      });

      // Fetch network logs for the analysis period
      const networkLogs = await this.fetchNetworkLogs(identifier, identifierType, startDate, endDate);

      if (networkLogs.length === 0) {
        logger.warn(`No network logs found for ${identifier} in the analysis period`);
        return null;
      }

      // Analyze traffic patterns
      const trafficPatterns = this.analyzeTrafficPatterns(networkLogs);
      
      // Analyze connection patterns
      const connectionPatterns = this.analyzeConnectionPatterns(networkLogs);
      
      // Get geolocation data
      const geolocation = await this.getGeolocationData(identifier, identifierType);
      
      // Analyze security events
      const securityEvents = this.analyzeSecurityEvents(networkLogs);
      
      // Calculate risk scores
      const riskScores = this.calculateNetworkRiskScores(
        trafficPatterns, 
        connectionPatterns, 
        geolocation, 
        securityEvents
      );
      
      // Detect network anomalies
      const anomalies = await this.detectNetworkAnomalies(
        identifier, 
        identifierType, 
        trafficPatterns, 
        connectionPatterns, 
        networkLogs
      );

      // ML predictions (simplified for now)
      const mlPredictions = this.generateMLPredictions(
        trafficPatterns, 
        connectionPatterns, 
        securityEvents
      );

      // Create or update network behavior profile
      const behaviorProfile = await NetworkBehavior.findOneAndUpdate(
        { identifier, identifierType, 'profilePeriod.endDate': endDate },
        {
          identifier,
          identifierType,
          profilePeriod: { startDate, endDate },
          trafficPatterns,
          connectionPatterns,
          geolocation,
          securityEvents,
          riskScores,
          anomalies,
          mlPredictions,
          lastUpdated: new Date(),
        },
        { upsert: true, new: true }
      );

      // Generate threat events for high-risk anomalies
      await this.generateNetworkThreatEvents(behaviorProfile);

      logger.info(`Network behavior analysis completed for ${identifier}`, {
        identifier,
        identifierType,
        riskScore: riskScores.overall,
        anomaliesCount: anomalies.length,
      });

      return behaviorProfile;
    } catch (error) {
      logger.error('Error analyzing network behavior:', error);
      throw error;
    }
  }

  /**
   * Fetch network logs based on identifier type
   */
  async fetchNetworkLogs(identifier, identifierType, startDate, endDate) {
    let query = {
      timestamp: { $gte: startDate, $lte: endDate },
    };

    switch (identifierType) {
      case 'ip':
        query.ip_address = identifier;
        break;
      case 'mac':
        query['metadata.macAddress'] = identifier;
        break;
      case 'subnet':
        // For subnet analysis, match IPs in the range (simplified)
        const [network, prefix] = identifier.split('/');
        query.ip_address = { $regex: `^${network.split('.').slice(0, Math.floor(prefix / 8)).join('\\.')}` };
        break;
      case 'device':
        query.device_id = identifier;
        break;
      default:
        throw new Error(`Unsupported identifier type: ${identifierType}`);
    }

    // Focus on network-related events
    query.$or = [
      { source: 'firewall' },
      { source: 'network' },
      { source: 'ids' },
      { source: 'proxy' },
      { event_type: { $regex: /(connection|traffic|network|flow)/ } },
    ];

    return await Log.find(query).sort({ timestamp: 1 });
  }

  /**
   * Analyze traffic patterns from network logs
   */
  analyzeTrafficPatterns(logs) {
    let totalInboundBytes = 0;
    let totalOutboundBytes = 0;
    let totalInboundPackets = 0;
    let totalOutboundPackets = 0;
    
    const hourlyTraffic = {};
    const protocolStats = {};
    const portStats = {};

    const startTime = new Date(logs[0].timestamp).getTime();
    const endTime = new Date(logs[logs.length - 1].timestamp).getTime();
    const durationSeconds = Math.max(1, (endTime - startTime) / 1000);

    logs.forEach(log => {
      const metadata = log.metadata || {};
      const hour = new Date(log.timestamp).getHours();

      // Traffic volume analysis
      const inboundBytes = metadata.inboundBytes || metadata.bytesReceived || 0;
      const outboundBytes = metadata.outboundBytes || metadata.bytesSent || 0;
      const inboundPackets = metadata.inboundPackets || metadata.packetsReceived || 0;
      const outboundPackets = metadata.outboundPackets || metadata.packetsSent || 0;

      totalInboundBytes += inboundBytes;
      totalOutboundBytes += outboundBytes;
      totalInboundPackets += inboundPackets;
      totalOutboundPackets += outboundPackets;

      // Hourly traffic distribution
      if (!hourlyTraffic[hour]) {
        hourlyTraffic[hour] = { hour, byteVolume: 0 };
      }
      hourlyTraffic[hour].byteVolume += inboundBytes + outboundBytes;

      // Protocol analysis
      const protocol = metadata.protocol || 'unknown';
      if (!protocolStats[protocol]) {
        protocolStats[protocol] = {
          protocol,
          bytesTransferred: 0,
          packetCount: 0,
          percentage: 0,
        };
      }
      protocolStats[protocol].bytesTransferred += inboundBytes + outboundBytes;
      protocolStats[protocol].packetCount += inboundPackets + outboundPackets;

      // Port analysis
      const srcPort = metadata.sourcePort;
      const dstPort = metadata.destinationPort;
      
      [srcPort, dstPort].forEach(port => {
        if (port && port >= 1 && port <= 65535) {
          const key = `${port}-${protocol}`;
          if (!portStats[key]) {
            portStats[key] = {
              port: parseInt(port),
              protocol,
              connections: 0,
              bytesTransferred: 0,
              direction: 'both',
            };
          }
          portStats[key].connections += 1;
          portStats[key].bytesTransferred += inboundBytes + outboundBytes;
        }
      });
    });

    // Calculate percentages for protocols
    const totalBytes = totalInboundBytes + totalOutboundBytes;
    Object.values(protocolStats).forEach(stat => {
      stat.percentage = totalBytes > 0 ? (stat.bytesTransferred / totalBytes) * 100 : 0;
    });

    return {
      totalBytes: {
        inbound: totalInboundBytes,
        outbound: totalOutboundBytes,
      },
      totalPackets: {
        inbound: totalInboundPackets,
        outbound: totalOutboundPackets,
      },
      averageBytesPerSecond: totalBytes / durationSeconds,
      peakTrafficHours: Object.values(hourlyTraffic)
        .sort((a, b) => b.byteVolume - a.byteVolume),
      protocols: Object.values(protocolStats)
        .sort((a, b) => b.bytesTransferred - a.bytesTransferred),
      ports: Object.values(portStats)
        .sort((a, b) => b.bytesTransferred - a.bytesTransferred),
    };
  }

  /**
   * Analyze connection patterns from network logs
   */
  analyzeConnectionPatterns(logs) {
    const destinations = {};
    const connectionStates = {};
    const failedConnections = { count: 0, commonReasons: {} };
    
    let totalConnections = 0;
    let totalDuration = 0;
    let connectionCount = 0;

    logs.forEach(log => {
      const metadata = log.metadata || {};
      
      // Connection analysis
      if (log.event_type === 'connection' || metadata.connectionState) {
        totalConnections += 1;
        
        const state = metadata.connectionState || 'unknown';
        connectionStates[state] = (connectionStates[state] || 0) + 1;

        // Duration analysis
        if (metadata.duration) {
          totalDuration += metadata.duration;
          connectionCount += 1;
        }

        // Destination analysis
        const destination = metadata.destinationIP || metadata.remoteHost;
        if (destination) {
          if (!destinations[destination]) {
            destinations[destination] = {
              destination,
              connections: 0,
              bytesTransferred: 0,
              ports: new Set(),
              lastConnection: log.timestamp,
            };
          }
          destinations[destination].connections += 1;
          destinations[destination].bytesTransferred += 
            (metadata.bytesTransferred || metadata.inboundBytes || 0) +
            (metadata.outboundBytes || 0);
          
          if (metadata.destinationPort) {
            destinations[destination].ports.add(metadata.destinationPort);
          }
          
          if (log.timestamp > destinations[destination].lastConnection) {
            destinations[destination].lastConnection = log.timestamp;
          }
        }

        // Failed connection analysis
        if (metadata.connectionState === 'FAILED' || 
            log.level === 'error' || 
            log.message.toLowerCase().includes('failed')) {
          failedConnections.count += 1;
          
          const reason = metadata.failureReason || 'unknown';
          failedConnections.commonReasons[reason] = 
            (failedConnections.commonReasons[reason] || 0) + 1;
        }
      }
    });

    // Convert destinations to array format
    const destinationArray = Object.values(destinations).map(dest => ({
      ...dest,
      ports: Array.from(dest.ports),
    }));

    return {
      uniqueConnections: totalConnections,
      averageConnectionDuration: connectionCount > 0 ? totalDuration / connectionCount : 0,
      commonDestinations: destinationArray
        .sort((a, b) => b.connections - a.connections),
      connectionStates: Object.entries(connectionStates)
        .map(([state, count]) => ({ state, count })),
      failedConnections: {
        count: failedConnections.count,
        commonReasons: Object.entries(failedConnections.commonReasons)
          .map(([reason, count]) => ({ reason, count }))
          .sort((a, b) => b.count - a.count),
      },
    };
  }

  /**
   * Get geolocation data for the identifier
   */
  async getGeolocationData(identifier, identifierType) {
    if (identifierType !== 'ip') {
      return {};
    }

    try {
      const geo = geoIpService.lookup(identifier);
      if (!geo) {
        return {};
      }

      return {
        country: geo.country,
        region: geo.region,
        city: geo.city,
        asn: geo.asn,
        organization: geo.organization,
        isProxy: false, // Would need additional threat intel
        isTor: false, // Would need Tor exit node list
        reputation: {
          score: 50, // Default neutral score
          sources: [],
        },
      };
    } catch (error) {
      logger.error('Error getting geolocation data:', error);
      return {};
    }
  }

  /**
   * Analyze security events from network logs
   */
  analyzeSecurityEvents(logs) {
    let deniedConnections = 0;
    let securityRuleViolations = 0;
    let malwareAttempts = 0;
    const suspiciousPatterns = {};

    logs.forEach(log => {
      // Count denied connections
      if (log.level === 'warn' || log.level === 'error' ||
          log.message.toLowerCase().includes('denied') ||
          log.message.toLowerCase().includes('blocked') ||
          log.message.toLowerCase().includes('rejected')) {
        deniedConnections += 1;
      }

      // Count security rule violations
      if (log.source === 'firewall' || log.source === 'ids' ||
          log.event_type === 'security_violation' ||
          log.message.toLowerCase().includes('violation') ||
          log.message.toLowerCase().includes('rule')) {
        securityRuleViolations += 1;
      }

      // Count malware attempts
      if (log.message.toLowerCase().includes('malware') ||
          log.message.toLowerCase().includes('virus') ||
          log.message.toLowerCase().includes('trojan') ||
          log.event_type === 'malware_detection') {
        malwareAttempts += 1;
      }

      // Detect suspicious patterns
      const patterns = this.extractSuspiciousPatterns(log);
      patterns.forEach(pattern => {
        if (!suspiciousPatterns[pattern]) {
          suspiciousPatterns[pattern] = {
            pattern,
            count: 0,
            lastOccurrence: log.timestamp,
          };
        }
        suspiciousPatterns[pattern].count += 1;
        if (log.timestamp > suspiciousPatterns[pattern].lastOccurrence) {
          suspiciousPatterns[pattern].lastOccurrence = log.timestamp;
        }
      });
    });

    return {
      deniedConnections,
      securityRuleViolations,
      malwareAttempts,
      suspiciousPatterns: Object.values(suspiciousPatterns),
    };
  }

  /**
   * Extract suspicious patterns from log entries
   */
  extractSuspiciousPatterns(log) {
    const patterns = [];
    const message = log.message.toLowerCase();
    const metadata = log.metadata || {};

    // Port scanning patterns
    if (message.includes('port scan') || message.includes('portscan')) {
      patterns.push('port_scanning');
    }

    // Brute force patterns
    if (message.includes('brute force') || message.includes('bruteforce') ||
        (message.includes('failed') && message.includes('login'))) {
      patterns.push('brute_force');
    }

    // DDoS patterns
    if (message.includes('ddos') || message.includes('flood') ||
        (metadata.packetRate && metadata.packetRate > 1000)) {
      patterns.push('ddos');
    }

    // Data exfiltration patterns
    if (metadata.bytesTransferred && metadata.bytesTransferred > 1000000) { // > 1MB
      patterns.push('large_data_transfer');
    }

    // Suspicious protocols
    if (metadata.protocol && ['tor', 'i2p', 'freenet'].includes(metadata.protocol.toLowerCase())) {
      patterns.push('anonymization_protocol');
    }

    return patterns;
  }

  /**
   * Calculate network risk scores
   */
  calculateNetworkRiskScores(trafficPatterns, connectionPatterns, geolocation, securityEvents) {
    let trafficRisk = 0;
    let connectionRisk = 0;
    let geoRisk = 0;
    let behaviorRisk = 0;

    // Traffic risk factors
    if (trafficPatterns.averageBytesPerSecond > 1000000) { // > 1MB/s
      trafficRisk += 30;
    }
    
    const suspiciousProtocols = trafficPatterns.protocols.filter(p => 
      ['tor', 'i2p', 'bittorrent'].includes(p.protocol.toLowerCase())
    );
    if (suspiciousProtocols.length > 0) {
      trafficRisk += 40;
    }

    // Connection risk factors
    if (connectionPatterns.failedConnections.count > connectionPatterns.uniqueConnections * 0.3) {
      connectionRisk += 35; // High failure rate
    }
    
    if (connectionPatterns.commonDestinations.length > 100) {
      connectionRisk += 25; // Many different destinations
    }

    // Geographic risk factors
    const highRiskCountries = ['CN', 'RU', 'KP', 'IR']; // Example high-risk countries
    if (geolocation.country && highRiskCountries.includes(geolocation.country)) {
      geoRisk += 50;
    }

    if (geolocation.isProxy || geolocation.isTor) {
      geoRisk += 60;
    }

    // Behavioral risk factors
    if (securityEvents.deniedConnections > 10) {
      behaviorRisk += 40;
    }
    
    if (securityEvents.malwareAttempts > 0) {
      behaviorRisk += 70;
    }
    
    if (securityEvents.suspiciousPatterns.length > 3) {
      behaviorRisk += 30;
    }

    // Normalize risk scores (0-100)
    trafficRisk = Math.min(100, trafficRisk);
    connectionRisk = Math.min(100, connectionRisk);
    geoRisk = Math.min(100, geoRisk);
    behaviorRisk = Math.min(100, behaviorRisk);

    const overall = Math.round((trafficRisk + connectionRisk + geoRisk + behaviorRisk) / 4);

    return {
      overall,
      trafficRisk,
      connectionRisk,
      geoRisk,
      behaviorRisk,
    };
  }

  /**
   * Detect network anomalies
   */
  async detectNetworkAnomalies(identifier, identifierType, trafficPatterns, connectionPatterns, logs) {
    const anomalies = [];

    try {
      // Get historical behavior for comparison
      const historicalProfiles = await NetworkBehavior.find({
        identifier,
        identifierType,
        'profilePeriod.endDate': { $lt: new Date() },
      }).sort({ 'profilePeriod.endDate': -1 }).limit(5);

      if (historicalProfiles.length === 0) {
        logger.info(`No historical network data for ${identifier}, skipping anomaly detection`);
        return anomalies;
      }

      // Calculate baseline from historical profiles
      const baseline = this.calculateNetworkBaseline(historicalProfiles);

      // Check for traffic spikes
      if (trafficPatterns.averageBytesPerSecond > baseline.averageBytesPerSecond * this.anomalyThresholds.trafficSpike) {
        anomalies.push({
          type: 'traffic_spike',
          severity: 'high',
          description: `Traffic volume ${Math.round(trafficPatterns.averageBytesPerSecond / baseline.averageBytesPerSecond)}x higher than normal`,
          riskScore: 80,
          evidence: {
            trafficVolume: trafficPatterns.averageBytesPerSecond,
          },
        });
      }

      // Check for new destinations
      const newDestinations = this.findNewDestinations(connectionPatterns.commonDestinations, baseline.destinations);
      if (newDestinations.length > 0) {
        anomalies.push({
          type: 'new_destination',
          severity: 'medium',
          description: `Connecting to ${newDestinations.length} new destinations`,
          riskScore: 60,
          evidence: {
            destinations: newDestinations.slice(0, 10), // Limit for storage
          },
        });
      }

      // Check for port scanning behavior
      const uniquePorts = new Set();
      trafficPatterns.ports.forEach(port => uniquePorts.add(port.port));
      if (uniquePorts.size > this.anomalyThresholds.portScanThreshold) {
        anomalies.push({
          type: 'port_scan',
          severity: 'high',
          description: `Accessed ${uniquePorts.size} different ports, possible port scanning`,
          riskScore: 85,
          evidence: {
            protocols: trafficPatterns.protocols.map(p => p.protocol),
          },
        });
      }

      logger.info(`Detected ${anomalies.length} network anomalies for ${identifier}`);
      
      return anomalies;
    } catch (error) {
      logger.error('Error detecting network anomalies:', error);
      return anomalies;
    }
  }

  /**
   * Generate ML predictions (simplified)
   */
  generateMLPredictions(trafficPatterns, connectionPatterns, securityEvents) {
    // This is a simplified ML prediction - in production, use actual ML models
    let maliciousProbability = 0;
    let classification = 'normal';

    // Simple rule-based scoring
    if (securityEvents.malwareAttempts > 0) {
      maliciousProbability += 0.8;
    }
    
    if (securityEvents.deniedConnections > connectionPatterns.uniqueConnections * 0.5) {
      maliciousProbability += 0.6;
    }
    
    if (securityEvents.suspiciousPatterns.length > 2) {
      maliciousProbability += 0.4;
    }
    
    if (connectionPatterns.uniqueConnections > 1000) {
      maliciousProbability += 0.3;
    }

    maliciousProbability = Math.min(1, maliciousProbability);

    if (maliciousProbability > 0.7) {
      classification = 'malicious';
    } else if (maliciousProbability > 0.3) {
      classification = 'suspicious';
    }

    return {
      isMalicious: {
        probability: maliciousProbability,
        confidence: 0.75, // Static confidence for demo
        lastPrediction: new Date(),
        model: 'RuleBasedClassifier-v1.0',
      },
      classification: {
        category: classification,
        subcategory: classification === 'malicious' ? 'automated-threat' : null,
        confidence: 0.75,
      },
    };
  }

  /**
   * Generate threat events for high-risk network anomalies
   */
  async generateNetworkThreatEvents(behaviorProfile) {
    const highRiskAnomalies = behaviorProfile.anomalies.filter(
      anomaly => anomaly.severity === 'high' || anomaly.severity === 'critical'
    );

    for (const anomaly of highRiskAnomalies) {
      const eventId = `nba-${behaviorProfile.identifier}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      const threatEvent = new ThreatEvent({
        eventId,
        eventType: 'behavioral_deviation',
        severity: anomaly.severity,
        title: `Network Behavioral Anomaly: ${anomaly.type.replace('_', ' ').toUpperCase()}`,
        description: anomaly.description,
        source: {
          system: 'nba',
          detector: 'NetworkBehaviorAnalyzer',
          version: '1.0.0',
        },
        entities: {
          networks: [{
            ipAddress: behaviorProfile.identifierType === 'ip' ? behaviorProfile.identifier : null,
            subnet: behaviorProfile.identifierType === 'subnet' ? behaviorProfile.identifier : null,
            asn: behaviorProfile.geolocation?.asn,
            organization: behaviorProfile.geolocation?.organization,
          }],
        },
        evidence: {
          behavior: {
            observed: {
              riskScore: behaviorProfile.riskScores.overall,
              anomalyType: anomaly.type,
            },
          },
          ...anomaly.evidence,
        },
        riskScore: anomaly.riskScore,
        status: 'new',
        tags: ['nba', 'network-anomaly', anomaly.type],
        metadata: {
          ttl: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000), // 60 days TTL
          retention: 60,
        },
      });

      try {
        await threatEvent.save();
        logger.info(`Generated threat event ${eventId} for network behavioral anomaly`, {
          identifier: behaviorProfile.identifier,
          anomalyType: anomaly.type,
          severity: anomaly.severity,
        });
      } catch (error) {
        logger.error('Error generating threat event:', error);
      }
    }
  }

  /**
   * Helper methods
   */
  calculateNetworkBaseline(historicalProfiles) {
    let totalTraffic = 0;
    const allDestinations = [];

    historicalProfiles.forEach(profile => {
      if (profile.trafficPatterns) {
        totalTraffic += profile.trafficPatterns.averageBytesPerSecond || 0;
      }
      if (profile.connectionPatterns) {
        allDestinations.push(...(profile.connectionPatterns.commonDestinations || []));
      }
    });

    return {
      averageBytesPerSecond: totalTraffic / historicalProfiles.length,
      destinations: allDestinations,
    };
  }

  findNewDestinations(current, baseline) {
    const baselineSet = new Set(baseline.map(d => d.destination));
    return current.filter(dest => !baselineSet.has(dest.destination));
  }
}

module.exports = NetworkBehaviorAnalyzer;