/**
 * Threat Hunting Service Tests
 */

const { ThreatHuntingService } = require('../src/services/threatHuntingService');

describe('ThreatHuntingService', () => {
  let service;

  beforeEach(() => {
    service = new ThreatHuntingService();
  });

  describe('Template Initialization', () => {
    test('should initialize threat hunting templates', () => {
      expect(service.huntTemplates.size).toBeGreaterThan(0);
      expect(service.huntTemplates.has('apt-detection')).toBe(true);
      expect(service.huntTemplates.has('data-exfiltration')).toBe(true);
      expect(service.huntTemplates.has('insider-threat')).toBe(true);
      expect(service.huntTemplates.has('ransomware')).toBe(true);
    });

    test('APT detection template should have correct structure', () => {
      const aptTemplate = service.huntTemplates.get('apt-detection');
      expect(aptTemplate).toBeDefined();
      expect(aptTemplate.name).toBe('APT Activity Detection');
      expect(aptTemplate.queries).toBeDefined();
      expect(Array.isArray(aptTemplate.queries)).toBe(true);
      expect(aptTemplate.queries.length).toBeGreaterThan(0);
      expect(aptTemplate.priority).toBe('high');
    });

    test('Data exfiltration template should have correct structure', () => {
      const template = service.huntTemplates.get('data-exfiltration');
      expect(template).toBeDefined();
      expect(template.name).toBe('Data Exfiltration Detection');
      expect(template.queries).toBeDefined();
      expect(Array.isArray(template.queries)).toBe(true);
      expect(template.priority).toBe('high');
    });

    test('Insider threat template should have correct structure', () => {
      const template = service.huntTemplates.get('insider-threat');
      expect(template).toBeDefined();
      expect(template.name).toBe('Insider Threat Detection');
      expect(template.queries).toBeDefined();
      expect(template.priority).toBe('medium');
    });

    test('Ransomware template should have correct structure', () => {
      const template = service.huntTemplates.get('ransomware');
      expect(template).toBeDefined();
      expect(template.name).toBe('Ransomware Activity Detection');
      expect(template.queries).toBeDefined();
      expect(template.priority).toBe('critical');
    });
  });

  describe('Time Range Parsing', () => {
    test('should parse minutes correctly', () => {
      const minutes = service.parseTimeRange('30m');
      expect(minutes).toBe(30 * 60 * 1000);
    });

    test('should parse hours correctly', () => {
      const hours = service.parseTimeRange('24h');
      expect(hours).toBe(24 * 60 * 60 * 1000);
    });

    test('should parse days correctly', () => {
      const days = service.parseTimeRange('7d');
      expect(days).toBe(7 * 24 * 60 * 60 * 1000);
    });

    test('should return default for invalid format', () => {
      const defaultTime = service.parseTimeRange('invalid');
      expect(defaultTime).toBe(24 * 60 * 60 * 1000); // Default 24 hours
    });
  });

  describe('Severity Calculation', () => {
    test('should calculate high severity for high risk scores', () => {
      const results = [
        { riskScore: 90 },
        { riskScore: 85 },
        { riskScore: 95 }
      ];
      const severity = service.calculateFindingSeverity(results);
      expect(severity).toBe('high');
    });

    test('should calculate medium severity for medium risk scores', () => {
      const results = [
        { riskScore: 65 },
        { riskScore: 70 },
        { riskScore: 60 }
      ];
      const severity = service.calculateFindingSeverity(results);
      expect(severity).toBe('medium');
    });

    test('should calculate low severity for low risk scores', () => {
      const results = [
        { riskScore: 40 },
        { riskScore: 50 },
        { riskScore: 45 }
      ];
      const severity = service.calculateFindingSeverity(results);
      expect(severity).toBe('low');
    });

    test('should return info for empty results', () => {
      const severity = service.calculateFindingSeverity([]);
      expect(severity).toBe('info');
    });
  });

  describe('Query Filter Building', () => {
    test('should build network query filter with basic pattern', () => {
      const startTime = new Date();
      const filter = service.buildNetworkQueryFilter('connection_count > 15', startTime);
      expect(filter).toBeDefined();
      expect(filter.timestamp).toBeDefined();
      expect(filter.connectionCount).toEqual({ $gt: 15 });
    });

    test('should build network query filter for external destinations', () => {
      const startTime = new Date();
      const filter = service.buildNetworkQueryFilter('external_destination', startTime);
      expect(filter).toBeDefined();
      expect(filter.$or).toBeDefined();
      expect(Array.isArray(filter.$or)).toBe(true);
    });

    test('should build behavior query filter for elevated privileges', () => {
      const startTime = new Date();
      const filter = service.buildBehaviorQueryFilter('elevated_privileges', startTime);
      expect(filter).toBeDefined();
      expect(filter['entities.users.0.privilegeLevel']).toBeDefined();
    });

    test('should build IOC query filter with type specification', () => {
      const startTime = new Date();
      const filter = service.buildIOCQueryFilter('type:ip confidence > 0.8', startTime);
      expect(filter).toBeDefined();
      expect(filter.type).toBe('ip');
      expect(filter.confidence).toEqual({ $gte: 0.8 });
    });

    test('should build threat event query filter with severity', () => {
      const startTime = new Date();
      const filter = service.buildThreatEventQueryFilter('severity:high riskScore > 80', startTime);
      expect(filter).toBeDefined();
      expect(filter.severity).toBe('high');
      expect(filter.riskScore).toEqual({ $gte: 80 });
    });
  });

  describe('Service State', () => {
    test('should initialize with empty active hunts', () => {
      expect(service.activeHunts.size).toBe(0);
    });

    test('should initialize with empty custom queries', () => {
      expect(service.customQueries.size).toBe(0);
    });

    test('should have hunt templates map', () => {
      expect(service.huntTemplates).toBeInstanceOf(Map);
    });
  });
});
