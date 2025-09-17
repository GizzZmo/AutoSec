/**
 * Splunk SIEM Integration
 * Provides integration with Splunk Security Information and Event Management system
 */

const axios = require('axios');
const https = require('https');
const logger = require('../config/logger');

class SplunkIntegration {
  constructor(config) {
    this.config = config;
    this.baseUrl = `${config.protocol}://${config.hostname}:${config.port}`;
    this.auth = {
      username: config.username,
      password: config.password,
    };
    this.sessionKey = null;
    this.httpClient = this.createHttpClient();
  }

  /**
   * Create HTTP client with authentication
   */
  createHttpClient() {
    return axios.create({
      baseURL: this.baseUrl,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      httpsAgent: new https.Agent({
        rejectUnauthorized: false // For self-signed certificates
      })
    });
  }

  /**
   * Initialize the integration
   */
  async initialize() {
    try {
      logger.info('Initializing Splunk integration...');
      
      // Authenticate and get session key
      await this.authenticate();
      
      // Test connectivity
      await this.healthCheck();
      
      logger.info('Splunk integration initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize Splunk integration:', error);
      throw error;
    }
  }

  /**
   * Authenticate with Splunk and get session key
   */
  async authenticate() {
    try {
      const response = await this.httpClient.post('/services/auth/login', 
        `username=${this.auth.username}&password=${this.auth.password}`,
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      // Parse XML response to get session key
      const sessionKeyMatch = response.data.match(/<sessionKey>(.*?)<\/sessionKey>/);
      if (sessionKeyMatch) {
        this.sessionKey = sessionKeyMatch[1];
        this.httpClient.defaults.headers.common['Authorization'] = `Splunk ${this.sessionKey}`;
        logger.info('Splunk authentication successful');
      } else {
        throw new Error('Failed to extract session key from Splunk response');
      }
    } catch (error) {
      logger.error('Splunk authentication failed:', error);
      throw error;
    }
  }

  /**
   * Send security event to Splunk
   */
  async sendEvent(event, options = {}) {
    try {
      await this.ensureAuthenticated();

      const splunkEvent = {
        index: options.index || this.config.index,
        sourcetype: options.sourcetype || this.config.sourcetype,
        source: options.source || 'AutoSec',
        event: JSON.stringify(event),
        time: event.timestamp ? new Date(event.timestamp).getTime() / 1000 : undefined
      };

      const response = await this.httpClient.post(
        '/services/collector/event',
        splunkEvent,
        {
          headers: {
            'Authorization': `Splunk ${this.sessionKey}`
          }
        }
      );

      logger.debug('Event sent to Splunk successfully');
      return {
        success: true,
        eventId: response.data.eventId,
        response: response.status
      };
    } catch (error) {
      logger.error('Failed to send event to Splunk:', error);
      throw error;
    }
  }

  /**
   * Send multiple events in batch to Splunk
   */
  async sendBatchEvents(events, options = {}) {
    try {
      await this.ensureAuthenticated();

      const splunkEvents = events.map(event => ({
        index: options.index || this.config.index,
        sourcetype: options.sourcetype || this.config.sourcetype,
        source: options.source || 'AutoSec',
        event: JSON.stringify(event),
        time: event.timestamp ? new Date(event.timestamp).getTime() / 1000 : undefined
      }));

      const response = await this.httpClient.post(
        '/services/collector/event',
        splunkEvents.map(e => JSON.stringify(e)).join('\n'),
        {
          headers: {
            'Authorization': `Splunk ${this.sessionKey}`,
            'Content-Type': 'application/json'
          }
        }
      );

      logger.debug(`Batch of ${events.length} events sent to Splunk successfully`);
      return {
        success: true,
        eventsCount: events.length,
        response: response.status
      };
    } catch (error) {
      logger.error('Failed to send batch events to Splunk:', error);
      throw error;
    }
  }

  /**
   * Query Splunk for events
   */
  async queryEvents(searchQuery, options = {}) {
    try {
      await this.ensureAuthenticated();

      // Create search job
      const searchResponse = await this.httpClient.post(
        '/services/search/jobs',
        `search=${encodeURIComponent(searchQuery)}&earliest_time=${options.earliest || '-24h'}&latest_time=${options.latest || 'now'}`,
        {
          headers: {
            'Authorization': `Splunk ${this.sessionKey}`,
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      // Extract search ID
      const sidMatch = searchResponse.data.match(/<sid>(.*?)<\/sid>/);
      if (!sidMatch) {
        throw new Error('Failed to create Splunk search job');
      }
      const sid = sidMatch[1];

      // Wait for search to complete
      await this.waitForSearchCompletion(sid);

      // Get search results
      const resultsResponse = await this.httpClient.get(
        `/services/search/jobs/${sid}/results`,
        {
          headers: {
            'Authorization': `Splunk ${this.sessionKey}`,
            'Accept': 'application/json'
          },
          params: {
            output_mode: 'json',
            count: options.count || 1000
          }
        }
      );

      logger.debug(`Splunk query completed, found ${resultsResponse.data.results?.length || 0} results`);
      return {
        success: true,
        results: resultsResponse.data.results || [],
        searchId: sid
      };
    } catch (error) {
      logger.error('Failed to query Splunk:', error);
      throw error;
    }
  }

  /**
   * Create alert in Splunk
   */
  async createAlert(alert, options = {}) {
    try {
      await this.ensureAuthenticated();

      const alertConfig = {
        name: alert.name || alert.title,
        search: alert.search || `index=${this.config.index} sourcetype=${this.config.sourcetype} | search ${alert.description}`,
        'dispatch.earliest_time': options.earliest || '-1h',
        'dispatch.latest_time': options.latest || 'now',
        'alert.severity': this.mapSeverity(alert.severity),
        'alert.track': '1',
        'alert.suppress': '0',
        'alert.digest_mode': '1',
        description: alert.description,
        is_scheduled: '1',
        'cron_schedule': options.cronSchedule || '*/15 * * * *' // Every 15 minutes
      };

      const formData = Object.entries(alertConfig)
        .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
        .join('&');

      const response = await this.httpClient.post(
        '/services/saved/searches',
        formData,
        {
          headers: {
            'Authorization': `Splunk ${this.sessionKey}`,
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      logger.info(`Alert '${alert.name}' created in Splunk`);
      return {
        success: true,
        alertName: alert.name,
        response: response.status
      };
    } catch (error) {
      logger.error('Failed to create alert in Splunk:', error);
      throw error;
    }
  }

  /**
   * Get dashboards from Splunk
   */
  async getDashboards() {
    try {
      await this.ensureAuthenticated();

      const response = await this.httpClient.get('/services/data/ui/views', {
        headers: {
          'Authorization': `Splunk ${this.sessionKey}`,
          'Accept': 'application/json'
        },
        params: {
          output_mode: 'json'
        }
      });

      return {
        success: true,
        dashboards: response.data.entry || []
      };
    } catch (error) {
      logger.error('Failed to get dashboards from Splunk:', error);
      throw error;
    }
  }

  /**
   * Get saved searches from Splunk
   */
  async getSavedSearches() {
    try {
      await this.ensureAuthenticated();

      const response = await this.httpClient.get('/services/saved/searches', {
        headers: {
          'Authorization': `Splunk ${this.sessionKey}`,
          'Accept': 'application/json'
        },
        params: {
          output_mode: 'json'
        }
      });

      return {
        success: true,
        savedSearches: response.data.entry || []
      };
    } catch (error) {
      logger.error('Failed to get saved searches from Splunk:', error);
      throw error;
    }
  }

  /**
   * Wait for search completion
   */
  async waitForSearchCompletion(sid, maxWaitTime = 30000) {
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWaitTime) {
      try {
        const response = await this.httpClient.get(`/services/search/jobs/${sid}`, {
          headers: {
            'Authorization': `Splunk ${this.sessionKey}`,
            'Accept': 'application/json'
          },
          params: {
            output_mode: 'json'
          }
        });

        const dispatchState = response.data.entry?.[0]?.content?.dispatchState;
        if (dispatchState === 'DONE') {
          return true;
        } else if (dispatchState === 'FAILED') {
          throw new Error('Search job failed');
        }

        await new Promise(resolve => setTimeout(resolve, 1000));
      } catch (error) {
        logger.error('Error checking search status:', error);
        throw error;
      }
    }

    throw new Error('Search job timed out');
  }

  /**
   * Map AutoSec severity to Splunk severity
   */
  mapSeverity(severity) {
    const severityMap = {
      'critical': '5',
      'high': '4',
      'medium': '3',
      'low': '2',
      'info': '1'
    };
    return severityMap[severity?.toLowerCase()] || '3';
  }

  /**
   * Ensure we have a valid session
   */
  async ensureAuthenticated() {
    if (!this.sessionKey) {
      await this.authenticate();
    }
  }

  /**
   * Perform health check
   */
  async healthCheck() {
    try {
      await this.ensureAuthenticated();
      const response = await this.httpClient.get('/services/server/info', {
        headers: {
          'Authorization': `Splunk ${this.sessionKey}`,
          'Accept': 'application/json'
        }
      });
      return response.status === 200;
    } catch (error) {
      logger.error('Splunk health check failed:', error);
      return false;
    }
  }

  /**
   * Get integration info
   */
  getInfo() {
    return {
      type: 'splunk',
      baseUrl: this.baseUrl,
      index: this.config.index,
      authenticated: !!this.sessionKey,
      status: 'connected'
    };
  }
}

module.exports = SplunkIntegration;