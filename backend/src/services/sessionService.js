const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const redis = require('redis');
const logger = require('../config/logger');

class SessionService {
  constructor() {
    this.redisClient = this.initializeRedis();
    this.sessionTimeout = 24 * 60 * 60 * 1000; // 24 hours
    this.maxSessionsPerUser = 5;
  }

  /**
   * Initialize Redis client for session storage
   */
  initializeRedis() {
    const client = redis.createClient({
      host: process.env.REDIS_HOST || 'localhost',
      port: process.env.REDIS_PORT || 6379,
      password: process.env.REDIS_PASSWORD,
    });

    client.on('error', (err) => {
      logger.error('Redis connection error:', err);
    });

    return client;
  }

  /**
   * Create a new session for user
   * @param {string} userId - User ID
   * @param {Object} sessionData - Session metadata
   * @returns {Promise<Object>} Session details
   */
  async createSession(userId, sessionData = {}) {
    try {
      const sessionId = crypto.randomUUID();
      const session = {
        id: sessionId,
        userId,
        createdAt: new Date().toISOString(),
        lastActivity: new Date().toISOString(),
        ipAddress: sessionData.ipAddress || null,
        userAgent: sessionData.userAgent || null,
        deviceFingerprint: sessionData.deviceFingerprint || null,
        isActive: true,
        mfaVerified: sessionData.mfaVerified || false,
      };

      // Store session in Redis
      const sessionKey = `session:${sessionId}`;
      await this.redisClient.setex(
        sessionKey,
        this.sessionTimeout / 1000,
        JSON.stringify(session)
      );

      // Add session to user's active sessions
      await this.addToUserSessions(userId, sessionId);

      // Enforce session limit
      await this.enforceSessionLimit(userId);

      logger.info(`Session created for user: ${userId}`, {
        sessionId,
        ipAddress: session.ipAddress,
      });

      return session;
    } catch (error) {
      logger.error('Error creating session:', error);
      throw new Error('Failed to create session');
    }
  }

  /**
   * Get session by ID
   * @param {string} sessionId - Session ID
   * @returns {Promise<Object|null>} Session object or null
   */
  async getSession(sessionId) {
    try {
      const sessionKey = `session:${sessionId}`;
      const sessionData = await this.redisClient.get(sessionKey);
      
      if (!sessionData) {
        return null;
      }

      return JSON.parse(sessionData);
    } catch (error) {
      logger.error('Error getting session:', error);
      return null;
    }
  }

  /**
   * Update session activity
   * @param {string} sessionId - Session ID
   * @returns {Promise<boolean>} Success status
   */
  async updateActivity(sessionId) {
    try {
      const session = await this.getSession(sessionId);
      if (!session) {
        return false;
      }

      session.lastActivity = new Date().toISOString();

      const sessionKey = `session:${sessionId}`;
      await this.redisClient.setex(
        sessionKey,
        this.sessionTimeout / 1000,
        JSON.stringify(session)
      );

      return true;
    } catch (error) {
      logger.error('Error updating session activity:', error);
      return false;
    }
  }

  /**
   * Invalidate a specific session
   * @param {string} sessionId - Session ID
   * @returns {Promise<boolean>} Success status
   */
  async invalidateSession(sessionId) {
    try {
      const session = await this.getSession(sessionId);
      if (!session) {
        return false;
      }

      // Remove from Redis
      const sessionKey = `session:${sessionId}`;
      await this.redisClient.del(sessionKey);

      // Remove from user's active sessions
      await this.removeFromUserSessions(session.userId, sessionId);

      logger.info(`Session invalidated: ${sessionId}`, {
        userId: session.userId,
      });

      return true;
    } catch (error) {
      logger.error('Error invalidating session:', error);
      return false;
    }
  }

  /**
   * Invalidate all sessions for a user
   * @param {string} userId - User ID
   * @returns {Promise<number>} Number of sessions invalidated
   */
  async invalidateAllUserSessions(userId) {
    try {
      const userSessionsKey = `user_sessions:${userId}`;
      const sessionIds = await this.redisClient.smembers(userSessionsKey);
      
      let invalidatedCount = 0;
      for (const sessionId of sessionIds) {
        const success = await this.invalidateSession(sessionId);
        if (success) invalidatedCount++;
      }

      // Clear user sessions set
      await this.redisClient.del(userSessionsKey);

      logger.info(`All sessions invalidated for user: ${userId}`, {
        count: invalidatedCount,
      });

      return invalidatedCount;
    } catch (error) {
      logger.error('Error invalidating all user sessions:', error);
      return 0;
    }
  }

  /**
   * Get all active sessions for a user
   * @param {string} userId - User ID
   * @returns {Promise<Array>} Array of session objects
   */
  async getUserSessions(userId) {
    try {
      const userSessionsKey = `user_sessions:${userId}`;
      const sessionIds = await this.redisClient.smembers(userSessionsKey);
      
      const sessions = [];
      for (const sessionId of sessionIds) {
        const session = await this.getSession(sessionId);
        if (session) {
          sessions.push(session);
        }
      }

      return sessions;
    } catch (error) {
      logger.error('Error getting user sessions:', error);
      return [];
    }
  }

  /**
   * Add session to user's active sessions
   * @param {string} userId - User ID
   * @param {string} sessionId - Session ID
   */
  async addToUserSessions(userId, sessionId) {
    try {
      const userSessionsKey = `user_sessions:${userId}`;
      await this.redisClient.sadd(userSessionsKey, sessionId);
      
      // Set expiration for user sessions set
      await this.redisClient.expire(userSessionsKey, this.sessionTimeout / 1000);
    } catch (error) {
      logger.error('Error adding to user sessions:', error);
    }
  }

  /**
   * Remove session from user's active sessions
   * @param {string} userId - User ID
   * @param {string} sessionId - Session ID
   */
  async removeFromUserSessions(userId, sessionId) {
    try {
      const userSessionsKey = `user_sessions:${userId}`;
      await this.redisClient.srem(userSessionsKey, sessionId);
    } catch (error) {
      logger.error('Error removing from user sessions:', error);
    }
  }

  /**
   * Enforce maximum sessions per user
   * @param {string} userId - User ID
   */
  async enforceSessionLimit(userId) {
    try {
      const sessions = await this.getUserSessions(userId);
      
      if (sessions.length > this.maxSessionsPerUser) {
        // Sort by last activity (oldest first)
        sessions.sort((a, b) => new Date(a.lastActivity) - new Date(b.lastActivity));
        
        // Remove oldest sessions
        const sessionsToRemove = sessions.slice(0, sessions.length - this.maxSessionsPerUser);
        for (const session of sessionsToRemove) {
          await this.invalidateSession(session.id);
        }

        logger.info(`Enforced session limit for user: ${userId}`, {
          removedSessions: sessionsToRemove.length,
        });
      }
    } catch (error) {
      logger.error('Error enforcing session limit:', error);
    }
  }

  /**
   * Validate session and extract user info
   * @param {string} sessionId - Session ID
   * @returns {Promise<Object|null>} User info or null
   */
  async validateSession(sessionId) {
    try {
      const session = await this.getSession(sessionId);
      if (!session || !session.isActive) {
        return null;
      }

      // Check if session has expired
      const lastActivity = new Date(session.lastActivity);
      const now = new Date();
      const timeDiff = now - lastActivity;

      if (timeDiff > this.sessionTimeout) {
        await this.invalidateSession(sessionId);
        return null;
      }

      // Update activity
      await this.updateActivity(sessionId);

      return {
        userId: session.userId,
        sessionId: session.id,
        mfaVerified: session.mfaVerified,
      };
    } catch (error) {
      logger.error('Error validating session:', error);
      return null;
    }
  }

  /**
   * Generate device fingerprint
   * @param {Object} req - Express request object
   * @returns {string} Device fingerprint
   */
  generateDeviceFingerprint(req) {
    const components = [
      req.get('User-Agent') || '',
      req.get('Accept-Language') || '',
      req.get('Accept-Encoding') || '',
      req.ip || '',
    ];

    return crypto
      .createHash('sha256')
      .update(components.join('|'))
      .digest('hex');
  }

  /**
   * Check for suspicious session activity
   * @param {string} userId - User ID
   * @param {Object} currentSession - Current session data
   * @returns {Promise<Object>} Risk assessment
   */
  async assessSessionRisk(userId, currentSession) {
    try {
      const userSessions = await this.getUserSessions(userId);
      const riskFactors = [];
      let riskScore = 0;

      // Check for multiple concurrent sessions
      if (userSessions.length > 2) {
        riskFactors.push('multiple_sessions');
        riskScore += 0.3;
      }

      // Check for sessions from different IP addresses
      const ipAddresses = [...new Set(userSessions.map(s => s.ipAddress))];
      if (ipAddresses.length > 1) {
        riskFactors.push('multiple_ips');
        riskScore += 0.4;
      }

      // Check for sessions from different devices
      const deviceFingerprints = [...new Set(userSessions.map(s => s.deviceFingerprint))];
      if (deviceFingerprints.length > 1) {
        riskFactors.push('multiple_devices');
        riskScore += 0.3;
      }

      return {
        riskScore: Math.min(riskScore, 1.0),
        riskFactors,
        requiresAdditionalVerification: riskScore > 0.6,
      };
    } catch (error) {
      logger.error('Error assessing session risk:', error);
      return {
        riskScore: 0,
        riskFactors: [],
        requiresAdditionalVerification: false,
      };
    }
  }

  /**
   * Clean up expired sessions
   * @returns {Promise<number>} Number of cleaned sessions
   */
  async cleanupExpiredSessions() {
    try {
      let cleanedCount = 0;
      const pattern = 'session:*';
      const keys = await this.redisClient.keys(pattern);

      for (const key of keys) {
        const sessionData = await this.redisClient.get(key);
        if (sessionData) {
          const session = JSON.parse(sessionData);
          const lastActivity = new Date(session.lastActivity);
          const now = new Date();
          const timeDiff = now - lastActivity;

          if (timeDiff > this.sessionTimeout) {
            await this.invalidateSession(session.id);
            cleanedCount++;
          }
        }
      }

      logger.info(`Cleaned up expired sessions: ${cleanedCount}`);
      return cleanedCount;
    } catch (error) {
      logger.error('Error cleaning up expired sessions:', error);
      return 0;
    }
  }
}

module.exports = new SessionService();