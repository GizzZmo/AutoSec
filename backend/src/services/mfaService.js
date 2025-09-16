const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const crypto = require('crypto');
const logger = require('../config/logger');

class MFAService {
  /**
   * Generate a new MFA secret for a user
   * @param {string} username - User's username
   * @param {string} serviceName - Service name for QR code
   * @returns {Object} Secret and QR code data
   */
  generateSecret(username, serviceName = 'AutoSec') {
    const secret = speakeasy.generateSecret({
      name: `${serviceName} (${username})`,
      issuer: serviceName,
      length: 32,
    });

    return {
      secret: secret.base32,
      tempSecret: secret.base32,
      dataURL: secret.otpauth_url,
    };
  }

  /**
   * Generate QR code for MFA setup
   * @param {string} otpauthUrl - OTP auth URL
   * @returns {Promise<string>} Base64 encoded QR code
   */
  async generateQRCode(otpauthUrl) {
    try {
      const qrCodeDataURL = await QRCode.toDataURL(otpauthUrl);
      return qrCodeDataURL;
    } catch (error) {
      logger.error('Error generating QR code:', error);
      throw new Error('Failed to generate QR code');
    }
  }

  /**
   * Verify TOTP token
   * @param {string} token - 6-digit TOTP token
   * @param {string} secret - Base32 encoded secret
   * @param {number} window - Time window for validation (default: 2)
   * @returns {boolean} True if token is valid
   */
  verifyToken(token, secret, window = 2) {
    try {
      return speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token,
        window: window,
      });
    } catch (error) {
      logger.error('Error verifying MFA token:', error);
      return false;
    }
  }

  /**
   * Generate backup codes for MFA
   * @param {number} count - Number of backup codes to generate
   * @returns {Array<string>} Array of backup codes
   */
  generateBackupCodes(count = 8) {
    const codes = [];
    for (let i = 0; i < count; i++) {
      const code = crypto.randomBytes(4).toString('hex').toUpperCase();
      const formattedCode = code.match(/.{1,4}/g).join('-');
      codes.push(formattedCode);
    }
    return codes;
  }

  /**
   * Validate backup code
   * @param {string} inputCode - User-provided backup code
   * @param {Array<string>} backupCodes - Array of valid backup codes
   * @returns {Object} Validation result and remaining codes
   */
  validateBackupCode(inputCode, backupCodes) {
    const normalizedInput = inputCode.replace(/-/g, '').toUpperCase();
    const normalizedCodes = backupCodes.map(code => code.replace(/-/g, '').toUpperCase());
    
    const index = normalizedCodes.indexOf(normalizedInput);
    if (index !== -1) {
      const remainingCodes = [...backupCodes];
      remainingCodes.splice(index, 1);
      return {
        valid: true,
        remainingCodes,
        usedCode: backupCodes[index],
      };
    }
    
    return {
      valid: false,
      remainingCodes: backupCodes,
      usedCode: null,
    };
  }

  /**
   * Generate recovery code for MFA reset
   * @returns {string} Recovery code
   */
  generateRecoveryCode() {
    return crypto.randomBytes(16).toString('hex').toUpperCase();
  }

  /**
   * Check if MFA token is required for user
   * @param {Object} user - User object
   * @param {Object} loginContext - Login context (IP, user agent, etc.)
   * @returns {boolean} True if MFA is required
   */
  isMFARequired(user, loginContext = {}) {
    // Always require MFA if enabled
    if (user.mfaEnabled) {
      return true;
    }

    // Risk-based authentication rules
    const riskFactors = this.assessLoginRisk(user, loginContext);
    return riskFactors.score > 0.7; // Require MFA for high-risk logins
  }

  /**
   * Assess login risk based on various factors
   * @param {Object} user - User object
   * @param {Object} context - Login context
   * @returns {Object} Risk assessment
   */
  assessLoginRisk(user, context) {
    let riskScore = 0;
    const factors = [];

    // Check for new IP address
    if (context.ip && user.knownIPs && !user.knownIPs.includes(context.ip)) {
      riskScore += 0.3;
      factors.push('unknown_ip');
    }

    // Check for new device/user agent
    if (context.userAgent && user.knownDevices && !user.knownDevices.includes(context.userAgent)) {
      riskScore += 0.2;
      factors.push('unknown_device');
    }

    // Check for unusual login time
    const currentHour = new Date().getHours();
    if (user.typicalLoginHours && !user.typicalLoginHours.includes(currentHour)) {
      riskScore += 0.1;
      factors.push('unusual_time');
    }

    // Check for high-privilege roles
    if (user.role === 'admin' || user.role === 'analyst') {
      riskScore += 0.2;
      factors.push('privileged_role');
    }

    // Check for recent failed login attempts
    if (user.failedLoginAttempts > 0) {
      riskScore += 0.1;
      factors.push('recent_failures');
    }

    return {
      score: Math.min(riskScore, 1.0),
      factors,
      requiresMFA: riskScore > 0.7,
    };
  }
}

module.exports = new MFAService();