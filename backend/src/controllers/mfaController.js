const { validationResult } = require('express-validator');
const User = require('../models/User');
const mfaService = require('../services/mfaService');
const logger = require('../config/logger');

// Setup MFA for user
exports.setupMFA = async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    if (user.mfaEnabled) {
      return res.status(400).json({
        success: false,
        message: 'MFA is already enabled for this account',
      });
    }

    // Generate MFA secret and QR code
    const { secret, dataURL } = mfaService.generateSecret(user.username);
    const qrCodeDataURL = await mfaService.generateQRCode(dataURL);

    // Store temporary secret
    await user.update({ mfaTempSecret: secret });

    logger.info(`MFA setup initiated for user: ${user.username}`, {
      userId: user.id,
    });

    res.json({
      success: true,
      message: 'MFA setup initiated',
      data: {
        secret,
        qrCode: qrCodeDataURL,
        manualEntryKey: secret,
      },
    });
  } catch (error) {
    logger.error('MFA setup error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Verify and enable MFA
exports.verifyAndEnableMFA = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array(),
      });
    }

    const { token } = req.body;
    const user = await User.findByPk(req.user.id);

    if (!user || !user.mfaTempSecret) {
      return res.status(400).json({
        success: false,
        message: 'MFA setup not initiated or user not found',
      });
    }

    // Verify the token
    const isValid = mfaService.verifyToken(token, user.mfaTempSecret);
    if (!isValid) {
      return res.status(400).json({
        success: false,
        message: 'Invalid verification code',
      });
    }

    // Generate backup codes
    const backupCodes = mfaService.generateBackupCodes();

    // Enable MFA
    await user.enableMFA(user.mfaTempSecret, backupCodes);

    logger.info(`MFA enabled for user: ${user.username}`, {
      userId: user.id,
    });

    res.json({
      success: true,
      message: 'MFA enabled successfully',
      data: {
        backupCodes,
        message: 'Please save these backup codes in a safe place. They can be used if you lose access to your authenticator app.',
      },
    });
  } catch (error) {
    logger.error('MFA verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Disable MFA
exports.disableMFA = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array(),
      });
    }

    const { token, password } = req.body;
    const user = await User.findByPk(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    if (!user.mfaEnabled) {
      return res.status(400).json({
        success: false,
        message: 'MFA is not enabled for this account',
      });
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: 'Invalid password',
      });
    }

    // Verify MFA token
    const isTokenValid = mfaService.verifyToken(token, user.mfaSecret);
    if (!isTokenValid) {
      return res.status(400).json({
        success: false,
        message: 'Invalid MFA code',
      });
    }

    // Disable MFA
    await user.disableMFA();

    logger.info(`MFA disabled for user: ${user.username}`, {
      userId: user.id,
    });

    res.json({
      success: true,
      message: 'MFA disabled successfully',
    });
  } catch (error) {
    logger.error('MFA disable error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Verify MFA token during login
exports.verifyMFA = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array(),
      });
    }

    const { token, useBackupCode = false } = req.body;
    const { userId } = req.mfaSession || {};

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'Invalid MFA session',
      });
    }

    const user = await User.findByPk(userId);
    if (!user || !user.mfaEnabled) {
      return res.status(400).json({
        success: false,
        message: 'Invalid MFA session',
      });
    }

    let isValid = false;
    let updatedBackupCodes = user.mfaBackupCodes;

    if (useBackupCode) {
      // Verify backup code
      const result = mfaService.validateBackupCode(token, user.mfaBackupCodes || []);
      isValid = result.valid;
      updatedBackupCodes = result.remainingCodes;
      
      if (isValid) {
        await user.update({ mfaBackupCodes: updatedBackupCodes });
        logger.warn(`Backup code used for user: ${user.username}`, {
          userId: user.id,
          remainingCodes: updatedBackupCodes.length,
        });
      }
    } else {
      // Verify TOTP token
      isValid = mfaService.verifyToken(token, user.mfaSecret);
    }

    if (!isValid) {
      logger.warn(`Invalid MFA attempt for user: ${user.username}`, {
        userId: user.id,
        useBackupCode,
        ip: req.ip,
      });
      return res.status(400).json({
        success: false,
        message: useBackupCode ? 'Invalid backup code' : 'Invalid verification code',
      });
    }

    // MFA successful, complete login
    const jwt = require('jsonwebtoken');
    const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
    const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
    const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

    const accessToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    const refreshToken = jwt.sign({ userId: user.id, type: 'refresh' }, JWT_SECRET, { expiresIn: JWT_REFRESH_EXPIRES_IN });

    // Update login context
    await user.updateLoginContext(req.ip, req.get('User-Agent'));

    logger.info(`MFA verification successful for user: ${user.username}`, {
      userId: user.id,
      ip: req.ip,
    });

    res.json({
      success: true,
      message: 'MFA verification successful',
      data: {
        user: user.getPublicProfile(),
        accessToken,
        refreshToken,
        warning: useBackupCode && updatedBackupCodes.length <= 2 ? 
          'You have used a backup code. Consider regenerating backup codes.' : null,
      },
    });
  } catch (error) {
    logger.error('MFA verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Generate new backup codes
exports.regenerateBackupCodes = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array(),
      });
    }

    const { token, password } = req.body;
    const user = await User.findByPk(req.user.id);

    if (!user || !user.mfaEnabled) {
      return res.status(400).json({
        success: false,
        message: 'MFA is not enabled for this account',
      });
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: 'Invalid password',
      });
    }

    // Verify MFA token
    const isTokenValid = mfaService.verifyToken(token, user.mfaSecret);
    if (!isTokenValid) {
      return res.status(400).json({
        success: false,
        message: 'Invalid MFA code',
      });
    }

    // Generate new backup codes
    const backupCodes = mfaService.generateBackupCodes();
    await user.update({ mfaBackupCodes: backupCodes });

    logger.info(`Backup codes regenerated for user: ${user.username}`, {
      userId: user.id,
    });

    res.json({
      success: true,
      message: 'Backup codes regenerated successfully',
      data: {
        backupCodes,
        message: 'Please save these new backup codes in a safe place. Your old backup codes are no longer valid.',
      },
    });
  } catch (error) {
    logger.error('Backup codes regeneration error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

module.exports = exports;