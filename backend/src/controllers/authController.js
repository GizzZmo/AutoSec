const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { validationResult } = require('express-validator');
const User = require('../models/User');
const logger = require('../config/logger');

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

// Generate JWT token
const generateTokens = (userId) => {
  const accessToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  const refreshToken = jwt.sign({ userId, type: 'refresh' }, JWT_SECRET, { expiresIn: JWT_REFRESH_EXPIRES_IN });
  
  return { accessToken, refreshToken };
};

// Register new user
exports.register = async (req, res) => {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array(),
      });
    }

    const { username, email, password, firstName, lastName, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      where: {
        $or: [{ email }, { username }],
      },
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'User with this email or username already exists',
      });
    }

    // Create new user
    const user = await User.create({
      username,
      email,
      password,
      firstName,
      lastName,
      role: role || 'viewer',
      emailVerificationToken: crypto.randomBytes(32).toString('hex'),
    });

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user.id);

    logger.info(`New user registered: ${user.username}`, {
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: user.getPublicProfile(),
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    logger.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Login user
exports.login = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array(),
      });
    }

    const { identifier, password } = req.body; // identifier can be email or username

    // Find user by email or username
    const user = await User.findOne({
      where: {
        $or: [{ email: identifier }, { username: identifier }],
      },
    });

    if (!user) {
      logger.warn(`Login attempt with invalid identifier: ${identifier}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    // Check if account is locked
    if (user.isLocked()) {
      logger.warn(`Login attempt on locked account: ${user.username}`, {
        userId: user.id,
        ip: req.ip,
        lockoutUntil: user.lockoutUntil,
      });
      return res.status(423).json({
        success: false,
        message: 'Account is temporarily locked due to too many failed login attempts',
      });
    }

    // Check if account is active
    if (!user.isActive) {
      logger.warn(`Login attempt on inactive account: ${user.username}`, {
        userId: user.id,
        ip: req.ip,
      });
      return res.status(401).json({
        success: false,
        message: 'Account is inactive',
      });
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      await user.incFailedLoginAttempts();
      logger.warn(`Failed login attempt for user: ${user.username}`, {
        userId: user.id,
        ip: req.ip,
        failedAttempts: user.failedLoginAttempts + 1,
      });
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    // Reset failed login attempts on successful password verification
    if (user.failedLoginAttempts > 0) {
      await user.resetFailedLoginAttempts();
    }

    const mfaService = require('../services/mfaService');
    const loginContext = {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    };

    // Check if MFA is required
    const requiresMFA = mfaService.isMFARequired(user, loginContext);
    
    if (requiresMFA) {
      // Create MFA session
      const crypto = require('crypto');
      const mfaToken = crypto.randomBytes(32).toString('hex');
      
      // Store MFA session (in production, use Redis or secure session store)
      req.session = req.session || {};
      req.session.mfaSession = {
        userId: user.id,
        token: mfaToken,
        expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
      };

      logger.info(`MFA required for user: ${user.username}`, {
        userId: user.id,
        ip: req.ip,
        reason: user.mfaEnabled ? 'mfa_enabled' : 'risk_assessment',
      });

      return res.json({
        success: true,
        requiresMFA: true,
        message: 'Multi-factor authentication required',
        data: {
          mfaToken,
          hasBackupCodes: !!(user.mfaBackupCodes && user.mfaBackupCodes.length > 0),
        },
      });
    }

    // Complete login without MFA
    const { accessToken, refreshToken } = generateTokens(user.id);
    await user.updateLoginContext(req.ip, req.get('User-Agent'));

    logger.info(`Successful login for user: ${user.username}`, {
      userId: user.id,
      ip: req.ip,
    });

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: user.getPublicProfile(),
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Refresh token
exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required',
      });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    if (decoded.type !== 'refresh') {
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token',
      });
    }

    // Find user
    const user = await User.findByPk(decoded.userId);
    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'User not found or inactive',
      });
    }

    // Generate new tokens
    const tokens = generateTokens(user.id);

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: tokens,
    });
  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired refresh token',
      });
    }

    logger.error('Refresh token error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Get current user profile
exports.getProfile = async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    res.json({
      success: true,
      data: {
        user: user.getPublicProfile(),
      },
    });
  } catch (error) {
    logger.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Update user profile
exports.updateProfile = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array(),
      });
    }

    const { firstName, lastName, preferences } = req.body;
    const user = await User.findByPk(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    await user.update({
      firstName: firstName || user.firstName,
      lastName: lastName || user.lastName,
      preferences: preferences || user.preferences,
    });

    logger.info(`Profile updated for user: ${user.username}`, {
      userId: user.id,
    });

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        user: user.getPublicProfile(),
      },
    });
  } catch (error) {
    logger.error('Update profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Change password
exports.changePassword = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array(),
      });
    }

    const { currentPassword, newPassword } = req.body;
    const user = await User.findByPk(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Verify current password
    const isCurrentPasswordValid = await user.comparePassword(currentPassword);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({
        success: false,
        message: 'Current password is incorrect',
      });
    }

    // Update password
    await user.update({ password: newPassword });

    logger.info(`Password changed for user: ${user.username}`, {
      userId: user.id,
    });

    res.json({
      success: true,
      message: 'Password changed successfully',
    });
  } catch (error) {
    logger.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Logout (client-side token invalidation)
exports.logout = (req, res) => {
  // In a stateless JWT setup, logout is handled client-side by removing the token
  // For enhanced security, you could maintain a blacklist of tokens in Redis
  
  logger.info(`User logged out: ${req.user.username}`, {
    userId: req.user.id,
  });

  res.json({
    success: true,
    message: 'Logged out successfully',
  });
};