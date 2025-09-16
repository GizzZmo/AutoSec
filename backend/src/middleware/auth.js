const jwt = require('jsonwebtoken');
const User = require('../models/User');
const rbacService = require('../services/rbacService');
const logger = require('../config/logger');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Authentication middleware
exports.authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Access token is required',
      });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if it's not a refresh token
    if (decoded.type === 'refresh') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token type',
      });
    }

    // Find user
    const user = await User.findByPk(decoded.userId);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found',
      });
    }

    // Check if user is active
    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Account is inactive',
      });
    }

    // Attach user to request
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token',
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expired',
      });
    }

    logger.error('Authentication error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Authorization middleware factory
exports.authorize = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      logger.warn(`Unauthorized access attempt by user: ${req.user.username}`, {
        userId: req.user.id,
        userRole: req.user.role,
        requiredRoles: allowedRoles,
        endpoint: req.originalUrl,
        method: req.method,
      });

      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions',
      });
    }

    next();
  };
};

// Permission-based authorization middleware
exports.requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
    }

    if (!rbacService.hasPermission(req.user, permission)) {
      logger.warn(`Permission denied for user: ${req.user.username}`, {
        userId: req.user.id,
        userRole: req.user.role,
        requiredPermission: permission,
        endpoint: req.originalUrl,
        method: req.method,
      });

      return res.status(403).json({
        success: false,
        message: `Permission required: ${permission}`,
        requiredPermission: permission,
      });
    }

    next();
  };
};

// Multiple permissions middleware (user needs ALL permissions)
exports.requireAllPermissions = (...permissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
    }

    const missingPermissions = permissions.filter(
      permission => !rbacService.hasPermission(req.user, permission)
    );

    if (missingPermissions.length > 0) {
      logger.warn(`Multiple permissions denied for user: ${req.user.username}`, {
        userId: req.user.id,
        userRole: req.user.role,
        missingPermissions,
        endpoint: req.originalUrl,
        method: req.method,
      });

      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions',
        missingPermissions,
      });
    }

    next();
  };
};

// Any of the permissions middleware (user needs ANY permission)
exports.requireAnyPermission = (...permissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
    }

    const hasAnyPermission = permissions.some(
      permission => rbacService.hasPermission(req.user, permission)
    );

    if (!hasAnyPermission) {
      logger.warn(`No required permissions for user: ${req.user.username}`, {
        userId: req.user.id,
        userRole: req.user.role,
        requiredPermissions: permissions,
        endpoint: req.originalUrl,
        method: req.method,
      });

      return res.status(403).json({
        success: false,
        message: 'At least one of the required permissions is needed',
        requiredPermissions: permissions,
      });
    }

    next();
  };
};

// Role hierarchy check
exports.requireMinRole = (minRole) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
    }

    if (!rbacService.hasMinimumRole(req.user, minRole)) {
      logger.warn(`Insufficient role level for user: ${req.user.username}`, {
        userId: req.user.id,
        userRole: req.user.role,
        requiredRole: minRole,
        endpoint: req.originalUrl,
        method: req.method,
      });

      return res.status(403).json({
        success: false,
        message: `Minimum role required: ${minRole}`,
      });
    }

    next();
  };
};

// Optional authentication (for endpoints that work with or without auth)
exports.optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next(); // Continue without user
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET);
    
    if (decoded.type === 'refresh') {
      return next(); // Continue without user
    }

    const user = await User.findByPk(decoded.userId);
    if (user && user.isActive) {
      req.user = user;
    }
    
    next();
  } catch (error) {
    // Ignore token errors for optional auth
    next();
  }
};

// Check if user owns resource or has admin privileges
exports.ownerOrAdmin = (resourceUserIdField = 'userId') => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
    }

    // Admin can access any resource
    if (req.user.role === 'admin') {
      return next();
    }

    // Check if user owns the resource
    const resourceUserId = req.params[resourceUserIdField] || 
                          req.body[resourceUserIdField] || 
                          req.query[resourceUserIdField];

    if (resourceUserId && resourceUserId === req.user.id) {
      return next();
    }

    return res.status(403).json({
      success: false,
      message: 'Access denied: You can only access your own resources',
    });
  };
};

// User management permission check
exports.canManageUser = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required',
    });
  }

  const targetUserId = req.params.userId || req.params.id || req.body.userId;
  
  if (!targetUserId) {
    return res.status(400).json({
      success: false,
      message: 'Target user ID is required',
    });
  }

  // Find target user to check role hierarchy
  User.findByPk(targetUserId)
    .then(targetUser => {
      if (!targetUser) {
        return res.status(404).json({
          success: false,
          message: 'Target user not found',
        });
      }

      if (!rbacService.canManageUser(req.user, targetUser)) {
        logger.warn(`User management denied for user: ${req.user.username}`, {
          userId: req.user.id,
          targetUserId: targetUser.id,
          userRole: req.user.role,
          targetRole: targetUser.role,
        });

        return res.status(403).json({
          success: false,
          message: 'Cannot manage user with equal or higher role level',
        });
      }

      req.targetUser = targetUser;
      next();
    })
    .catch(error => {
      logger.error('User management check error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    });
};

module.exports = exports;

module.exports = exports;