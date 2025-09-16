const { body, param, query } = require('express-validator');

// User registration validation
exports.validateRegistration = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Username must be between 3 and 50 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username can only contain letters, numbers, underscores, and hyphens'),
  
  body('email')
    .trim()
    .isEmail()
    .withMessage('Must be a valid email address')
    .normalizeEmail(),
  
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  
  body('firstName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name is required and must be less than 50 characters'),
  
  body('lastName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name is required and must be less than 50 characters'),
  
  body('role')
    .optional()
    .isIn(['admin', 'analyst', 'operator', 'viewer'])
    .withMessage('Role must be one of: admin, analyst, operator, viewer'),
];

// User login validation
exports.validateLogin = [
  body('identifier')
    .trim()
    .notEmpty()
    .withMessage('Email or username is required'),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
];

// Password change validation
exports.validatePasswordChange = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('New password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
];

// Profile update validation
exports.validateProfileUpdate = [
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be between 1 and 50 characters'),
  
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be between 1 and 50 characters'),
  
  body('preferences')
    .optional()
    .isObject()
    .withMessage('Preferences must be an object'),
];

// Refresh token validation
exports.validateRefreshToken = [
  body('refreshToken')
    .notEmpty()
    .withMessage('Refresh token is required'),
];

// Rule validation
exports.validateRule = [
  body('type')
    .isIn(['IP_SINGLE', 'IP_RANGE', 'COUNTRY', 'ORGANIZATION'])
    .withMessage('Type must be one of: IP_SINGLE, IP_RANGE, COUNTRY, ORGANIZATION'),
  
  body('value')
    .trim()
    .notEmpty()
    .withMessage('Value is required')
    .custom((value, { req }) => {
      const type = req.body.type;
      
      if (type === 'IP_SINGLE') {
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        if (!ipRegex.test(value)) {
          throw new Error('Invalid IP address format');
        }
      } else if (type === 'IP_RANGE') {
        const cidrRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;
        if (!cidrRegex.test(value)) {
          throw new Error('Invalid CIDR format');
        }
      } else if (type === 'COUNTRY') {
        const countryRegex = /^[A-Z]{2}$/;
        if (!countryRegex.test(value)) {
          throw new Error('Country code must be 2 uppercase letters');
        }
      } else if (type === 'ORGANIZATION') {
        if (value.length < 1 || value.length > 255) {
          throw new Error('Organization name must be between 1 and 255 characters');
        }
      }
      
      return true;
    }),
  
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Description must be less than 500 characters'),
  
  body('is_permanent')
    .optional()
    .isBoolean()
    .withMessage('is_permanent must be a boolean'),
  
  body('expires_at')
    .optional()
    .isISO8601()
    .withMessage('expires_at must be a valid ISO 8601 date')
    .custom((value, { req }) => {
      if (!req.body.is_permanent && !value) {
        throw new Error('expires_at is required for temporary rules');
      }
      if (req.body.is_permanent && value) {
        throw new Error('expires_at should not be provided for permanent rules');
      }
      if (value && new Date(value) <= new Date()) {
        throw new Error('expires_at must be in the future');
      }
      return true;
    }),
];

// Rule update validation
exports.validateRuleUpdate = [
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Description must be less than 500 characters'),
  
  body('is_active')
    .optional()
    .isBoolean()
    .withMessage('is_active must be a boolean'),
  
  body('is_permanent')
    .optional()
    .isBoolean()
    .withMessage('is_permanent must be a boolean'),
  
  body('expires_at')
    .optional()
    .isISO8601()
    .withMessage('expires_at must be a valid ISO 8601 date')
    .custom((value, { req }) => {
      if (value && new Date(value) <= new Date()) {
        throw new Error('expires_at must be in the future');
      }
      return true;
    }),
];

// Log ingestion validation
exports.validateLogIngestion = [
  body('level')
    .isIn(['info', 'warn', 'error', 'debug', 'critical'])
    .withMessage('Level must be one of: info, warn, error, debug, critical'),
  
  body('source')
    .trim()
    .notEmpty()
    .withMessage('Source is required')
    .isLength({ max: 100 })
    .withMessage('Source must be less than 100 characters'),
  
  body('event_type')
    .trim()
    .notEmpty()
    .withMessage('Event type is required')
    .isLength({ max: 100 })
    .withMessage('Event type must be less than 100 characters'),
  
  body('message')
    .trim()
    .notEmpty()
    .withMessage('Message is required')
    .isLength({ max: 1000 })
    .withMessage('Message must be less than 1000 characters'),
  
  body('timestamp')
    .optional()
    .isISO8601()
    .withMessage('Timestamp must be a valid ISO 8601 date'),
  
  body('ip_address')
    .optional()
    .isIP()
    .withMessage('IP address must be valid'),
  
  body('user_id')
    .optional()
    .isUUID()
    .withMessage('User ID must be a valid UUID'),
  
  body('device_id')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Device ID must be less than 100 characters'),
  
  body('metadata')
    .optional()
    .isObject()
    .withMessage('Metadata must be an object'),
];

// UUID parameter validation
exports.validateUUID = [
  param('id')
    .isUUID()
    .withMessage('Invalid ID format'),
];

// Pagination validation
exports.validatePagination = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
];

// Log filtering validation
exports.validateLogFilters = [
  query('level')
    .optional()
    .isIn(['info', 'warn', 'error', 'debug', 'critical'])
    .withMessage('Level must be one of: info, warn, error, debug, critical'),
  
  query('source')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Source must be less than 100 characters'),
  
  query('event_type')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Event type must be less than 100 characters'),
  
  query('ip_address')
    .optional()
    .isIP()
    .withMessage('IP address must be valid'),
  
  query('search')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('Search term must be less than 200 characters'),
];

module.exports = exports;