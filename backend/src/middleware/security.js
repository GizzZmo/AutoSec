const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const logger = require('../config/logger');

// Rate limiting configurations
exports.createRateLimit = (windowMs, max, message, skipSuccessfulRequests = false) => {
  return rateLimit({
    windowMs,
    max,
    message: {
      success: false,
      message: message || 'Too many requests, please try again later',
    },
    skipSuccessfulRequests,
    handler: (req, res) => {
      logger.warn('Rate limit exceeded', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        method: req.method,
      });
      res.status(429).json({
        success: false,
        message: message || 'Too many requests, please try again later',
      });
    },
  });
};

// General API rate limiting
exports.generalRateLimit = exports.createRateLimit(
  15 * 60 * 1000, // 15 minutes
  100, // 100 requests per window
  'Too many requests from this IP, please try again later'
);

// Strict rate limiting for authentication endpoints
exports.authRateLimit = exports.createRateLimit(
  15 * 60 * 1000, // 15 minutes
  5, // 5 attempts per window
  'Too many authentication attempts, please try again later',
  true // Skip successful requests
);

// Password reset rate limiting
exports.passwordResetRateLimit = exports.createRateLimit(
  60 * 60 * 1000, // 1 hour
  3, // 3 attempts per hour
  'Too many password reset attempts, please try again later'
);

// File upload rate limiting
exports.uploadRateLimit = exports.createRateLimit(
  60 * 60 * 1000, // 1 hour
  10, // 10 uploads per hour
  'Too many file uploads, please try again later'
);

// Security headers with Helmet
exports.securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false, // Disable for development
});

// Compression middleware
exports.compression = compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  },
});

// Request logging middleware
exports.requestLogger = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    };

    if (req.user) {
      logData.userId = req.user.id;
      logData.username = req.user.username;
    }

    if (res.statusCode >= 400) {
      logger.warn('HTTP Error', logData);
    } else {
      logger.http('HTTP Request', logData);
    }
  });

  next();
};

// Error handling middleware
exports.errorHandler = (err, req, res, next) => {
  logger.error('Unhandled error:', {
    error: err.message,
    stack: err.stack,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userId: req.user?.id,
  });

  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal server error',
    ...(isDevelopment && { stack: err.stack }),
  });
};

// 404 handler
exports.notFound = (req, res) => {
  logger.warn('Route not found', {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
  });

  res.status(404).json({
    success: false,
    message: 'Route not found',
  });
};

// Request timeout middleware
exports.timeout = (ms = 30000) => {
  return (req, res, next) => {
    res.setTimeout(ms, () => {
      logger.warn('Request timeout', {
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
        timeout: ms,
      });

      if (!res.headersSent) {
        res.status(408).json({
          success: false,
          message: 'Request timeout',
        });
      }
    });
    next();
  };
};

// Request size limiting
exports.requestSizeLimit = (limit = '10mb') => {
  return (req, res, next) => {
    req.on('data', (chunk) => {
      const size = chunk.length;
      if (size > parseFloat(limit) * 1024 * 1024) {
        logger.warn('Request size limit exceeded', {
          method: req.method,
          url: req.originalUrl,
          ip: req.ip,
          size: `${size} bytes`,
          limit,
        });

        return res.status(413).json({
          success: false,
          message: 'Request entity too large',
        });
      }
    });
    next();
  };
};

// IP whitelist middleware (for admin endpoints)
// NOTE: allowedIPs is cloned to avoid mutation leaking across requests
exports.ipWhitelist = (allowedIPs = []) => {
  const baseIPs = [...allowedIPs]; // capture once at registration time
  return (req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    
    // Build final list per request (don't mutate baseIPs)
    const effectiveIPs = [...baseIPs];
    if (process.env.NODE_ENV === 'development') {
      effectiveIPs.push('127.0.0.1', '::1', '::ffff:127.0.0.1');
    }

    if (effectiveIPs.length > 0 && !effectiveIPs.includes(clientIP)) {
      logger.warn('IP not in whitelist', {
        ip: clientIP,
        method: req.method,
        url: req.originalUrl,
      });

      return res.status(403).json({
        success: false,
        message: 'Access denied: IP not allowed',
      });
    }

    next();
  };
};

// Sanitize user input — replace HTML special chars to prevent XSS.
// This strips HTML tags and event handlers from all string inputs.
// NOTE: The primary defense is CSP headers (helmet) above. This is belt-and-suspenders.
exports.sanitizeInput = (req, res, next) => {
  const sanitize = (obj) => {
    if (typeof obj === 'string') {
      // Strip all HTML tags (catches <script>, <img onerror>, <svg onload>, etc.)
      // and remove dangerous URL schemes
      return obj
        .replace(/<[^>]*>/g, '')           // all HTML tags
        .replace(/javascript:/gi, '')       // javascript: URIs
        .replace(/vbscript:/gi, '')         // vbscript: URIs
        .replace(/data:(?!image\/)/gi, '')  // data: URIs except images
        .replace(/on\w+\s*=/gi, '');        // event handlers
    } else if (Array.isArray(obj)) {
      return obj.map(sanitize);
    } else if (typeof obj === 'object' && obj !== null) {
      const sanitized = {};
      for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          sanitized[key] = sanitize(obj[key]);
        }
      }
      return sanitized;
    }
    return obj;
  };

  req.body = sanitize(req.body);
  // Create new objects for query and params — don't mutate the originals
  req.query = sanitize(req.query);
  req.params = sanitize(req.params);
  
  next();
};

module.exports = exports;