const express = require('express');
const cors = require('cors');
const path = require('path');

// Import middleware
const {
  securityHeaders,
  compression,
  requestLogger,
  errorHandler,
  notFound,
  timeout,
  sanitizeInput,
} = require('./middleware/security');

// Import routes
const apiRoutes = require('./routes');
const logger = require('./config/logger');

const app = express();

// Trust proxy if behind reverse proxy
app.set('trust proxy', 1);

// Security headers
app.use(securityHeaders);

// Compression
app.use(compression);

// Request timeout
app.use(timeout(30000)); // 30 seconds

// Request logging
app.use(requestLogger);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Input sanitization
app.use(sanitizeInput);

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001',
      'https://autosec.io',
      'https://app.autosec.io',
      process.env.FRONTEND_URL,
    ].filter(Boolean);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      logger.warn('CORS blocked origin:', { origin });
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
};

app.use(cors(corsOptions));

// Static file serving (for uploads, documentation, etc.)
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// API Routes
app.use('/api', apiRoutes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'AutoSec API Server',
    version: process.env.API_VERSION || '1.0.0',
    docs: '/api/docs',
    health: '/api/health',
  });
});

// Health check endpoint (legacy)
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    message: 'AutoSec backend is healthy',
    timestamp: new Date().toISOString(),
  });
});

// 404 handler
app.use(notFound);

// Error handling middleware
app.use(errorHandler);

// Graceful shutdown handling
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

// Unhandled promise rejection handler
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', { promise, reason });
  process.exit(1);
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

module.exports = app;