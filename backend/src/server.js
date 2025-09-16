require('dotenv').config();
const app = require('./app');
const { sequelize } = require('./config/db');
const { connectMongoDB } = require('./config/db');
const { connectRabbitMQ, consumeMessages } = require('./config/rabbitmq');
const rabbitmqConsumer = require('./services/rabbitmqConsumer');
const ScheduledAnalysisService = require('./services/scheduledAnalysis');
const logger = require('./config/logger');

const PORT = process.env.PORT || 8080;

// Initialize scheduled analysis service
const scheduledAnalysisService = new ScheduledAnalysisService();

async function startServer() {
  try {
    // Connect to PostgreSQL
    await sequelize.authenticate();
    logger.info('PostgreSQL connection has been established successfully.');
    await sequelize.sync(); // Sync models with database (creates tables if they don't exist)
    logger.info('PostgreSQL models synced.');

    // Connect to MongoDB
    await connectMongoDB();
    logger.info('MongoDB connection has been established successfully.');

    // Connect to RabbitMQ and start consuming
    await connectRabbitMQ();
    logger.info('RabbitMQ connection has been established successfully.');
    consumeMessages('log_queue', rabbitmqConsumer.processLogMessage); // Start consuming logs

    // Start scheduled analysis service
    if (process.env.NODE_ENV !== 'test') { // Don't start in test environment
      scheduledAnalysisService.start();
      logger.info('Scheduled analysis service started');
    }

    // Start the Express server
    const server = app.listen(PORT, () => {
      logger.info(`AutoSec Backend running on port ${PORT}`);
      logger.info(`API Documentation available at http://localhost:${PORT}/api/docs`);
    });

    // Graceful shutdown handlers
    const gracefulShutdown = async (signal) => {
      logger.info(`${signal} received, starting graceful shutdown`);
      
      // Stop accepting new connections
      server.close(() => {
        logger.info('HTTP server closed');
      });

      // Stop scheduled services
      scheduledAnalysisService.stop();
      logger.info('Scheduled analysis service stopped');

      // Close database connections
      try {
        await sequelize.close();
        logger.info('PostgreSQL connection closed');
      } catch (error) {
        logger.error('Error closing PostgreSQL connection:', error);
      }

      // Exit process
      process.exit(0);
    };

    // Handle shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  } catch (error) {
    logger.error('Unable to connect to the database or start server:', error);
    process.exit(1); // Exit with failure code
  }
}

startServer();

// Export for testing purposes
module.exports = { scheduledAnalysisService };