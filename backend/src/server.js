require('dotenv').config();
const app = require('./app');
const { sequelize } = require('./config/db');
const { connectMongoDB } = require('./config/db');
const { connectRabbitMQ, consumeMessages } = require('./config/rabbitmq');
const rabbitmqConsumer = require('./services/rabbitmqConsumer'); // Import the consumer

const PORT = process.env.PORT || 8080;

async function startServer() {
  try {
    // Connect to PostgreSQL
    await sequelize.authenticate();
    console.log('PostgreSQL connection has been established successfully.');
    await sequelize.sync(); // Sync models with database (creates tables if they don't exist)
    console.log('PostgreSQL models synced.');

    // Connect to MongoDB
    await connectMongoDB();
    console.log('MongoDB connection has been established successfully.');

    // Connect to RabbitMQ and start consuming
    await connectRabbitMQ();
    console.log('RabbitMQ connection has been established successfully.');
    consumeMessages('log_queue', rabbitmqConsumer.processLogMessage); // Start consuming logs

    // Start the Express server
    app.listen(PORT, () => {
      console.log(`AutoSec Backend running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Unable to connect to the database or start server:', error);
    process.exit(1); // Exit with failure code
  }
}

startServer();