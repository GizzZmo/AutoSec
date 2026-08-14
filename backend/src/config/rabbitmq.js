const amqp = require('amqplib');
const logger = require('./logger');

let connection = null;
let channel = null;
let isConnecting = false;
let reconnectTimer = null;

const RECONNECT_DELAY = 5000; // 5 seconds
const MAX_RECONNECT_DELAY = 60000; // 1 minute

const connectRabbitMQ = async () => {
  if (isConnecting) return;
  isConnecting = true;

  try {
    connection = await amqp.connect(process.env.RABBITMQ_URL);

    connection.on('error', (err) => {
      logger.error('RabbitMQ connection error:', { error: err.message });
    });

    connection.on('close', () => {
      logger.warn('RabbitMQ connection closed. Attempting reconnect...');
      channel = null;
      isConnecting = false;
      scheduleReconnect();
    });

    channel = await connection.createChannel();

    channel.on('error', (err) => {
      logger.error('RabbitMQ channel error:', { error: err.message });
    });

    channel.on('close', () => {
      logger.warn('RabbitMQ channel closed.');
      channel = null;
    });

    // Prefetch — don't flood the consumer
    channel.prefetch(10);

    logger.info('RabbitMQ channel created.');
    isConnecting = false;

    // Clear any pending reconnect timer on successful connection
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  } catch (error) {
    logger.error('Failed to connect to RabbitMQ:', { error: error.message });
    isConnecting = false;
    scheduleReconnect();
  }
};

let currentDelay = RECONNECT_DELAY;

const scheduleReconnect = () => {
  if (reconnectTimer) return;
  logger.info(`RabbitMQ reconnecting in ${currentDelay / 1000}s...`);
  reconnectTimer = setTimeout(async () => {
    reconnectTimer = null;
    await connectRabbitMQ();
    // Exponential backoff (reset on success handled above)
    currentDelay = Math.min(currentDelay * 2, MAX_RECONNECT_DELAY);
  }, currentDelay);
};

const getChannel = () => channel;

const closeRabbitMQ = async () => {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  try {
    if (channel) await channel.close();
    if (connection) await connection.close();
    logger.info('RabbitMQ connections closed');
  } catch (e) {
    // Ignore close errors during shutdown
  }
  channel = null;
  connection = null;
};

const publishMessage = async (queue, message) => {
  if (!channel) {
    logger.error('RabbitMQ channel not established; message dropped.');
    return false;
  }
  try {
    await channel.assertQueue(queue, { durable: true });
    return channel.sendToQueue(queue, Buffer.from(JSON.stringify(message)), { persistent: true });
  } catch (error) {
    logger.error(`Failed to publish message to queue ${queue}:`, { error: error.message });
    return false;
  }
};

const consumeMessages = async (queue, callback) => {
  if (!channel) {
    logger.error('RabbitMQ channel not established; cannot consume.');
    return;
  }
  try {
    await channel.assertQueue(queue, { durable: true });
    channel.consume(queue, (msg) => {
      if (msg !== null) {
        try {
          callback(JSON.parse(msg.content.toString()));
          channel.ack(msg);
        } catch (err) {
          // Reject the message on parse/processing error, don't requeue (avoid poison pills)
          logger.error(`Error processing message from ${queue}:`, { error: err.message });
          channel.nack(msg, false, false);
        }
      }
    }, { noAck: false });
    logger.info(`Started consuming messages from queue: ${queue}`);
  } catch (error) {
    logger.error(`Failed to consume messages from queue ${queue}:`, { error: error.message });
  }
};

module.exports = { connectRabbitMQ, publishMessage, consumeMessages, closeRabbitMQ, getChannel };