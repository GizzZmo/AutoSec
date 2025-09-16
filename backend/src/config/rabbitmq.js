const amqp = require('amqplib');

let channel;

const connectRabbitMQ = async () => {
  try {
    const connection = await amqp.connect(process.env.RABBITMQ_URL);
    channel = await connection.createChannel();
    console.log('RabbitMQ channel created.');
  } catch (error) {
    console.error('Failed to connect to RabbitMQ:', error);
    process.exit(1);
  }
};

const publishMessage = async (queue, message) => {
  if (!channel) {
    console.error('RabbitMQ channel not established.');
    return;
  }
  try {
    await channel.assertQueue(queue, { durable: true });
    channel.sendToQueue(queue, Buffer.from(JSON.stringify(message)), { persistent: true });
    // console.log(`Message sent to queue ${queue}:`, message);
  } catch (error) {
    console.error(`Failed to publish message to queue ${queue}:`, error);
  }
};

const consumeMessages = async (queue, callback) => {
  if (!channel) {
    console.error('RabbitMQ channel not established.');
    return;
  }
  try {
    await channel.assertQueue(queue, { durable: true });
    channel.consume(queue, (msg) => {
      if (msg !== null) {
        callback(JSON.parse(msg.content.toString()));
        channel.ack(msg);
      }
    }, { noAck: false });
    console.log(`Started consuming messages from queue: ${queue}`);
  } catch (error) {
    console.error(`Failed to consume messages from queue ${queue}:`, error);
  }
};

module.exports = { connectRabbitMQ, publishMessage, consumeMessages };