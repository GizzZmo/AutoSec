const Log = require('../models/Log');

// This function will be called by the RabbitMQ consumer when a new message arrives
const processLogMessage = async (logData) => {
  try {
    // Save the log to MongoDB
    const newLog = new Log(logData);
    await newLog.save();
    // console.log('Log saved to MongoDB:', newLog._id);

    // Here you would also trigger other services based on the log:
    // - Behavioral Analysis Engine: Send log for anomaly detection
    // - Alerting Service: Check for critical events and generate alerts
    // - Incident Response: Trigger playbooks for specific event types

  } catch (error) {
    console.error('Error processing log message from RabbitMQ:', error);
  }
};

module.exports = { processLogMessage };