const Log = require('../models/Log');
const { publishMessage } = require('../config/rabbitmq');
const geoIpService = require('../services/geoIpService');

// Ingest logs (via API endpoint, then publish to RabbitMQ)
exports.ingestLog = async (req, res) => {
  const { timestamp, level, source, event_type, message, metadata, ip_address, user_id, device_id } = req.body;

  if (!level || !source || !event_type || !message) {
    return res.status(400).json({ message: 'Missing required log fields: level, source, event_type, message.' });
  }

  const logData = {
    timestamp: timestamp ? new Date(timestamp) : new Date(),
    level,
    source,
    event_type,
    message,
    metadata: metadata || {},
    ip_address,
    user_id,
    device_id,
  };

  // Perform GeoIP lookup if an IP address is provided
  if (ip_address) {
    const geo = geoIpService.lookup(ip_address);
    if (geo) {
      logData.country = geo.country;
      logData.region = geo.region;
      logData.asn = geo.asn;
      logData.organization = geo.organization;
    }
  }

  try {
    // Publish the log to RabbitMQ for asynchronous processing/storage
    await publishMessage('log_queue', logData);
    res.status(202).json({ message: 'Log accepted for processing.' });
  } catch (error) {
    console.error('Error ingesting log:', error);
    res.status(500).json({ message: 'Error ingesting log', error: error.message });
  }
};

// Get logs from MongoDB (with basic filtering/pagination)
exports.getLogs = async (req, res) => {
  const { level, source, event_type, search, ip_address, page = 1, limit = 20 } = req.query;
  const query = {};

  if (level) query.level = level;
  if (source) query.source = source;
  if (event_type) query.event_type = event_type;
  if (ip_address) query.ip_address = ip_address;

  if (search) {
    query.$or = [
      { message: { $regex: search, $options: 'i' } },
      { 'metadata.details': { $regex: search, $options: 'i' } }, // Example for metadata search
    ];
  }

  try {
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const logs = await Log.find(query)
      .sort({ timestamp: -1 }) // Sort by newest first
      .skip(skip)
      .limit(parseInt(limit));

    const totalLogs = await Log.countDocuments(query);

    res.status(200).json({
      data: logs,
      currentPage: parseInt(page),
      totalPages: Math.ceil(totalLogs / parseInt(limit)),
      totalLogs,
    });
  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({ message: 'Error fetching logs', error: error.message });
  }
};