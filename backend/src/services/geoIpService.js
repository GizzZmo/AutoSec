const geoip = require('geoip-lite');
const path = require('path');
const fs = require('fs');

// Path to the GeoLite2-City.mmdb file
const geoIpDbPath = process.env.GEOIP_DB_PATH || path.join(__dirname, '../../data/geoip/GeoLite2-City.mmdb');

// Check if the GeoIP database file exists
if (!fs.existsSync(geoIpDbPath)) {
  console.warn(`GeoIP database not found at ${geoIpDbPath}. GeoIP lookups will not work.`);
  console.warn('Please download GeoLite2-City.mmdb from MaxMind and place it in the data/geoip directory.');
  console.warn('You can get a free GeoLite2 database from: https://dev.maxmind.com/geoip/downloads/geolite2/ (requires registration)');
} else {
  // Load the database (geoip-lite handles this internally when lookup is called)
  // We just need to ensure the path is set if it's not default
  // geoip.set
  console.log(`GeoIP database loaded from: ${geoIpDbPath}`);
}

const lookup = (ip) => {
  if (!fs.existsSync(geoIpDbPath)) {
    return null; // Cannot perform lookup if DB is missing
  }
  const geo = geoip.lookup(ip);
  if (geo) {
    return {
      range: geo.range,
      country: geo.country,
      region: geo.region,
      city: geo.city,
      ll: geo.ll, // latitude, longitude
      metro: geo.metro,
      zip: geo.zip,
      asn: geo.asn, // Autonomous System Number
      organization: geo.organization, // Organization name
    };
  }
  return null;
};

module.exports = { lookup };