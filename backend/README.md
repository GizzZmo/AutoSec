# AutoSec Backend

This is the backend service for the AutoSec cybersecurity application. It provides APIs for managing dynamic IP blocklist rules, ingesting telemetry logs, and interfacing with the database and message broker infrastructure.

## Technology Stack

- **Node.js** with **Express.js** for the web framework
- **PostgreSQL** for structured data (blocklist rules)
- **MongoDB** for unstructured data (logs and telemetry)
- **RabbitMQ** for asynchronous message processing
- **Sequelize** ORM for PostgreSQL interactions
- **Mongoose** ODM for MongoDB interactions

## API Endpoints

### Rule Management
- `GET /api/rules` - Get all blocklist rules
- `POST /api/rules` - Create a new blocklist rule
- `PUT /api/rules/:id` - Update a blocklist rule
- `DELETE /api/rules/:id` - Delete a blocklist rule

### Log Management
- `POST /api/logs` - Ingest a new log entry
- `GET /api/logs` - Retrieve logs with filtering and pagination

### Utilities
- `GET /api/geoip?ip=<IP_ADDRESS>` - Get GeoIP information for an IP address
- `GET /health` - Health check endpoint

## Environment Variables

Copy `.env.example` to `.env` and configure the following variables:

- `PORT` - Server port (default: 8080)
- `PG_HOST` - PostgreSQL host
- `PG_PORT` - PostgreSQL port
- `PG_USER` - PostgreSQL username
- `PG_PASSWORD` - PostgreSQL password
- `PG_DATABASE` - PostgreSQL database name
- `MONGO_URI` - MongoDB connection string
- `RABBITMQ_URL` - RabbitMQ connection string
- `GEOIP_DB_PATH` - Path to GeoLite2-City.mmdb file

## Running Locally

1. Ensure PostgreSQL, MongoDB, and RabbitMQ are running
2. Install dependencies: `npm install`
3. Copy and configure environment: `cp .env.example .env`
4. Start the server: `npm run dev` (development) or `npm start` (production)

## Docker

Build and run using Docker:

```bash
docker build -t autosec-backend .
docker run -p 8080:8080 autosec-backend
```

Or use with docker-compose from the root directory.