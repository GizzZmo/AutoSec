# MongoDB Setup

MongoDB is used for storing logs and telemetry data. As a NoSQL document database, it does not require a predefined schema file like PostgreSQL. The schema is defined within the Node.js application's `backend/src/models/Log.js` file.

When the `autosec-mongodb` service starts via Docker Compose, it will create the `autosec_logs` database automatically upon the first connection and data insertion from the backend.

No manual initialization script is typically needed for MongoDB in this setup.