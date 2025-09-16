# AutoSec Frontend

This is the frontend application for the AutoSec cybersecurity operations console. It provides a web-based user interface for managing dynamic IP blocklists, viewing telemetry logs, and monitoring system status.

## Technology Stack

- **React.js** for the user interface framework
- **React Router** for client-side routing
- **Axios** for API communication
- **CSS3** with a cyberpunk-inspired theme

## Features

- **Dashboard**: Overview of system status, active rules, and recent activity
- **Dynamic Blocklist**: Manage IP blocking rules (single IPs, ranges, countries, organizations)
- **Telemetry Logs**: View and filter ingested logs with pagination
- **Responsive Design**: Cyberpunk-themed UI optimized for security operations

## Available Scripts

- `npm start` - Runs the app in development mode
- `npm run build` - Builds the app for production
- `npm test` - Launches the test runner
- `npm run eject` - Ejects from Create React App (one-way operation)

## Environment Variables

- `REACT_APP_API_BASE_URL` - Backend API base URL (default: http://localhost:8080/api)

## Running Locally

1. Install dependencies: `npm install`
2. Start the development server: `npm start`
3. Open http://localhost:3000 in your browser

## Docker

Build and run using Docker:

```bash
docker build -t autosec-frontend .
docker run -p 3000:80 autosec-frontend
```

The Docker build uses a multi-stage process:
1. Build the React app using Node.js
2. Serve the built files using Nginx

## Project Structure

- `src/components/` - Reusable React components
- `src/pages/` - Main page components
- `src/services/` - API service modules
- `src/App.js` - Main application component
- `src/index.css` - Global styles and theme
- `public/` - Static assets