# Use an official Node.js runtime as a parent image
FROM node:24-alpine

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json (if any)
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Expose the port the app runs on
EXPOSE 8080

# Mount GeoIP data volume (will be mounted by docker-compose/k8s)
# VOLUME /app/data/geoip

# Command to run the application
CMD ["npm", "start"]