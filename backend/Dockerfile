# Use an official Node.js runtime as a parent image
FROM node:20-alpine

# Security: run as non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json first (layer caching)
COPY package*.json ./

# Install production deps only, with npm ci for reproducible builds
RUN npm ci --only=production

# Copy the rest of the application code
COPY --chown=appuser:appgroup . .

# Create logs and uploads directories
RUN mkdir -p logs uploads && chown -R appuser:appgroup logs uploads

USER appuser

# Expose the port the app runs on
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Command to run the application
CMD ["node", "src/server.js"]