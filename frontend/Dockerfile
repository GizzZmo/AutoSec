# Stage 1: Build the React application
FROM node:20-alpine as build-stage

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Stage 2: Serve the application with Nginx
FROM nginx:stable-alpine as production-stage

# Copy the build output from the build stage
COPY --from=build-stage /app/build /usr/share/nginx/html

# Copy custom Nginx configuration (optional, for more advanced setups)
# COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]