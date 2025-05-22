# Stage 1: Build the Node.js application
FROM node:23-alpine AS builder

# Set working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json first to leverage Docker cache
# This means npm install only runs if these files change
COPY package.json package-lock.json ./

# Install dependencies
RUN npm ci --omit=dev

# Copy the rest of the application code
COPY . .

# Build the application if it has a build step (e.g., frontend frameworks)
# RUN npm run build # Uncomment if you have a build script

# Stage 2: Create the final production image
# Use a slimmed-down Node.js image for production
FROM node:23-alpine

# Set working directory inside the container
WORKDIR /app

# Ensure non-root user for OpenShift compatibility
# The 'node' user exists by default in official Node.js images
# and usually has UID 1000. OpenShift will run with an arbitrary UID.
# We ensure the /app directory is owned by the 'node' user.
RUN chown -R node:node /app
USER node

# Copy only the necessary files from the builder stage
# This keeps the final image small and secure
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/*.js ./ 
COPY --from=builder /app/package.json ./ 
# Add other necessary application files/folders (e.g., 'dist/', 'src/', 'public/')
# For example:
# COPY --from=builder /app/dist ./dist
# COPY --from=builder /app/public ./public

# Expose the port  Node.js app listens on
EXPOSE 3000

# Command to run the application
CMD ["npm", "start"]