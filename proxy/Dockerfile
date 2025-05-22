# Use the official NGINX stable image
FROM nginx:1.25-alpine

# Set working directory
WORKDIR /etc/nginx

# Remove default NGINX configuration
# We will not directly copy our nginx.conf into conf.d/default.conf
# Instead, we'll create a dedicated directory for ConfigMap mounting
RUN rm /etc/nginx/conf.d/default.conf

# Create a directory to hold the ConfigMap mounted configuration
RUN mkdir -p /etc/nginx/conf.d/external
# Ensure the nginx user has permissions to read from this directory (it will)
# NGINX's default run user 'nginx' needs to read from /etc/nginx/conf.d/external
# The base image ensures this is fine.

# Modify the main NGINX configuration to include files from the new directory
# This typically means adding an 'include' directive in /etc/nginx/nginx.conf
# However, the default NGINX Docker image already has 'include /etc/nginx/conf.d/*.conf;'
# So, we'll just mount our config *as* default.conf into the external directory.
# This means our ConfigMap will provide the *content* of default.conf.

# Ensure non-root user for OpenShift compatibility
# NGINX runs as 'nginx' user by default (UID 101).
# We ensure the logs and cache directories are writable.
RUN chown -R nginx:nginx /var/cache/nginx /var/run /var/log/nginx && \
    chmod -R 755 /var/cache/nginx /var/run /var/log/nginx

USER nginx

# Expose HTTP (and HTTPS if you terminate SSL at NGINX)
EXPOSE 8080 
# EXPOSE 8443 # If you are terminating HTTPS here

# CMD ["nginx", "-g", "daemon off;"] # This is the default CMD of the base image and works