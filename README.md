#Secure Web Application Architecture with BC Government Keycloak SSO

Scalable NGINX-based reverse proxy architecture for web applications, with SSO client and session management. Can be integrated with the BC Government's Common Keycloak service for Single Sign-On (SSO).

## Table of Contents

1.  [Overview](https://www.google.com/search?q=%23overview)
2.  [Key Components](https://www.google.com/search?q=%23key-components)
      * [NGINX Reverse Proxy](https://www.google.com/search?q=%23nginx-reverse-proxy)
      * [BC Government Common Keycloak Service (OIDC)](https://www.google.com/search?q=%23bc-government-common-keycloak-service-oidc)
      * [Node.js Client Application](https://www.google.com/search?q=%23nodejs-client-application)
      * [Redis Session Store](https://www.google.com/search?q=%23redis-session-store)
3.  [Architecture Diagram](https://www.google.com/search?q=%23architecture-diagram)
4.  [Authentication and Session Flow](https://www.google.com/search?q=%23authentication-and-session-flow)
5.  [Benefits](https://www.google.com/search?q=%23benefits)
6.  [Setup Considerations](https://www.google.com/search?q=%23setup-considerations)
      * [BC Gov Keycloak Integration](https://www.google.com/search?q=%23bc-gov-keycloak-integration)
      * [NGINX Configuration](https://www.google.com/search?q=%23nginx-configuration)
      * [Node.js Application Configuration](https://www.google.com/search?q=%23nodejs-application-configuration)
      * [Redis Deployment](https://www.google.com/search?q=%23redis-deployment)
7.  [Security Best Practices](https://www.google.com/search?q=%23security-best-practices)

## 1\. Overview

This architecture is designed to provide a secure, high-performance, and scalable foundation for web applications. By utilizing NGINX as a reverse proxy, we centralize request handling, enable SSL termination, and facilitate load balancing. The Node.js application focuses on business logic, offloading authentication to the BC Government's Common Keycloak service via OpenID Connect (OIDC). User sessions are managed efficiently and externalized to Redis, allowing for seamless scaling and resilience.

## 2\. Key Components

### NGINX Reverse Proxy

  * **Role:** The public-facing entry point for all incoming requests.
  * **Functions:**
      * **SSL/TLS Termination:** Handles HTTPS encryption and decryption, offloading this CPU-intensive task from the Node.js application.
      * **Request Routing:** Directs incoming traffic to the appropriate Node.js application instances.
      * **Load Balancing:** Distributes requests across multiple Node.js application instances for improved performance and availability.
      * **Security Layer:** Provides an initial layer of defense against common web attacks and can rate-limit requests.
      * **Static Content Serving/Caching:** Can serve static assets directly or cache responses, reducing the load on the Node.js application.

### BC Government Common Keycloak Service (OIDC)

  * **Role:** The centralized Identity and Access Management (IAM) provider for BC Government applications.
  * **Functions:**
      * **Single Sign-On (SSO):** Allows users to authenticate once and gain access to multiple integrated BC Gov applications without re-authenticating.
      * **User Authentication:** Manages user credentials and performs secure authentication processes.
      * **Identity Provisioning:** Provides user identity information (via ID Tokens) and access control context (via Access Tokens) to the Node.js client.
      * **OpenID Connect (OIDC):** The standard protocol used for secure communication and identity verification between the Node.js client and Keycloak.

### Node.js Client Application

  * **Role:** The core business logic application.
  * **Functions:**
      * **OIDC Client:** Initiates authentication requests to Keycloak and processes the authorization codes/tokens returned.
      * **Session Management:** Creates and manages user sessions, storing essential session data (e.g., user ID, access token, refresh token) in Redis.
      * **Business Logic:** Executes the application's specific functionalities and serves dynamic content.
      * **API Endpoints:** Exposes APIs for frontend consumption.

### Redis Session Store

  * **Role:** An external, high-performance, in-memory data store for user sessions.
  * **Functions:**
      * **Centralized Session Storage:** Stores all active user sessions, accessible by any Node.js application instance.
      * **Scalability:** Enables horizontal scaling of Node.js instances without losing session state.
      * **Resilience:** Sessions persist even if a Node.js application instance crashes.
      * **Performance:** Extremely fast read/write operations for session data due to its in-memory nature.

## 3\. Architecture Diagram

```mermaid
graph TD
    subgraph Internet
        User_Browser
    end

    subgraph Your Application Infrastructure
        NGINX_Reverse_Proxy
        Load_Balancer(Load Balancer)
        subgraph Node.js Application Cluster
            NodeJS_App_1[Node.js App Instance 1]
            NodeJS_App_2[Node.js App Instance 2]
            NodeJS_App_N[Node.js App Instance N]
        end
        Redis_Session_Store
    end

    subgraph BC Government Services
        BC_Gov_Keycloak_Service(BC Gov Keycloak Service)
    end

    User_Browser -- HTTPS Request --> NGINX_Reverse_Proxy
    NGINX_Reverse_Proxy -- Proxy Pass --> Load_Balancer
    Load_Balancer -- Distribute Traffic --> NodeJS_App_1
    Load_Balancer -- Distribute Traffic --> NodeJS_App_2
    Load_Balancer -- Distribute Traffic --> NodeJS_App_N

    NodeJS_App_1 -- OIDC Authentication Request (Redirect) --> User_Browser
    User_Browser -- Authenticates --> BC_Gov_Keycloak_Service

    BC_Gov_Keycloak_Service -- OIDC Authorization Code (Redirect) --> User_Browser
    User_Browser -- OIDC Authorization Code --> NodeJS_App_1

    NodeJS_App_1 -- OIDC Token Exchange --> BC_Gov_Keycloak_Service
    BC_Gov_Keycloak_Service -- ID & Access Tokens --> NodeJS_App_1

    NodeJS_App_1 -- Store Session Data --> Redis_Session_Store
    NodeJS_App_2 -- Retrieve Session Data --> Redis_Session_Store
    NodeJS_App_N -- Retrieve Session Data --> Redis_Session_Store

    NodeJS_App_1 -- Set Session Cookie --> User_Browser
    User_Browser -- Subsequent Requests (with Session Cookie) --> NGINX_Reverse_Proxy
    NGINX_Reverse_Proxy -- Proxy Pass --> Load_Balancer
    Load_Balancer -- Distribute Traffic --> NodeJS_App_X[Node.js App Instance (any)]
    NodeJS_App_X -- Retrieve Session Data --> Redis_Session_Store
    NodeJS_App_X -- Application Response --> NGINX_Reverse_Proxy
    NGINX_Reverse_Proxy -- HTTPS Response --> User_Browser

```

## 4\. Authentication and Session Flow

1.  **Initial Request:** A user's browser sends an HTTPS request to your application's domain (e.g., `https://myapp.gov.bc.ca`).
2.  **NGINX Proxy:** NGINX receives the request, terminates SSL, and forwards it to a Node.js application instance (via a load balancer, if present).
3.  **Authentication Check (Node.js):** The Node.js application checks for an existing, valid session (e.g., via a session cookie).
4.  **Redirect to Keycloak:** If no valid session exists, the Node.js application initiates an OIDC authorization code flow by redirecting the user's browser to the BC Government's Keycloak login page, including `client_id`, `redirect_uri`, `scope`, and `response_type`.
5.  **Keycloak Authentication:** The user logs in to Keycloak using their BCeID or other supported credentials.
6.  **Authorization Code Grant:** Upon successful authentication, Keycloak redirects the user's browser back to the Node.js application's `redirect_uri` with an authorization code.
7.  **Token Exchange (Node.js):** The Node.js application receives the authorization code and exchanges it directly with Keycloak (server-to-server) for ID, Access, and Refresh Tokens. This exchange is secure and bypasses the user's browser.
8.  **Session Creation (Node.js & Redis):** The Node.js application validates the received tokens. It then creates a server-side session, storing relevant user details (from the ID Token), the Access Token, and the Refresh Token in Redis, associated with a unique session ID.
9.  **Session Cookie:** The Node.js application sends a `Set-Cookie` header to the user's browser containing the session ID (e.g., `connect.sid`). This cookie is typically `HttpOnly` and `Secure`.
10. **Authorized Access:** For all subsequent requests within the session, the user's browser sends the session ID cookie.
11. **Session Retrieval (Node.js & Redis):** The Node.js application retrieves the session data from Redis using the session ID from the cookie.
12. **Token Validation/Refresh:** The Node.js application validates the Access Token. If expired, it uses the Refresh Token to obtain new Access and ID Tokens from Keycloak without user re-authentication.
13. **Resource Access:** If the session and tokens are valid, the Node.js application grants access to the requested resources.

## 5\. Benefits

  * **Enhanced Security:** Centralized authentication via Keycloak reduces the attack surface. NGINX provides an additional layer of security.
  * **Single Sign-On (SSO):** Seamless user experience across multiple BC Government applications.
  * **Scalability:** Node.js application instances can be scaled horizontally without session conflicts due to Redis. NGINX can load balance across these instances.
  * **Performance:** NGINX handles SSL termination and can cache content, improving response times. Redis provides extremely fast session lookups.
  * **Maintainability:** Clear separation of concerns between proxy, application, and identity management.
  * **Compliance:** Leverages the BC Government's established and secure Keycloak service for identity management.

## 6\. Setup Considerations

### BC Gov Keycloak Integration

  * **Client Registration:** Your application must be registered as a client within the BC Government's Keycloak realm. You will need to obtain a `client_id` and `client_secret`.
  * **Redirect URIs:** Configure all valid `redirect_uri`s for your application in Keycloak (e.g., `https://myapp.gov.bc.ca/auth/callback`).
  * **Public/Confidential Client:** For Node.js (server-side), it's typically configured as a `confidential` client as it can securely store the `client_secret`.
  * **Scope:** Define the necessary OIDC scopes (e.g., `openid`, `profile`, `email`) your application requires.

### NGINX Configuration

  * **SSL/TLS:** Configure SSL certificates (e.g., from Let's Encrypt or BC Gov provided certificates) for your domain.
  * **Proxy Pass:** Set up `proxy_pass` directives to forward requests to your Node.js application instances (or a load balancer).
  * **HTTP Headers:** Ensure correct `X-Forwarded-For`, `X-Real-IP`, and `X-Forwarded-Proto` headers are passed to Node.js for accurate request context.
  * **Error Pages:** Configure custom error pages.

**Example NGINX Snippet (simplified):**

```nginx
server {
    listen 80;
    server_name myapp.gov.bc.ca;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name myapp.gov.bc.ca;

    ssl_certificate /etc/nginx/ssl/myapp.gov.bc.ca.crt;
    ssl_certificate_key /etc/nginx/ssl/myapp.gov.bc.ca.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5; # Ensure strong ciphers

    location / {
        proxy_pass http://localhost:3000; # Or your Node.js app's internal IP/port
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
    }
}
```

### Node.js Application Configuration

  * **OIDC Client Library:** Use a robust OIDC client library (e.g., `openid-client`, `passport-keycloak-oauth2`) to handle the OIDC flow.
  * **Environment Variables:** Store sensitive configuration like Keycloak `client_id`, `client_secret`, and Redis connection details as environment variables.
  * **Session Middleware:** Integrate a session management middleware (e.g., `express-session` with a Redis store like `connect-redis`).
  * **Token Management:** Implement logic to store, validate, and refresh Access Tokens using the Refresh Token.

**Example Node.js `express-session` with `connect-redis` (simplified):**

```javascript
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');

// Initialize Redis client
const redisClient = createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379'
});
redisClient.connect().catch(console.error);

// Initialize store
const redisStore = new RedisStore({
    client: redisClient,
    prefix: "myapp_session:",
});

app.use(session({
    store: redisStore,
    secret: process.env.SESSION_SECRET, // A strong, random secret
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true, // Requires HTTPS
        httpOnly: true, // Prevents client-side JS access
        maxAge: 3600000, // Session duration (e.g., 1 hour)
        sameSite: 'Lax' // Or 'Strict' depending on your needs
    }
}));
```

### Redis Deployment

  * **Persistent Storage:** Ensure Redis is deployed with persistent storage (e.g., AOF or RDB snapshots) to prevent session loss on restart.
  * **Security:** Secure your Redis instance (e.g., bind to specific IPs, use a strong password, disable dangerous commands if not needed).
  * **High Availability:** For production, consider a Redis High Availability setup (e.g., Redis Sentinel or Redis Cluster).

## 7\. Security Best Practices

  * **Always use HTTPS:** Enforce HTTPS for all traffic using NGINX.
  * **Strong Session Secrets:** Use long, random, and frequently rotated secrets for session management.
  * **Secure Cookies:** Mark session cookies as `HttpOnly`, `Secure`, and `SameSite` (Lax or Strict).
  * **Input Validation:** Sanitize and validate all user inputs to prevent injection attacks.
  * **Rate Limiting:** Implement rate limiting on NGINX to mitigate brute-force attacks.
  * **Regular Updates:** Keep all software components (NGINX, Node.js, Redis, libraries) updated to their latest stable versions.
  * **Least Privilege:** Configure permissions for your application and database users with the principle of least privilege.
  * **Logging and Monitoring:** Implement comprehensive logging and monitoring to detect and respond to security incidents.
  * **OWASP Top 10:** Familiarize yourself with and address the OWASP Top 10 security risks.

-----
