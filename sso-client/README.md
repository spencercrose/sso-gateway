# Node.js OpenID Connect Client for BC Government SSO

This is a Node.js implementation of an OpenID Connect (OIDC) client for the BC Government's Common Keycloak service.

## Features

*   Implements the Authorization Code Flow to authenticate users with the BC Government's SSO service.
*   Uses Redis as a high-performance session store to manage user sessions.
*   Exposes a REST API for authentication, logout, and session management.

## Getting Started

### Prerequisites

*   Node.js 16 or higher
*   npm (the package manager that comes with Node.js)
*   A Redis instance (for session storage)

### Installation

1.  Clone this repository.
2.  Install the dependencies: `npm install`
3.  Configure the environment variables (see below).
4.  Start the server: `npm start`

### Environment Variables

The following environment variables are required:

*   `SSO_BASE_URL`: The base URL of the BC Government's SSO service (e.g. <https://sso-dev.pathfinder.gov.bc.ca/>).
*   `SSO_REALM`: The realm of the BC Government's SSO service (e.g. `bcgov`).
*   `SSO_CLIENT_ID`: The client ID of your application in the BC Government's SSO service.
*   `SSO_CLIENT_SECRET`: The client secret of your application in the BC Government's SSO service.
*   `REDIS_HOST`: The hostname of your Redis instance.
*   `REDIS_PORT`: The port number of your Redis instance.
*   `REDIS_PASSWORD`: The password for your Redis instance.
*   `SESSION_SECRET`: A secret key for encrypting session data.

### API Endpoints

The following endpoints are exposed:

*   `GET /authn`: Redirects the user to the BC Government's SSO service for authentication.
*   `GET /logout`: Logs the user out of the application.
*   `GET /session`: Returns the user's session data.

### Usage

The application can be used as a backend for a web application or as a standalone service.

For example, to use the application as a backend for a web application:

1.  The user requests a protected resource (e.g. a web page).
2.  The web application redirects the user to the `/authn` endpoint.
3.  The user is redirected to the BC Government's SSO service for authentication.
4.  After authentication, the user is redirected back to the web application with an authorization code.
5.  The web application exchanges the authorization code for an access token.
6.  The web application stores the access token in the user's session.
7.  The web application uses the access token to access the protected resource.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
