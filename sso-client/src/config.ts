
export interface AppConfig {
  SSO_CLIENT_PORT: number;
  SSO_AUTH_SERVER_URL: string;
  SSO_REALM: string;
  SSO_CLIENT_ID: string;
  SSO_CLIENT_SECRET: string;
  SSO_REDIRECT_URL: string;
  SSO_REDIS_SESSION_STORE_URL: string;
  SSO_REDIS_CONNECT_PASSWORD: string;
  SSO_SESSION_SECRET: string;
  SSO_LOGOUT_REDIRECT_URI: string; 
  SM_LOGOUT_URL: string;
  CLIENT_HOST: string; 
}

const config: AppConfig = { 
  SSO_CLIENT_PORT: Number(process.env.SSO_CLIENT_PORT) || 3000,
  SSO_AUTH_SERVER_URL: process.env.SSO_AUTH_SERVER_URL || 'YOUR_KEYCLOAK_URL',
  SSO_REALM: process.env.SSO_REALM || 'YOUR_REALM', // Defaulting to a string here
  SSO_CLIENT_ID: process.env.SSO_CLIENT_ID || 'YOUR_CLIENT_ID',
  SSO_CLIENT_SECRET: process.env.SSO_CLIENT_SECRET || 'YOUR_CLIENT_SECRET',
  SSO_REDIRECT_URL: process.env.SSO_REDIRECT_URL || 'http://localhost:3000/authn/callback',
  SSO_REDIS_SESSION_STORE_URL: process.env.SSO_REDIS_SESSION_STORE_URL || 'redis://localhost:6379',
  SSO_REDIS_CONNECT_PASSWORD: process.env.SSO_REDIS_CONNECT_PASSWORD || '', // Provide an empty string as default
  SSO_SESSION_SECRET: process.env.SSO_SESSION_SECRET || 'supersecret', // Provide a default string
  SSO_LOGOUT_REDIRECT_URI: process.env.SSO_LOGOUT_REDIRECT_URI || 'http://localhost:3000', // ADDED/FIXED
  SM_LOGOUT_URL: process.env.SM_LOGOUT_URL || 'https://logon.gov.bc.ca/clp-cgi/logoff.cgi',
  CLIENT_HOST: process.env.CLIENT_HOST || 'http://localhost:3000', // ADDED/FIXED
};

export default config;