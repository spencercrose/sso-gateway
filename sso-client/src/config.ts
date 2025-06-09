/**
 * This file is part of the BC Gov SSO Client.
 * @file config.ts
 * @description Configuration file for the SSO Client, which integrates with Keycloak for authentication.
 * @license MIT Licensed 2025
 * @author Government of British Columbia
 */

export interface AppConfig {
  HOSTNAME: string;
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
}

let config: AppConfig = {
      HOSTNAME: 'localhost',
      SSO_CLIENT_PORT: 3000,
      SSO_AUTH_SERVER_URL: 'keycloak.example.com',
      SSO_REALM: 'standard',
      SSO_CLIENT_ID: 'CLIENT_ID',
      SSO_CLIENT_SECRET: 'CLIENT_SECRET',
      SSO_REDIRECT_URL: 'http://localhost:3000/authn/callback',
      SSO_REDIS_SESSION_STORE_URL: 'redis://localhost:6379',
      SSO_REDIS_CONNECT_PASSWORD: '',
      SSO_SESSION_SECRET: 'SESSION_SECRET',
      SSO_LOGOUT_REDIRECT_URI: 'http://localhost:3000',
      SM_LOGOUT_URL: 'https://logon.gov.bc.ca/clp-cgi/logoff.cgi',
    };

// Get Keycloak multi-config JSON from environment variable
const appConfigJsonString = process.env.KEYCLOAK_MULTI_CONFIG_JSON;

if (appConfigJsonString) {
  try {
    const appConfig = JSON.parse(appConfigJsonString);

    console.log("App Hostname:", appConfig.hostname);
    console.log("Keycloak Auth Server URL:", appConfig.keycloak["auth-server-url"]);
    console.log("Keycloak Secret:", appConfig.keycloak.credentials.secret); // Note: Sensitive! Handle securely.

    // Assign values to config object, ensuring types are correct
    config = { 
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
  } catch (error) {
    console.error("Failed to parse KEYCLOAK_MULTI_CONFIG_JSON:", error);
    process.exit(1); // Exit if critical config can't be parsed
  }
} else {
  console.warn("KEYCLOAK_MULTI_CONFIG_JSON environment variable not found.");
}

export default config;