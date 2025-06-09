/**
 * This file is part of the BC Gov SSO Client.
 * @file config.ts
 * @description Configuration file for the SSO Client, which integrates with Keycloak for authentication.
 * @license MIT Licensed 2025
 * @author Government of British Columbia
 */

import fs from 'fs';

export interface SSOConfig {
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

// Default path for the configuration secrets file injected by Vault
const configFilePath = process.env.VAULT_CONFIG_PATH || "/vault/secrets/secrets";

if (!fs.existsSync(configFilePath)) {
  console.error(`Configuration file not found at path: ${configFilePath}`);
  process.exit(1);
}

/**
 * Load and parse the JSON configuration file.
     * Structure:
     *  - hostname
     *  - keycloak:
     *    - confidential-port
     *    - auth-server-url
     *    - realm
     *    - ssl-required
     *    - client-id
     *    - client-secret
     */
function loadAndParseJSON(filePath: string) {
  try {
    const fileContent = fs.readFileSync(filePath, 'utf8');
    const configData = JSON.parse(fileContent);
    console.log("Parsed JSON:", configData);

    // Merge the loaded config data with the appConfig
    let config: SSOConfig = {
      HOSTNAME: configData['hostname'] || 'localhost',
      SSO_CLIENT_PORT: Number(process.env.SSO_CLIENT_PORT) || 3000,
      SSO_AUTH_SERVER_URL: configData['keycloak']?.['auth-server-url'] || 'localhost/auth',
      SSO_REALM: configData['keycloak']?.realm || 'standard',
      SSO_CLIENT_ID: configData['keycloak']?.['client-id'] || 'sso-client',
      SSO_CLIENT_SECRET: configData['keycloak']?.['client-secret'] || 'client-secret',
      SSO_REDIRECT_URL: process.env.REDIRECT_URL || 'http://localhost:8080/authn/callback',
      SSO_REDIS_SESSION_STORE_URL: process.env.REDIS_STORE_URL || 'redis://localhost:6379',
      SSO_REDIS_CONNECT_PASSWORD: process.env.REDIS_CONNECT_PASSWORD || '',
      SSO_SESSION_SECRET: process.env.SSO_SESSION_SECRET || '',
      SSO_LOGOUT_REDIRECT_URI: 'https://gov.bc.ca',
      SM_LOGOUT_URL: 'https://logon.gov.bc.ca/clp-cgi/logoff.cgi',
    };

    return config;
  } catch (error) {
    console.error("Error loading or parsing JSON:", error);
  }
}

export default loadAndParseJSON(configFilePath);