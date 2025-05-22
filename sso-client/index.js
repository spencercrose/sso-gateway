/**
 * @file Server application to authenticate and manage user sessions using SSO
 * @module index
 * @license MIT Licensed 2025
 *
 * @description
 * This application acts as a **confidential OpenID Connect (OIDC) client** for the
 * **BC Government's Common Keycloak service**. It implements the **Authorization Code Flow**
 * to securely authenticate users and manage their sessions.
 *
 * All incoming requests are routed via an **NGINX reverse proxy**, which handles SSL/TLS termination
 * and potentially load balancing. User session data is externalized and managed using **Redis**
 * as a high-performance session store, enabling statelessness and horizontal scalability for
 * the Node.js application instances.
 *
 * This setup ensures robust security, seamless Single Sign-On (SSO) with other
 * BC Government applications, and efficient resource management.
 *
 * @see {@link https://openid.net/specs/openid-connect-core-1_0.html|OpenID Connect Core 1.0}
 * @see {@link https://www.keycloak.org/|Keycloak Official Website}
 * @see {@link https://nginx.org/|NGINX Official Website}
 * @see {@link https://redis.io/|Redis Official Website}
 *
 * @version 1.0.0
 * @author Government of British Columbia
 */

// Your application code starts here
// const express = require('express');
// const session = require('express-session');
// ...

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import session from 'express-session';
import passport from 'passport';
import { Issuer, Strategy } from 'openid-client';
import redis from 'redis';
import RedisStore from "connect-redis";
import cookieParser from "cookie-parser";
import 'dotenv/config';

// optional load of .env
dotenv.config();

// Application port
const port = process.env.SSO_CLIENT_PORT || 3000;

/**
 * Loads OpenID Connect 1.0 documents. When the issuer 
 * argument contains '.well-known' only that document is loaded, 
 * otherwise performs both openid-configuration and 
 * oauth-authorization-server requests.
 * 
 * This is the recommended method of getting yourself an Issuer instance.
 * - issuer: <string> Issuer Identifier or metadata URL
 * - Returns: Promise<Issuer>
 */

const keycloakIssuer = await Issuer.discover(
  `${process.env.SSO_AUTH_SERVER_URL}/auth/realms/${process.env.SSO_REALM}/.well-known/openid-configuration`,
);

/**
 * Returns the <Client> class tied to the Keycloak issuer.
 */

const keycloakClient = new keycloakIssuer.Client({
  client_id: process.env.SSO_CLIENT_ID,
  client_secret: process.env.SSO_CLIENT_SECRET,
  redirect_uris: [process.env.SSO_REDIRECT_URL],
  response_types: ['code'],
});

// Initialize Redis client for session store
let redisClient = redis.createClient({
  url: process.env.SSO_REDIS_SESSION_STORE_URL,
  password: process.env.SSO_REDIS_CONNECT_PASSWORD
});
redisClient.on('error', function (err) {
  console.log('Could not establish a connection with redis. ' + err);
});
redisClient.on('connect', function (err) {
  console.log('Connected to redis session store successfully');
});
redisClient.connect().catch(console.error);

// configure CORS allowed hostnames
const allowedOrigins = [
  process.env.SSO_BASE_URL,
  process.env.SSO_REDIS_SESSION_STORE_URL,
  process.env.SSO_AUTH_SERVER_URL
];

// CORS configuration settings
const corsConfig = {
  origin: allowedOrigins,
  methods: ["GET", "POST"],
  credentials: true,
  optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
};

// create express application
const app = express();

// Allow CORS requests from the specified CLIENT_HOST
const corsOptions = {
  origin: [process.env.CLIENT_HOST],
};

app.use(cors(corsConfig));

// Set up Helmet for security
app.use(helmet());

// include before other routes
app.options('*', cors(corsOptions));

// Set up Morgan for logging
const loggingFormat = ':method :url :status :res[content-length] - :response-time ms';
app.use(morgan(loggingFormat));

// app.use(helmet({contentSecurityPolicy: false}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.disable("x-powered-by");

// 'trust proxy' = truthy to handle undefined forwarded proxy
// ref: https://expressjs.com/en/guide/behind-proxies.html
app.set("trust proxy", 1);

// Configure session middleware
// - connects to Redis store for sessions
app.use(session({
  store: new RedisStore({
    client: redisClient,
  }),
  secret: process.env.SSO_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // if true only transmit cookie over https
    maxAge: 1000 * 60 * 60 * 24 // 1 day expiration 
  }
}));
// parse cookies to store session data
app.use(cookieParser(process.env.SSO_SESSION_SECRET));

/**
 * Configure passport
 * Returns the <Client> class tied to the Keycloak issuer.
 */

app.use(passport.initialize());
app.use(passport.session());

// scope token claims for logout
let tokenset = {};

passport.use(
  'oidc',
  new Strategy({ client: keycloakClient }, (tokenSet, userinfo, done) => {
    tokenset = tokenSet
    return done(null, tokenSet.claims());
  }),
);
passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});

/**
* Route: Authentication (Keycloak SSO-CSS)
*/

app.get('/authn', (req, res, next) => {
  const redirectURL = req.query.relay || '/';
  req.session.redirectURL = redirectURL;
  passport.authenticate('oidc')(req, res, next);
});

/**
* Route: Callback for authentication redirection
*/

app.get('/authn/callback', (req, res, next) => {
  passport.authenticate('oidc', {
    successRedirect: `https://${req.headers.host}${req.session.redirectURL}`,
    failureRedirect: '/',
  })(req, res, next);
});

/**
* Route: Return response status of application
*/

app.get('/health', (req, res) => {
  return res.sendStatus(200);
});

/**
* Route: Logout SSO Keycloak session
*/

app.get('/logout', (req, res, next) => {
  req.session.destroy();
  const retUrl = `${process.env.SSO_AUTH_SERVER_URL}/auth/realms/${process.env.SSO_REALM
    }/protocol/openid-connect/logout?post_logout_redirect_uri=${encodeURIComponent(
      process.env.SSO_LOGOUT_REDIRECT_URI,
    )}&id_token_hint=${tokenset.id_token}`;
  res.redirect(`https://logon7.gov.bc.ca/clp-cgi/logoff.cgi?retnow=1&returl=${encodeURIComponent(retUrl)}`);
});

/**
   * Route: Authorize user session
   * - callback for NGINX auth_request: status 2xx = Good, 4xx = Bad.
   */

app.get('/', (req, res) => {
  return res.sendStatus(req.isAuthenticated() ? 200 : 401);
});

// API endpoint for readiness check
app.get('/health', async (_, res) => {
  res.status(200).send({ status: 'OK' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send({ error: 'Internal Server Error' });
});

// 404 handler
app.use((req, res, next) => {
  res.status(404).send({ error: 'Not Found' });
});

/**
* Client listens on defined port
*/

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
  console.log(`Client host at ${process.env.CLIENT_HOST}`);
});


