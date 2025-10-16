'use strict';

const db = require('./models/db.js');
require("log-timestamp");

const config = require('config');
const redis = require('./helpers/redis');
const websockets = require('./helpers/websockets');

const http = require('http');
const path = require('path');

const favicon = require('serve-favicon');
const logger = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

const i18n = require('i18n-2');
const express = require('express');
const session = require('express-session');
const serveStatic = require('serve-static');

const { initKeycloakClient, keycloakCallback } = require('./middlewares/keycloak_auth');

const app = express();
const isProduction = app.get('env') === 'production';

// -------------------- SESSION --------------------
app.use(session({
  secret: config.keycloak.session_secret || 'superSecret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // in dev su http
}));

// -------------------- POPOLA req.user --------------------
app.use(async (req, res, next) => {
  if (req.session?.userId) {
    const user = await db.User.findOne({ where: { _id: req.session.userId } });
    if (user) req.user = user;
  }
  next();
});

// -------------------- KEYCLOAK --------------------
// login su /keycloak
app.get('/keycloak', async (req, res) => {
  try {
    if (req.user) return res.redirect('/spaces'); // già loggato

    const client = await initKeycloakClient();
    const authUrl = client.authorizationUrl({
      scope: 'openid email profile',
      response_mode: 'query',
    });

    res.redirect(authUrl);
  } catch (err) {
    console.error('Errore Keycloak login:', err);
    res.status(500).send('Errore Keycloak login');
  }
});

// callback Keycloak
app.get('/callback', keycloakCallback);

// -------------------- LOGGER --------------------
app.use(logger(isProduction ? 'combined' : 'dev'));

// -------------------- i18n --------------------
i18n.expressBind(app, {
  locales: ["de", "en", "es", "fr", "hu", "oc"],
  defaultLocale: "en",
  cookieName: "spacedeck_locale",
  devMode: (app.get('env') === 'development')
});

app.set('view engine', 'ejs');

if (isProduction) {
  app.set('views', path.join(__dirname, 'build', 'views'));
  app.use(favicon(path.join(__dirname, 'build', 'assets', 'images', 'favicon.png')));
  app.use(express.static(path.join(__dirname, 'build', 'assets')));
} else {
  app.set('views', path.join(__dirname, 'views'));
  app.use(favicon(path.join(__dirname, 'public', 'images', 'favicon.png')));
  app.use(express.static(path.join(__dirname, 'public')));
}

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: false, limit: '50mb' }));
app.use(cookieParser());
app.disable('x-powered-by');

app.use(require("./middlewares/session"));
app.use(require("./middlewares/i18n"));
app.use("/api", require("./middlewares/api_helpers"));
app.use('/api/spaces/:id', require("./middlewares/space_helpers"));
app.use('/api/spaces/:id/artifacts/:artifact_id', require("./middlewares/artifact_helpers"));

app.use('/api/users', require('./routes/api/users'));
app.use('/api/memberships', require('./routes/api/memberships'));

const spaceRouter = require('./routes/api/spaces');
app.use('/api/spaces', spaceRouter);

spaceRouter.use('/:id/artifacts', require('./routes/api/space_artifacts'));
spaceRouter.use('/:id/memberships', require('./routes/api/space_memberships'));
spaceRouter.use('/:id/messages', require('./routes/api/space_messages'));
spaceRouter.use('/:id/digest', require('./routes/api/space_digest'));
spaceRouter.use('/:id', require('./routes/api/space_exports'));

app.use('/api/sessions', require('./routes/api/sessions'));

// -------------------- ROUTE PRINCIPALE --------------------
app.use('/', require('./routes/root'));

// -------------------- STORAGE --------------------
if (config.get('storage_local_path')) {
  app.use('/storage', serveStatic(config.get('storage_local_path')+"/"+config.get('storage_bucket'), {
    maxAge: 24*3600
  }));
}

// -------------------- ROUTE PROTETTE E LOGIN --------------------
function requireLogin(req, res, next) {
  if (!req.user) return res.redirect('/keycloak');
  next();
}

// esempio: proteggi /spaces
app.get('/spaces', requireLogin, (req, res) => {
  res.render('spaces', { user: req.user });
});

// -------------------- ERRORI --------------------
if (app.get('env') === 'development') {
  app.set('view cache', false);
} else {
  app.use(require('./middlewares/500'));
}

// -------------------- DATABASE --------------------
db.init();

// -------------------- WEBSERVER --------------------
const host = config.get('host');
const port = config.get('port');

const server = http.Server(app).listen(port, host, () => {
  if ("send" in process) process.send('online');
}).on('listening', () => {
  const host = server.address().address;
  const port = server.address().port;
  console.log('Spacedeck Open listening at http://%s:%s', host, port);
}).on('error', (error) => {
  if (error.syscall !== 'listen') throw error;
  const bind = typeof port === 'string' ? 'Pipe ' + port : 'Port ' + port;
  switch (error.code) {
    case 'EACCES':
      console.error(bind + ' requires elevated privileges');
      process.exit(1);
      break;
    case 'EADDRINUSE':
      console.error(bind + ' is already in use');
      process.exit(1);
      break;
    default:
      throw error;
  }
});

websockets.startWebsockets(server);
redis.connectRedis();

module.exports = app;
