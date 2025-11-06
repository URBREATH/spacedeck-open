'use strict';
const { Issuer } = require('openid-client');
const db = require('../models/db');
const { v4: uuidv4 } = require('uuid');
const config = require('config');

let client;

async function initKeycloakClient() {
  if (!client) {
    const issuer = await Issuer.discover(config.keycloak.issuer);
    client = new issuer.Client({
      client_id: config.keycloak.client_id,
      client_secret: config.keycloak.client_secret,
      redirect_uris: [config.keycloak.redirect_uri],
      response_types: ['code'],
    });
  }
  return client;
}

async function keycloakCallback(req, res) {
  try {
    const client = await initKeycloakClient();
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(client.redirect_uris[0], params, {
      code_verifier: req.session?.codeVerifier
    });

    const idToken = tokenSet.claims();

    let user = await db.User.findOne({ where: { email: idToken.email } });

    if (!user) {
      user = await db.User.create({
        _id: uuidv4(),
        email: idToken.email,
        nickname: idToken.preferred_username || idToken.given_name,
        prefs_language: req.i18n?.locale || 'en',
        confirmation_token: null,
      });

      const homeFolder = await db.Space.create({
        _id: uuidv4(),
        name: req.i18n?.__('home') || 'Home',
        space_type: 'folder',
        creator_id: user._id,
      });

      user.home_folder_id = homeFolder._id;
      await user.save();
    }

    // salva sessione
    const token = uuidv4();
    await db.Session.create({
      token,
      user_id: user._id,
      ip: req.ip,
      device: "web",
      created_at: new Date()
    });

    if (req.session) {
      req.session.userId = user._id;
      req.session.idToken = tokenSet.id_token;
      await new Promise((resolve, reject) => {
        req.session.save((err) => (err ? reject(err) : resolve()));
      }).catch((err) => {
        console.warn("Impossibile salvare la sessione dopo il login Keycloak:", err);
      });
    }

    res.cookie('sdsession', token, { httpOnly: true });
    res.redirect('/spaces');
  } catch (err) {
    console.error('Errore Keycloak callback:', err);
    res.status(500).send('Errore durante il login');
  }
}

// Funzione per il logout
async function keycloakLogout(req, res) {
  try {
    const configuredEndpoint = config.get('endpoint');
    const configuredHost = (() => {
      try {
        return new URL(configuredEndpoint).hostname;
      } catch (err) {
        return null;
      }
    })();

    // Rimuoviamo la sessione utente e il cookie
    const token = req.cookies['sdsession'];
    if (token) {
      const session = await db.Session.findOne({ where: { token } });
      if (session) await session.destroy();
    }

    const idTokenHint = req.session?.idToken || null;
    const requestHost = req.hostname || (req.headers.host ? req.headers.host.split(':')[0] : null);
    const domain = process.env.NODE_ENV === "production"
      ? configuredHost
      : (requestHost || configuredHost);

    const clearCookieOptions = { path: '/' };
    if (domain && domain !== 'localhost') {
      clearCookieOptions.domain = domain;
    }
    res.clearCookie('sdsession', clearCookieOptions);

    if (req.session) {
      await new Promise((resolve) => {
        req.session.destroy((err) => {
          if (err) {
            console.error('Errore durante la distruzione della sessione express:', err);
          }
          resolve();
        });
      });
    }

    // Opzionale: Se Keycloak ha un endpoint per il logout, reindirizzare
    const client = await initKeycloakClient();
    const fallbackRedirect = configuredEndpoint || `${req.protocol}://${req.get('host')}`;
    let logoutUrl = fallbackRedirect;

    if (client) {
      const { issuer } = client;
      if (typeof client.endSessionUrl === 'function') {
        const params = {
          post_logout_redirect_uri: fallbackRedirect
        };
        if (idTokenHint) {
          params.id_token_hint = idTokenHint;
        }
        logoutUrl = client.endSessionUrl(params);
      } else if (issuer?.metadata?.end_session_endpoint) {
        const endSessionUrl = new URL(issuer.metadata.end_session_endpoint);
        endSessionUrl.searchParams.set('post_logout_redirect_uri', fallbackRedirect);
        if (idTokenHint) {
          endSessionUrl.searchParams.set('id_token_hint', idTokenHint);
        }
        logoutUrl = endSessionUrl.toString();
      }
    }

    res.redirect(logoutUrl || '/');

  } catch (err) {
    console.error('Errore logout:', err);
    res.status(500).send('Errore durante il logout');
  }
}

module.exports = { initKeycloakClient, keycloakCallback, keycloakLogout };
