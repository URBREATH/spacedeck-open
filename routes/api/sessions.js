"use strict";

const config = require("config");
const db = require("../../models/db");
const { v4: uuidv4 } = require("uuid");

const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { URL } = require("url");

const express = require("express");
const router = express.Router();

async function ensureKeycloakUser({ email, name, language, req }) {
  if (!email) {
    throw new Error("missing_email");
  }

  const normalizedEmail = email.toLowerCase();
  let user = await db.User.findOne({ where: { email: normalizedEmail } });

  if (!user) {
    user = await db.User.create({
      _id: uuidv4(),
      email: normalizedEmail,
      nickname: name || normalizedEmail,
      prefs_language: language || (req?.i18n?.locale ?? "en"),
      confirmation_token: null,
    });

    const homeFolder = await db.Space.create({
      _id: uuidv4(),
      name: (req?.i18n && typeof req.i18n.__ === "function") ? req.i18n.__("home") : "Home",
      space_type: "folder",
      creator_id: user._id,
    });

    user.home_folder_id = homeFolder._id;
    await user.save();
  } else {
    let shouldSave = false;

    if (!user._id) {
      user._id = uuidv4();
      shouldSave = true;
    }

    if (!user.nickname && name) {
      user.nickname = name;
      shouldSave = true;
    }

    if (!user.home_folder_id) {
      const homeFolder = await db.Space.create({
        _id: uuidv4(),
        name: (req?.i18n && typeof req.i18n.__ === "function") ? req.i18n.__("home") : "Home",
        space_type: "folder",
        creator_id: user._id,
      });
      user.home_folder_id = homeFolder._id;
      shouldSave = true;
    }

    if (language && user.prefs_language !== language) {
      user.prefs_language = language;
      shouldSave = true;
    }

    if (shouldSave) {
      await user.save();
    }
  }

  return user;
}

function isSecureRequest(req) {
  if (req.secure) return true;
  const forwardedProto = req.headers["x-forwarded-proto"];
  if (forwardedProto) {
    return forwardedProto.split(",")[0].trim().toLowerCase() === "https";
  }
  return false;
}

async function createSessionForUser(req, res, user, options = {}) {
  const token = crypto.randomBytes(48).toString("hex");

  await db.Session.create({
    token,
    user_id: user._id,
    ip: req.ip,
    device: "web",
    created_at: new Date(),
  });

  if (req.session) {
    req.session.userId = user._id;
    if (typeof req.session.save === "function") {
      await new Promise((resolve, reject) => {
        req.session.save((err) => (err ? reject(err) : resolve()));
      }).catch(() => {});
    }
  }

  const domain =
    process.env.NODE_ENV === "production"
      ? new URL(config.get("endpoint")).hostname
      : req.hostname || req.headers.hostname || "localhost";

  const cookieOptions = {
    httpOnly: true,
    path: "/",
  };

  if (domain && domain !== "localhost") {
    cookieOptions.domain = domain;
  }

  const secure = isSecureRequest(req);
  const hostname = (req.hostname || "").toLowerCase();
  const isLocalHost = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
  const allowCrossSite = options.allowCrossSite === true;

  if (allowCrossSite) {
    cookieOptions.sameSite = "none";
    if (secure || !isLocalHost) {
      cookieOptions.secure = true;
    } else {
      cookieOptions.secure = false;
    }
  } else {
    cookieOptions.sameSite = "lax";
    cookieOptions.secure = secure;
  }

  res.cookie("sdsession", token, cookieOptions);

  const userJson = user.toJSON ? user.toJSON() : { ...user };
  delete userJson.password_hash;
  delete userJson.password_reset_token;
  delete userJson.confirmation_token;

  return {
    user: userJson,
    session: {
      token,
    },
  };
}

function decodeJwt(token) {
  if (!token || typeof token !== "string") return {};
  const parts = token.split(".");
  if (parts.length < 2) return {};

  try {
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4 || 4)) % 4);
    const json = Buffer.from(padded, "base64").toString("utf8");
    return JSON.parse(json);
  } catch (err) {
    console.error("Unable to decode JWT payload:", err.message);
    return {};
  }
}

/**
 * LOGIN locale (email + password)
 */
router.post("/", function (req, res) {
  var data = req.body;
  if (!data.email || !data.password) {
    res.status(400).json({});
    return;
  }

  var email = req.body.email.toLowerCase();
  var password = req.body["password"];

  db.User.findOne({ where: { email: email } })
    .catch((err) => {
      res.sendStatus(404);
    })
    .then((user) => {
      if (!user) {
        res.sendStatus(404);
      } else if (bcrypt.compareSync(password, user.password_hash)) {
        crypto.randomBytes(48, function (ex, buf) {
          var token = buf.toString("hex");

          var session = {
            user_id: user._id,
            token: token,
            ip: req.ip,
            device: "web",
            created_at: new Date(),
          };

          db.Session.create(session)
            .catch((err) => {
              console.error("Error creating Session:", err);
              res.sendStatus(500);
            })
            .then(() => {
              var domain =
                process.env.NODE_ENV == "production"
                  ? new URL(config.get("endpoint")).hostname
                  : req.headers.hostname;
              res.cookie("sdsession", token, { domain: domain, httpOnly: true });
              res.status(201).json(session);
            });
        });
      } else {
        res.sendStatus(403);
      }
    });
});

/**
 * LOGIN via Keycloak → crea utente se non esiste + home folder
 */
router.post("/keycloak", async function (req, res) {
  try {
    const { email, name, language } = req.body;
    if (!email) {
      return res.status(400).json({ error: "missing_email" });
    }

    const user = await ensureKeycloakUser({ email, name, language, req });
    const payload = await createSessionForUser(req, res, user);

    res.status(201).json(payload);
  } catch (err) {
    console.error("Errore login Keycloak:", err);
    res.sendStatus(500);
  }
});

/**
 * LOGIN via Keycloak access token (postMessage embedding)
 */
router.post("/keycloak/token", async function (req, res) {
  try {
    const {
      accessToken,
      refreshToken,
      language,
      email: bodyEmail,
      name: bodyName,
      profile,
    } = req.body || {};

    if (!accessToken) {
      return res.status(400).json({ error: "missing_access_token" });
    }

    console.log('[Keycloak Token] incoming body:', JSON.stringify(req.body || {}));

    const decodedClaims = decodeJwt(accessToken);
    console.log('[Keycloak Token] decoded claims:', decodedClaims ? { email: decodedClaims.email, preferred_username: decodedClaims.preferred_username } : null);

    console.log('[Keycloak Token] incoming email/name', bodyEmail, bodyName);

    const computedEmail =
      (bodyEmail ||
        decodedClaims.email ||
        decodedClaims.preferred_username ||
        "").toLowerCase();

    if (!computedEmail) {
      return res.status(400).json({ error: "missing_email" });
    }

    const displayName =
      bodyName ||
      decodedClaims.name ||
      decodedClaims.preferred_username ||
      decodedClaims.given_name ||
      decodedClaims.family_name ||
      computedEmail;

    const user = await ensureKeycloakUser({
      email: computedEmail,
      name: displayName,
      language: language || decodedClaims.locale,
      req,
    });

    console.log('[Keycloak Token] resolved user:', user ? { id: user._id, email: user.email, home_folder_id: user.home_folder_id } : null);

    const payload = await createSessionForUser(req, res, user, {
      allowCrossSite: true,
    });

    if (refreshToken) {
      payload.session.refreshToken = refreshToken;
    }

    if (profile) {
      payload.profile = profile;
    }

    res.status(201).json(payload);
  } catch (err) {
    console.error("Errore login Keycloak token:", err);
    res.sendStatus(500);
  }
});

/**
 * LOGOUT (locale + pulizia cookie)
 */
router.delete("/current", function (req, res, next) {
  if (req.user) {
    var token = req.cookies["sdsession"];

    db.Session.findOne({ where: { token: token } })
      .then((session) => {
        if (session) {
          session.destroy();
        }
      })
      .catch((err) => {
        console.error("Error destroying session:", err);
      });

    var domain =
      process.env.NODE_ENV == "production"
        ? new URL(config.get("endpoint")).hostname
        : req.headers.hostname;
    res.clearCookie("sdsession", { domain: domain, path: "/" });

    res.sendStatus(204);
  } else {
    res.sendStatus(404);
  }
});

module.exports = router;
