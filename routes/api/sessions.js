"use strict";

const config = require("config");
const db = require("../../models/db");
const { v4: uuidv4 } = require("uuid");

const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { URL } = require("url");

const express = require("express");
const router = express.Router();

function resolveCookieDomain(req) {
  if (process.env.NODE_ENV === "production") {
    return new URL(config.get("endpoint")).hostname;
  }
  return req.headers.hostname;
}

/**
 * LOGIN locale (email + password)
 */
router.post("/", function (req, res) {
  const data = req.body;
  if (!data.email || !data.password) {
    res.status(400).json({});
    return;
  }

  const email = req.body.email.toLowerCase();
  const password = req.body["password"];

  db.User.findOne({ where: { email: email } })
    .catch(() => {
      res.sendStatus(404);
    })
    .then((user) => {
      if (!user) {
        res.sendStatus(404);
        return;
      }

      if (!bcrypt.compareSync(password, user.password_hash)) {
        res.sendStatus(403);
        return;
      }

      crypto.randomBytes(48, function (ex, buf) {
        if (ex) {
          console.error("Error generating session token:", ex);
          res.sendStatus(500);
          return;
        }

        const token = buf.toString("hex");
        const session = {
          user_id: user._id,
          token,
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
            const domain = resolveCookieDomain(req);
            res.cookie("sdsession", token, { domain: domain, httpOnly: true });
            res.status(201).json(session);
          });
      });
    });
});

/**
 * LOGIN via Keycloak → crea utente se non esiste + home folder
 */
router.post("/keycloak", async function (req, res) {
  try {
    const { email, name, language } = req.body || {};
    if (!email) {
      return res.status(400).json({ error: "missing_email" });
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
        name: (req?.i18n && typeof req.i18n.__ === "function")
          ? req.i18n.__("home")
          : "Home",
        space_type: "folder",
        creator_id: user._id,
      });

      user.home_folder_id = homeFolder._id;
      await user.save();
    }

    const token = crypto.randomBytes(48).toString("hex");
    const session = await db.Session.create({
      user_id: user._id,
      token,
      ip: req.ip,
      device: "web",
      created_at: new Date(),
    });

    const domain = resolveCookieDomain(req);
    res.cookie("sdsession", token, { domain: domain, httpOnly: true });
    res.status(201).json({ user, session });
  } catch (err) {
    console.error("Errore login Keycloak:", err);
    res.sendStatus(500);
  }
});

/**
 * LOGOUT (locale + pulizia cookie)
 */
router.delete("/current", function (req, res) {
  if (!req.user) {
    res.sendStatus(404);
    return;
  }

  const token = req.cookies["sdsession"];

  db.Session.findOne({ where: { token: token } })
    .then((session) => {
      if (session) {
        session.destroy();
      }
    })
    .catch((err) => {
      console.error("Error destroying session:", err);
    })
    .finally(() => {
      const domain = resolveCookieDomain(req);
      res.clearCookie("sdsession", { domain: domain, path: "/" });
      res.sendStatus(204);
    });
});

module.exports = router;
