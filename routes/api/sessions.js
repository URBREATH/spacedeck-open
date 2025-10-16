"use strict";

var config = require("config");
const db = require("../../models/db");

var bcrypt = require("bcryptjs");
var crypto = require("crypto");
var URL = require("url").URL;

var express = require("express");
var router = express.Router();

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
    const { email, name } = req.body; // dati minimi che ti arrivano da Keycloak
    if (!email) {
      return res.status(400).json({ error: "missing_email" });
    }

    // Controlla se l'utente esiste già
    let user = await db.User.findOne({ where: { email } });

    if (!user) {
      // Creazione utente base
      user = await db.User.create({
        email: email,
        username: email, // puoi usare name o email
        display_name: name || email,
      });

      // Crea la home folder
      const folder = await db.Folder.create({
        title: "Home",
        user_id: user.id,
        parent_id: null,
      });

      // Collega la home folder all’utente
      user.home_folder_id = folder.id;
      await user.save();

      console.log("Creato utente Keycloak con home folder:", email);
    }

    // Genera sessione
    const token = crypto.randomBytes(48).toString("hex");
    const session = await db.Session.create({
      user_id: user.id,
      token,
      ip: req.ip,
      device: "web",
      created_at: new Date(),
    });

    // Cookie sessione
    var domain =
      process.env.NODE_ENV == "production"
        ? new URL(config.get("endpoint")).hostname
        : req.headers.hostname;

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
