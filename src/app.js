const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const path = require("path");
const LocalStrategy = require("passport-local").Strategy;
const dotenv = require("dotenv").config();
const bycrypt = require("bcryptjs");
// const { user } = require("pg/lib/defaults");

const PORT = parseInt(process.env.PG_PORTs);

const pool = new Pool({
  host: process.env.PG_HOST, // or wherever the db is hosted
  user: process.env.PG_USER,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: PORT, // The default port
  // port: 8000,
});

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

// // middlewares for parsing request body
app.use(express.urlencoded({ extended: true })); // For form submissions
app.use(express.json()); // For JSON payloads

app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.session());

app.get("/", (req, res) => res.render("index", { user: req.user }));
app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", async (req, res, next) => {
  const cryptPassword = bycrypt.hash(
    req.body.password,
    10,
    async (err, hashedPassword) => {
      if (err) {
        console.log("Hashing error: ", err);

        return err;
      }
      return hashedPassword;
    }
  );

  try {
    await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [
      req.body.username,
      cryptPassword,
      // req.body.password,
    ]);
    console.log(req.body);

    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});

// setting up the LocalStrategy
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username]
      );
      const user = rows[0];
      console.log(user);

      const cryptPasswordMatch = await bycrypt.compare(password, user.password);

      if (!user) {
        console.log("Incorrect username");

        return done(null, false, { message: "Incorrect username" });
      }
      if (!cryptPasswordMatch) {
        console.log("Incorrect password");

        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

// app.use((req, res, next) => {
//   console.log(req.user);
//   console.log(req.session);

//   next();
// });

// sessions and serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    const user = rows[0];

    done(null, user);
  } catch (err) {
    done(err);
  }
});

// log in
app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

//log out
app.get("/log-out", (req, res, next) => {
  req.logOut((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.listen(9000, () => console.log("app listening on port 9000!"));
