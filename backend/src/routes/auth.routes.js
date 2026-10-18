const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { randomUUID } = require("crypto");
const db = require("../auth/store");
const authenticate = require("../middleware/authenticate");

const router = express.Router();

function issueToken(user) {
  return jwt.sign(
    { email: user.email },
    process.env.JWT_SECRET,
    {
      subject: user.id,
      expiresIn: "12h",
      issuer: "securelens-nexus"
    }
  );
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email
  };
}

function authConfigured(res) {
  if (
    !process.env.JWT_SECRET ||
    process.env.JWT_SECRET === "paste_your_generated_secret_here"
  ) {
    res.status(500).json({
      error: "Authentication is not configured"
    });
    return false;
  }

  return true;
}

// Create an account.
router.post("/register", async (req, res) => {
  try {
    if (!authConfigured(res)) return;

    const name = String(req.body?.name || "").trim();
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = req.body?.password;

    if (name.length < 2 || name.length > 80) {
      return res.status(400).json({
        error: "Name must be between 2 and 80 characters"
      });
    }

    if (
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return res.status(400).json({
        error: "Enter a valid email address"
      });
    }

    if (
      typeof password !== "string" ||
      password.length < 8 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        error: "Password must be at least 8 characters and no more than 72 UTF-8 bytes"
      });
    }

    const existing = db.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).get(email);

    if (existing) {
      return res.status(409).json({
        error: "An account with this email already exists"
      });
    }

    const user = {
      id: randomUUID(),
      name,
      email,
      password_hash: await bcrypt.hash(password, 12),
      created_at: new Date().toISOString()
    };

    db.prepare(`
      INSERT INTO users (id, name, email, password_hash, created_at)
      VALUES (@id, @name, @email, @password_hash, @created_at)
    `).run(user);

    res.status(201).json({
      token: issueToken(user),
      user: publicUser(user)
    });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({
        error: "An account with this email already exists"
      });
    }

    console.error("Registration failed:", error.message);
    res.status(500).json({ error: "Could not create account" });
  }
});

// Sign in.
router.post("/login", async (req, res) => {
  try {
    if (!authConfigured(res)) return;

    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = req.body?.password;

    if (typeof password !== "string" || !email) {
      return res.status(400).json({
        error: "Email and password are required"
      });
    }

    const user = db.prepare(
      "SELECT * FROM users WHERE email = ?"
    ).get(email);

    const valid = user
      ? await bcrypt.compare(password, user.password_hash)
      : false;

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    res.json({
      token: issueToken(user),
      user: publicUser(user)
    });
  } catch (error) {
    console.error("Login failed:", error.message);
    res.status(500).json({ error: "Could not sign in" });
  }
});

// Validate the saved frontend session.
router.get("/me", authenticate, (req, res) => {
  const user = db.prepare(
    "SELECT id, name, email FROM users WHERE id = ?"
  ).get(req.user.id);

  if (!user) {
    return res.status(401).json({
      error: "Account no longer exists"
    });
  }

  res.json({ user });
});

module.exports = router;