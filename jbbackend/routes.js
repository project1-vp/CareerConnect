// Import required modules
const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./config");

/* ================= REGISTER API ================= */

router.post("/register", async (req, res) => {

  console.log("Register API called");

  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !role) {
    return res.json({ message: "All fields required" });
  }

  // Check existing email
  db.query("SELECT * FROM users WHERE email=?", [email], async (err, result) => {

    if (err) {
      console.log(err);
      return res.json({ message: "Database error" });
    }

    if (result.length > 0) {
      return res.json({ message: "Email already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    db.query(
      "INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)",
      [name, email, hashedPassword, role],
      (err) => {

        if (err) {
          console.log(err);
          return res.json({ message: "Database error" });
        }

        res.json({ message: "Registration Successful" });
      }
    );

  });
});


/* ================= LOGIN API ================= */

router.post("/login", (req, res) => {

  const { email, password } = req.body;

  if (!email || !password) {
    return res.json({ message: "All fields required" });
  }

  // Find user by email
  db.query("SELECT * FROM users WHERE email=?", [email], async (err, result) => {

    if (err) {
      console.log(err);
      return res.json({ message: "Database error" });
    }

    if (result.length === 0) {
      return res.json({ message: "User not found" });
    }

    const user = result[0];

    // Compare entered password with hashed password
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.json({ message: "Invalid password" });
    }

    // Create JWT token (optional but recommended)
    const token = jwt.sign(
      { id: user.id },
      "secretkey",
      { expiresIn: "1d" }
    );

    res.json({
      message: "Login Successful",
      token
    });

  });
});

module.exports = router;