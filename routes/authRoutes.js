// Express framework import kar rahe hain
const express = require("express");
// Router banaya - isse hum alag routes define kar sakte hain
const router = express.Router();

// Password encrypt/decrypt ke liye bcrypt use kar rahe hain
const bcrypt = require("bcrypt");

// JWT tokens banane ke liye import kiya
const jwt = require('jsonwebtoken');

// Unique user_id generate karne ke liye
const { v4: uuidv4 } = require('uuid');

// Database connection import kiya - isme connection.query() hona chahiye
const connection = require("../config/database");

// JWT ke liye secret key import kiya
const { SECRET_KEY } = require("../config/env");

// OTP bhejne aur store karne ke liye functions import kiye
const { transporter, otpStorage, generateOTP } = require("../utils/otp");

// ------------------------- SEND OTP --------------------------
// 🔐 Utility: Set JWT in HttpOnly cookie
const setAuthCookie = (res, token) => {
  res.cookie("token", token, {
    httpOnly: true,               // JS can't access it
    secure: process.env.NODE_ENV === "production", // Only sent over HTTPS in prod
    sameSite: "Strict",           // Prevent CSRF
    maxAge: 3600000,              // 1 hour expiration
  });
};

// ✅ 1. Send OTP for registration
router.post("/send-otp", (req, res) => {
  // Request body se email nikala
  const { email } = req.body;

  // Agar email nahi diya gaya, toh error bhejna
  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000); // Generate 6-digit OTP
  }

  const otp = generateOTP();
  otpStorage[email] = otp;

  // Mail bhejne ke liye options set kiye
  const mailOptions = {
    from: "sharmayatin0882@gmail.com", // Sender email
    to: email,                         // Receiver email
    subject: "Your OTP Code",         // Email subject
    text: `Your OTP code is ${otp}. It is valid for 10 minutes.`, // Email body
  };

  // Email bhejna using nodemailer
  transporter.sendMail(mailOptions, (error) => {
    if (error) return res.status(500).json({ message: "Failed to send OTP" });
    res.json({ message: "OTP sent successfully" });
  });
});

// ✅ 2. Register new user (with OTP check)
router.post("/register", async (req, res) => {
  // Frontend se data le rahe hain
  const { user_id, username, email, otp, password } = req.body;

  // OTP match kar rahe hain
  if (!otpStorage[email] || otpStorage[email] != otp) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  // OTP use hone ke baad delete kar diya
  delete otpStorage[email];

  try {
    // Check kar rahe hain ki email pehle se register hai ya nahi
    const [results] = await connection.query("SELECT * FROM users WHERE email = ?", [email]);
    if (results.length > 0) {
      return res.status(400).json({ message: "User already registered. Please log in." });
    }

    // Password ko hash (encrypt) kar rahe hain
    const hashedPassword = await bcrypt.hash(password, 10);

    // Naya user database mein insert kar rahe hain
    const [result] = await connection.query(
      "INSERT INTO users (user_id, username, email, password) VALUES (?, ?, ?, ?)",
      [user_id, username, email, hashedPassword]
    );

    // JWT token bana rahe hain
    const token = jwt.sign({ id: result.insertId, email }, SECRET_KEY, { expiresIn: "1h" });

    // Success message bhej rahe hain with token
    res.json({ message: "User registered successfully", token });
  } catch (err) {
    res.status(500).json({ message: "Database error", error: err });
  }
});

// ------------------------- LOGIN USER --------------------------
// ✅ 3. Login (email + password)
router.post("/login", async (req, res) => {
  // Frontend se login ke liye email aur password le rahe hain
  const { email, password } = req.body;

  // Agar email ya password missing hai toh error bhejna
  if (!email || !password) {
    return res.status(400).json({ message: "Please provide email and password" });
  }

  try {
    // Database se user find kar rahe hain
    const [results] = await connection.query("SELECT * FROM users WHERE email = ?", [email]);

    // Agar user nahi mila toh error
    if (results.length === 0) {
      return res.status(400).json({ message: "User not found" });
    }

    console.log(results);
    const user = results[0]; // User details

    // Agar password field hi nahi mila (rare case)
    if (!user.password) {
      console.log("No password found for this user");
      return res.status(500).json({ message: "No password found for this user" });
    }
    // Compare password 
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

    // Password match kar rahe hain
    const passwordMatch = await bcrypt.compare(password, user.password);

    // Agar password galat hai
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Token bana rahe hain successful login ke baad
    const token = jwt.sign({ id: user.user_id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });

    // Success response ke saath token aur user info bhej rahe hain
    res.json({ message: "Login successful", token, user_id: user.user_id, username: user.username });
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Database error", error: err });
  }
});


// ✅ 4. Google login (no password)
router.post("/user/google-login", async (req, res) => {
  // Frontend se Google sign-in data le rahe hain
  const { user_id, email, username } = req.body;

  try {
    // Pehle check kar rahe hain ki user already exist karta hai ya nahi
    const [results] = await connection.query("SELECT * FROM users WHERE email = ?", [email]);

    // Agar user exist nahi karta toh register kar rahe hain
    if (results.length === 0) {
      await connection.query(
        "INSERT INTO users (user_id, username, email) VALUES (?, ?, ?)",
        [user_id, username, email]
      );
    }

    // Agar user already exist karta hai toh bas login message bhejna
    res.status(200).json({ message: "Google user already exists. Logging in..." });
    const token = jwt.sign({ id: user_id, email }, SECRET_KEY, { expiresIn: "1h" });
    setAuthCookie(res, token);

    res.status(200).json({ message: "Google login successful" });
  } catch (err) {
    res.status(500).json({ message: "Google login error", error: err });
  }
});

// Is route module ko export kar rahe hain taaki app.js mein use ho sake
// ✅ 5. Logout route (clears cookie)
router.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logged out successfully" });
});

module.exports = router;