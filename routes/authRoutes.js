const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const connection = require("../config/database");
const { SECRET_KEY } = require("../config/env");
const { transporter, otpStorage } = require("../utils/otp");

// ======================= SECURITY CONFIG =======================
const SECURITY = {
  OTP_VALIDITY: 10 * 60 * 1000,    // 10 minutes
  OTP_COOLDOWN: 2 * 60 * 1000,     // 2 minutes
  MAX_OTP_ATTEMPTS: 3,             // Max wrong attempts
  MAX_OTP_REQUESTS: 5,             // Max OTP requests per IP per hour
  LOGIN_ATTEMPTS: 5,               // Max login attempts per IP per hour
  PASSWORD_MIN_LENGTH: 8,
  TOKEN_EXPIRY: '1h'
};

// ======================= RATE LIMITERS =======================
const rateLimiters = {
  otpRequests: {}, // Format: { ip: { count, firstAttempt } }
  loginAttempts: {},
  
  // Middleware for OTP request limiting
  limitOtpRequests: (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    
    if (!this.otpRequests[ip]) {
      this.otpRequests[ip] = { count: 1, firstAttempt: now };
      return next();
    }
    
    // Reset if hour has passed
    if (now - this.otpRequests[ip].firstAttempt > 3600000) {
      this.otpRequests[ip] = { count: 1, firstAttempt: now };
      return next();
    }
    
  // Check if limit exceeded
if (this.otpRequests[ip].count >= SECURITY.MAX_OTP_REQUESTS) {
  const waitTime = Math.ceil((3600000 - (now - this.otpRequests[ip].firstAttempt)) / 1000);
  return res.status(429).json({
    message: `Too many OTP requests. Try again in ${waitTime} seconds.`
  });
}

    
    this.otpRequests[ip].count++;
    next();
  },
  
  // Middleware for login attempt limiting
  limitLoginAttempts: (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    
    if (!this.loginAttempts[ip]) {
      this.loginAttempts[ip] = { count: 1, firstAttempt: now };
      return next();
    }
    
    // Reset if hour has passed
    if (now - this.loginAttempts[ip].firstAttempt > 3600000) {
      this.loginAttempts[ip] = { count: 1, firstAttempt: now };
      return next();
    }
    
    // Check if limit exceeded
    if (this.loginAttempts[ip].count >= SECURITY.LOGIN_ATTEMPTS) {
      const waitTime = Math.ceil((3600000 - (now - this.loginAttempts[ip].firstAttempt)) / 1000;
      return res.status(429).json({
        message: `Too many login attempts. Try again in ${waitTime} seconds.`
      });
    }
    
    this.loginAttempts[ip].count++;
    next();
  }
};

// Cleanup rate limiters hourly
setInterval(() => {
  const now = Date.now();
  for (const ip in rateLimiters.otpRequests) {
    if (now - rateLimiters.otpRequests[ip].firstAttempt > 3600000) {
      delete rateLimiters.otpRequests[ip];
    }
  }
  for (const ip in rateLimiters.loginAttempts) {
    if (now - rateLimiters.loginAttempts[ip].firstAttempt > 3600000) {
      delete rateLimiters.loginAttempts[ip];
    }
  }
}, 3600000);

// ======================= HELPER FUNCTIONS =======================
const validateEmail = (email) => {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
};

const validatePassword = (password) => {
  return password.length >= SECURITY.PASSWORD_MIN_LENGTH && 
         /[A-Z]/.test(password) && 
         /[0-9]/.test(password) &&
         /[^A-Za-z0-9]/.test(password);
};

// ======================= ROUTES =======================

// 1. Send OTP with rate limiting and security checks
router.post("/send-otp", rateLimiters.limitOtpRequests, async (req, res) => {
  const { email } = req.body;
  
  // Validate email
  if (!email || !validateEmail(email)) {
    return res.status(400).json({ message: "Valid email required" });
  }
  
  // Check cooldown
  const existing = otpStorage.data[email];
  if (existing && Date.now() - existing.lastSentAt < SECURITY.OTP_COOLDOWN) {
    const wait = Math.ceil((SECURITY.OTP_COOLDOWN - (Date.now() - existing.lastSentAt)) / 1000);
    return res.status(429).json({
      message: `Please wait ${wait} seconds before requesting another OTP.`
    });
  }
  
  // Generate and store OTP
  const otp = Math.floor(100000 + Math.random() * 900000);
  const otpHash = await bcrypt.hash(otp.toString(), 8);
  
  otpStorage.currentIP = req.ip; // Store IP for security checks
  otpStorage.add(email, otpHash);
  
  // Send email
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP is ${otp}. Valid for 10 minutes.`,
      html: `<p>Your OTP is <strong>${otp}</strong>. Valid for 10 minutes.</p>`
    });
    
    res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("OTP send error:", err);
    res.status(500).json({ message: "Failed to send OTP" });
  }
});

// 2. Register with OTP verification
router.post("/register", async (req, res) => {
  const { email, otp, password, username } = req.body;
  
  // Validate inputs
  if (!validateEmail(email) || !validatePassword(password)) {
    return res.status(400).json({
      message: `Invalid email or password (min ${SECURITY.PASSWORD_MIN_LENGTH} chars with uppercase, number & special char)`
    });
  }
  
  // Verify OTP
  const isValid = await otpStorage.verify(email, otp);
  if (!isValid) {
    return res.status(400).json({ message: "Invalid OTP or too many attempts" });
  }
  
  try {
    // Check if user exists
    const [existing] = await connection.query(
      "SELECT * FROM users WHERE email = ?", 
      [email]
    );
    
    if (existing.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }
    
    // Create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    
    await connection.query(
      "INSERT INTO users (user_id, username, email, password) VALUES (?, ?, ?, ?)",
      [userId, username, email, hashedPassword]
    );
    
    // Generate token
    const token = jwt.sign({ id: userId, email }, SECRET_KEY, { 
      expiresIn: SECURITY.TOKEN_EXPIRY 
    });
    
    res.json({ 
      message: "Registration successful",
      token,
      user_id: userId,
      username
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ message: "Registration failed", error: err.message });
  }
});

// 3. Login with rate limiting
router.post("/login", rateLimiters.limitLoginAttempts, async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }
  
  try {
    const [users] = await connection.query(
      "SELECT * FROM users WHERE email = ?", 
      [email]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    
    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    
    // Generate token with security details
    const token = jwt.sign({ 
      id: user.user_id, 
      email: user.email,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    }, SECRET_KEY, { expiresIn: SECURITY.TOKEN_EXPIRY });
    
    res.json({ 
      message: "Login successful",
      token,
      user_id: user.user_id,
      username: user.username
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Login failed", error: err.message });
  }
});

// 4. Google login with security checks
router.post("/user/google-login", async (req, res) => {
  const { user_id, email, username } = req.body;
  
  try {
    const [existing] = await connection.query(
      "SELECT * FROM users WHERE email = ?", 
      [email]
    );
    
    // Register if new user
    if (existing.length === 0) {
      await connection.query(
        "INSERT INTO users (user_id, username, email) VALUES (?, ?, ?)",
        [user_id, username, email]
      );
    }
    
    // Generate secure token
    const token = jwt.sign({ 
      id: user_id, 
      email,
      ip: req.ip,
      authMethod: 'google'
    }, SECRET_KEY, { expiresIn: SECURITY.TOKEN_EXPIRY });
    
    res.json({ 
      message: "Google login successful",
      token,
      user_id,
      username
    });
  } catch (err) {
    console.error("Google login error:", err);
    res.status(500).json({ message: "Google login failed", error: err.message });
  }
});

// 5. Secure logout
router.post("/logout", (req, res) => {
  // In a real app, you might want to blacklist the token here
  res.json({ message: "Logged out successfully" });
});

module.exports = router;