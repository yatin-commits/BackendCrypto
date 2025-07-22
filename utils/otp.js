const nodemailer = require('nodemailer');

// Enhanced transporter configuration
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  pool: true, // Use connection pooling
  rateLimit: 5, // Max 5 messages per second
});

// Enhanced OTP storage with security features
const otpStorage = {
  data: {},
  
  // Add OTP with security metadata
  add: function(email, otpHash) {
    this.data[email] = {
      otpHash,
      expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
      attempts: 0,
      lastSentAt: Date.now(),
      ip: this.currentIP // Will be set by middleware
    };
  },
  
  // Verify OTP with attempt tracking
  verify: async function(email, otp) {
    if (!this.data[email]) return false;
    
    const entry = this.data[email];
    if (entry.attempts >= 3) {
      delete this.data[email];
      return false;
    }
    
    const isValid = await bcrypt.compare(otp.toString(), entry.otpHash);
    if (!isValid) {
      entry.attempts++;
      return false;
    }
    
    delete this.data[email];
    return true;
  },
  
  // Cleanup expired OTPs
  cleanup: function() {
    const now = Date.now();
    for (const email in this.data) {
      if (this.data[email].expiresAt < now) {
        delete this.data[email];
      }
    }
  }
};

// Run cleanup every hour
setInterval(() => otpStorage.cleanup(), 60 * 60 * 1000);

module.exports = { transporter, otpStorage };