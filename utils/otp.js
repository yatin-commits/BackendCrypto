const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "sharmayatin0882@gmail.com",
    pass: "bnkjpxlfsgezlyvx",
  },
});

const otpStorage = {};

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000); // Generate 6-digit OTP
}

module.exports = { transporter, otpStorage, generateOTP };