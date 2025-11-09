// controllers/authController.js
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import validator from "validator";
import nodemailer from "nodemailer";
import userModel from "../models/userModel.js";
import otpModel from "../models/otpModel.js";

// ------------------ UTILITIES ------------------

const createToken = (id) => {
  if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET missing");
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

// Single cached transporter (Gmail STARTTLS on 587)
let _transporter = null;
let _verified = false;

function getTransporter() {
  if (_transporter) return _transporter;

  const user = process.env.EMAIL_USER;
  const pass = process.env.EMAIL_PASS; // Gmail App Password

  if (!user || !pass) {
    throw new Error("EMAIL_USER/EMAIL_PASS missing");
  }

  _transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || "smtp.gmail.com",
    port: Number(process.env.SMTP_PORT || 587),
    secure: false,          // false for 587 (STARTTLS)
    requireTLS: true,       // enforce STARTTLS
    auth: { user, pass },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 20000,
  });

  return _transporter;
}

async function ensureSmtpReady() {
  if (_verified) return;
  const transporter = getTransporter();
  await transporter.verify();
  _verified = true;
}

function sanitizeUser(u) {
  if (!u) return u;
  const obj = u.toObject ? u.toObject() : { ...u };
  delete obj.password;
  return obj;
}

// ------------------ AUTH ------------------

export const loginUser = async (req, res) => {
  const { email, password } = req.body || {};
  try {
    const user = await userModel.findOne({ email });
    if (!user) return res.json({ success: false, message: "User does not exist" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.json({ success: false, message: "Invalid credentials" });

    const token = createToken(user._id);
    res.json({ success: true, token, user: sanitizeUser(user) });
  } catch (error) {
    console.error("loginUser error:", error);
    res.json({ success: false, message: "Error" });
  }
};

// ------------------ REGISTER WITH OTP ------------------

// Step 1: Send OTP for registration (with 30s cooldown)
export const sendRegisterOTP = async (req, res) => {
  const { email } = req.body || {};

  try {
    console.log("📩 Received OTP request for:", email);

    if (!validator.isEmail(email)) {
      return res.json({ success: false, message: "Invalid email" });
    }

    // Already registered?
    const exists = await userModel.findOne({ email });
    if (exists) {
      return res.json({ success: false, message: "User already exists" });
    }

    // Cooldown 30s
    const lastOtp = await otpModel.findOne({ email }).sort({ createdAt: -1 });
    if (lastOtp?.createdAt) {
      const diff = Date.now() - lastOtp.createdAt.getTime();
      if (diff < 30_000) {
        const wait = Math.ceil((30_000 - diff) / 1000);
        return res.json({
          success: false,
          message: `Please wait ${wait} seconds before requesting again`,
        });
      }
    }

    // Remove old OTPs for this email
    await otpModel.deleteMany({ email });

    // Generate & save OTP (5 min expiry)
    const otp = Math.floor(100000 + Math.random() * 900000);
    await otpModel.create({
      email,
      otp,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    // Send mail
    await ensureSmtpReady();
    const transporter = getTransporter();

    await transporter.sendMail({
      from: `"Food App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Email Verification OTP",
      text: `Your OTP for registration is ${otp}. It will expire in 5 minutes.`,
    });

    console.log("✅ OTP email sent successfully to:", email);
    res.json({ success: true, message: "OTP sent to email" });
  } catch (error) {
    console.error("❌ Error in sendRegisterOTP:", error);
    res.json({ success: false, message: "Error sending OTP", error: error.message });
  }
};

// Step 2: Verify OTP and Register
export const registerUser = async (req, res) => {
  const { name, email, password, otp } = req.body || {};

  try {
    if (!validator.isEmail(email)) {
      return res.json({ success: false, message: "Invalid email" });
    }

    const exists = await userModel.findOne({ email });
    if (exists) {
      return res.json({ success: false, message: "User already exists" });
    }

    const otpNum = Number(otp);
    if (!Number.isInteger(otpNum)) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    const record = await otpModel.findOne({ email, otp: otpNum });
    if (!record) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    if (record.expiresAt < new Date()) {
      await otpModel.deleteMany({ email });
      return res.json({ success: false, message: "OTP expired" });
    }

    if (!password || password.length < 8) {
      return res.json({ success: false, message: "Password must be 8+ chars" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new userModel({ name, email, password: hashedPassword });
    const user = await newUser.save();

    await otpModel.deleteMany({ email });

    const token = createToken(user._id);
    res.json({ success: true, token, user: sanitizeUser(user) });
  } catch (error) {
    console.error("registerUser error:", error);
    res.json({ success: false, message: "Error registering user" });
  }
};

// ------------------ PASSWORD RESET ------------------

// Step 1: Send OTP for reset
export const sendResetOTP = async (req, res) => {
  const { email } = req.body || {};

  try {
    const user = await userModel.findOne({ email });
    if (!user) return res.json({ success: false, message: "User not found" });

    // Remove old OTPs
    await otpModel.deleteMany({ email });

    const otp = Math.floor(100000 + Math.random() * 900000);

    await otpModel.create({
      email,
      otp,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    await ensureSmtpReady();
    const transporter = getTransporter();

    await transporter.sendMail({
      from: `"Food App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP is ${otp}. It will expire in 5 minutes.`,
    });

    res.json({ success: true, message: "OTP sent to email" });
  } catch (error) {
    console.error("sendResetOTP error:", error);
    res.json({ success: false, message: "Error sending OTP" });
  }
};

// Step 2: Reset Password
export const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body || {};

  try {
    const otpNum = Number(otp);
    if (!Number.isInteger(otpNum)) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    const record = await otpModel.findOne({ email, otp: otpNum });
    if (!record) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    if (record.expiresAt < new Date()) {
      await otpModel.deleteMany({ email });
      return res.json({ success: false, message: "OTP expired" });
    }

    const user = await userModel.findOne({ email });
    if (!user) return res.json({ success: false, message: "User not found" });

    if (!newPassword || newPassword.length < 8) {
      return res.json({ success: false, message: "Password must be 8+ chars" });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    await otpModel.deleteMany({ email });

    res.json({ success: true, message: "Password reset successful" });
  } catch (error) {
    console.error("resetPassword error:", error);
    res.json({ success: false, message: "Error resetting password" });
  }
};
