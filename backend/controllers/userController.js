import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import validator from "validator";
import userModel from "../models/userModel.js";
import otpModel from "../models/otpModel.js";
import nodemailer from "nodemailer";

// Create JWT token
const createToken = (id) => {
  if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET missing");
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

// ------------------ AUTH ------------------

// Login
const loginUser = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await userModel.findOne({ email });
    if (!user) return res.json({ success: false, message: "User does not exist" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.json({ success: false, message: "Invalid credentials" });

    const token = createToken(user._id);
    res.json({ success: true, token, user });
  } catch (error) {
    console.error(error);
    res.json({ success: false, message: "Error" });
  }
};

// ------------------ REGISTER WITH OTP ------------------

// Step 1: Send OTP for registration
// Step 1: Send OTP for registration (with cooldown)
// Step 1: Send OTP for registration (with cooldown)
const sendRegisterOTP = async (req, res) => {
  const { email } = req.body;

  try {
    console.log("📩 Received OTP request for:", email);

    // Validate email
    if (!validator.isEmail(email)) {
      return res.json({ success: false, message: "Invalid email" });
    }

    // Check if user already exists
    const exists = await userModel.findOne({ email });
    if (exists) {
      return res.json({ success: false, message: "User already exists" });
    }

    // Check cooldown (30 seconds)
    const lastOtp = await otpModel.findOne({ email }).sort({ createdAt: -1 });

    if (lastOtp?.createdAt) {
      const timeDiff = Date.now() - lastOtp.createdAt.getTime();
      if (timeDiff < 30 * 1000) {
        const waitTime = Math.ceil((30 * 1000 - timeDiff) / 1000);
        return res.json({
          success: false,
          message: `Please wait ${waitTime} seconds before requesting again`,
        });
      }
    }

    // Remove old OTPs
    await otpModel.deleteMany({ email });

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000);
    console.log("Generated OTP:", otp);

    // Save OTP with 5-min expiry
    await otpModel.create({
      email,
      otp,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    // Create email transporter
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS, // Gmail App Password
      },
    });

    // Send mail
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
const registerUser = async (req, res) => {
  const { name, email, password, otp } = req.body;
  try {
    // Validate email
    if (!validator.isEmail(email)) {
      return res.json({ success: false, message: "Invalid email" });
    }

    // Check if user already exists
    const exists = await userModel.findOne({ email });
    if (exists) {
      return res.json({ success: false, message: "User already exists" });
    }

    // Find OTP record
    const record = await otpModel.findOne({ email, otp });
    if (!record) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    // Check expiry
    if (record.expiresAt < new Date()) {
      await otpModel.deleteMany({ email });
      return res.json({ success: false, message: "OTP expired" });
    }

    // Validate password
    if (password.length < 8) {
      return res.json({ success: false, message: "Password must be 8+ chars" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new userModel({ name, email, password: hashedPassword });
    const user = await newUser.save();

    // Delete OTP after successful registration
    await otpModel.deleteMany({ email });

    // Generate token
    const token = createToken(user._id);

    res.json({ success: true, token, user });
  } catch (error) {
    console.error(error);
    res.json({ success: false, message: "Error registering user" });
  }
};

// ------------------ PASSWORD RESET ------------------

// Step 1: Send OTP for reset
const sendResetOTP = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await userModel.findOne({ email });
    if (!user) return res.json({ success: false, message: "User not found" });

    // Remove old OTPs for this email
    await otpModel.deleteMany({ email });

    const otp = Math.floor(100000 + Math.random() * 900000);

    await otpModel.create({
      email,
      otp,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: `"Food App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP is ${otp}. It will expire in 5 minutes.`,
    });

    res.json({ success: true, message: "OTP sent to email" });
  } catch (error) {
    console.error(error);
    res.json({ success: false, message: "Error sending OTP" });
  }
};

// Step 2: Reset Password
const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    const record = await otpModel.findOne({ email, otp });
    if (!record) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    // Check expiry
    if (record.expiresAt < new Date()) {
      await otpModel.deleteMany({ email });
      return res.json({ success: false, message: "OTP expired" });
    }

    const user = await userModel.findOne({ email });
    if (!user) return res.json({ success: false, message: "User not found" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    // Delete OTP after successful reset
    await otpModel.deleteMany({ email });

    res.json({ success: true, message: "Password reset successful" });
  } catch (error) {
    console.error(error);
    res.json({ success: false, message: "Error resetting password" });
  }
};

export { loginUser, sendRegisterOTP, registerUser, sendResetOTP, resetPassword };