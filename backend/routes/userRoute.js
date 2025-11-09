import express from "express";
import {
  loginUser,
  registerUser,
  sendRegisterOTP,
  sendResetOTP,
  resetPassword,
} from "../controllers/userController.js";

const userRouter = express.Router();

// ---------------- AUTH ----------------
userRouter.post("/login", loginUser);

// Sign Up with OTP
userRouter.post("/send-register-otp", sendRegisterOTP); // Step 1: send OTP for signup
userRouter.post("/register", registerUser);             // Step 2: verify OTP + create account

// ---------------- PASSWORD RESET ----------------
userRouter.post("/send-otp", sendResetOTP);      // for password reset
userRouter.post("/reset-password", resetPassword);

export default userRouter;
