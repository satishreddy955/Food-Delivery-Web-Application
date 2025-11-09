// import mongoose from "mongoose";

// const otpSchema = new mongoose.Schema(
//   {
//     email: {
//       type: String,
//       required: true,
//     },
//     otp: {
//       type: Number,
//       required: true,
//     },
//     expiresAt: {
//       type: Date,
//       required: true,
//     },
//   },
//   { timestamps: true }
// );

// // TTL index: MongoDB will delete documents automatically after expiresAt
// otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// const otpModel = mongoose.models.OTP || mongoose.model("OTP", otpSchema);

// export default otpModel;

// models/otpModel.js

import mongoose from "mongoose";

const otpSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, index: true },
    // Store OTP as string to avoid type mismatch with req.body
    otp: { type: String, required: true },
    // We’ll set this per-document (dynamic TTL)
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true } // enables createdAt used for cooldown
);

// TTL index: expire exactly at expiresAt
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const otpModel =
  mongoose.models.OTP || mongoose.model("OTP", otpSchema);

export default otpModel;
