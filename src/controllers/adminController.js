import { Admin } from "../models/Admin.js";
import User from "../models/User.js";
import OTP from "../models/OTP.js";
import { sendOTP } from "../utils/twilio.js";
import { generateToken, generateResetToken } from "../middleware/auth.js";
import bcrypt from "bcrypt";
import { NODE_ENV } from "../config/env.js";

// Create Admin Account
export const createAdminAccount = async (req, res) => {
  const { phone, password, username } = req.body;
  console.log(req.body);

  if ([phone, password, username].some((field) => field === "")) {
    return res.status(400).json({ message: "Username/phone and password are required" });
  }

  try {
    const adminExists = await Admin.findOne({
      $or: [{ username }, { phone }],
    });

    if (adminExists) {
      return res.status(409).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const admin = await Admin.create({
      username,
      phone,
      password: hashedPassword,
    });

    return res.status(201).json({
      message: "Admin created successfully",
      admin: {
        id: admin._id,
        username: admin.username,
        phone: admin.phone,
      },
    });
  } catch (error) {
    console.error("Admin creation error:", error);
    return res.status(500).json({ message: "Server error" });
  }
};

// Login Admin
export const login = async (req, res) => {
  const { identifier, password } = req.body;
  console.log(req.body);

  if (!identifier || !password) {
    return res.status(400).json({ message: "Username/phone and password are required" });
  }

  try {
    const admin = await Admin.findOne({
      $or: [{ username: identifier }, { phone: identifier }],
    });

    if (!admin) return res.status(404).json({ message: "Admin not found" });

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

    const token = generateToken(admin._id, "admin");
    return res
      .cookie("token", token, {
        httpOnly: true,
        secure: NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 60 * 60 * 1000,
      })
      .status(200)
      .json({
        message: "Login successful",
        admin: {
          id: admin._id,
          phone: admin.phone,
          username: admin.username,
          role: admin.role,
        },
      });
  } catch (error) {
    console.error("Admin login error:", error);
    return res.status(500).json({ message: "Server error" });
  }
};

// Request OTP
export const requestOtp = async (req, res) => {
  const { phone } = req.body;
  console.log(req.body);

  if (!phone) return res.status(400).json({ message: "Phone is required" });

  try {
    const admin = await Admin.findOne({ phone });
    if (!admin) return res.status(404).json({ message: "Admin not found" });

    const otpRecord = await OTP.findOne({ phone, role: "admin" });
    const now = new Date();

    if (otpRecord && otpRecord.requestCount >= 5) {
      const cooldownEnd = new Date(otpRecord.lastRequestTime.getTime() + 15 * 60 * 1000);
      if (now < cooldownEnd) {
        const waitTime = Math.ceil((cooldownEnd - now) / 60000);
        return res.status(429).json({
          message: `Too many requests. Please wait ${waitTime} minutes.`,
        });
      } else {
        otpRecord.requestCount = 0;
      }
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await OTP.findOneAndUpdate(
      { phone, role: "admin" },
      {
        otpCode: otp,
        expiresAt,
        requestCount: (otpRecord?.requestCount || 0) + 1,
        lastRequestTime: now,
        verified: false,
      },
      { upsert: true }
    );

    await sendOTP(phone, otp);
    return res.status(200).json({ message: "OTP sent successfully" });
  } catch (error) {
    console.error("Admin OTP request error:", error);
    return res.status(500).json({ message: "Server error" });
  }
};

// Verify OTP
export const verifyOtp = async (req, res) => {
  const { phone, otp } = req.body;
  console.log(req.body);

  if (!phone || !otp) {
    return res.status(400).json({ message: "Phone and OTP are required" });
  }

  try {
    const otpRecord = await OTP.findOne({ phone, otpCode: otp, role: "admin" });

    if (!otpRecord || new Date() > otpRecord.expiresAt) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    if (otpRecord.verified) {
      return res.status(400).json({ message: "OTP has already been used" });
    }

    otpRecord.verified = true;
    await otpRecord.save();

    const token = generateResetToken(otpRecord._id, "10m");

    return res
      .cookie("resetToken", token, {
        httpOnly: true,
        secure: NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 10 * 60 * 1000,
      })
      .status(200)
      .json({ message: "OTP verified successfully" });
  } catch (error) {
    console.error("Admin OTP verify error:", error);
    return res.status(500).json({ message: "Server error" });
  }
};

// Reset Password
export const resetPassword = async (req, res) => {
  const { newPassword } = req.body;
  console.log(req.body);

  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ message: "Password must be at least 8 characters" });
  }

  try {
    const { otpId } = req;
    const otpRecord = await OTP.findById(otpId);

    if (!otpRecord || !otpRecord.verified || otpRecord.role !== "admin") {
      return res.status(400).json({ message: "Invalid or unverified OTP" });
    }

    const admin = await Admin.findOne({ phone: otpRecord.phone });
    if (!admin) return res.status(404).json({ message: "Admin not found" });

    admin.password = await bcrypt.hash(newPassword, 10);
    await admin.save();

    await OTP.deleteOne({ _id: otpRecord._id });

    return res
      .clearCookie("resetToken")
      .status(200)
      .json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("Admin reset password error:", error);
    return res.status(500).json({ message: "Server error" });
  }
};

// Check Reset Token
export const checkResetToken = async (req, res) => {
  try {
    const { otpId } = req;
    const otpRecord = await OTP.findById(otpId);

    if (!otpRecord || !otpRecord.verified || otpRecord.role !== "admin") {
      return res.status(401).json({ message: "Invalid or unverified reset token" });
    }

    return res.status(200).json({ message: "Token valid" });
  } catch (error) {
    console.error("Check reset token error:", error);
    return res.status(500).json({ message: "Server error" });
  }
};

// Approve Vendor
export const approveVendor = async (req, res) => {
  const { userId } = req.body;
  console.log(req.body);

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    if (user.vendorRequest.status !== "pending") {
      return res.status(400).json({ message: "No pending vendor request" });
    }

    user.role = "vendor";
    user.vendorRequest.status = "approved";
    user.vendorDetails = { ...user.vendorRequest };

    delete user.vendorRequest.rejectionCount;
    delete user.vendorRequest.lastRejectionTime;

    await user.save();

    await sendOTP(user.phone, "Congratulations! You have been registered as a vendor.");
    return res.status(200).json({ message: "Vendor approved successfully" });
  } catch (error) {
    console.error("Vendor approval error:", error);
    return res.status(500).json({ message: "Server error" });
  }
};

// Reject Vendor
export const rejectVendor = async (req, res) => {
  const { userId } = req.body;
  console.log(req.body);

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    if (user.vendorRequest.status !== "pending") {
      return res.status(400).json({ message: "No pending vendor request" });
    }

    user.vendorRequest.status = "canApply";
    user.vendorRequest.rejectionCount = (user.vendorRequest.rejectionCount || 0) + 1;
    user.vendorRequest.lastRejectionTime = new Date();

    await user.save();

    await sendOTP(user.phone, "Your request was rejected. Please try again with correct details.");
    return res.status(200).json({ message: "Vendor request rejected" });
  } catch (error) {
    console.error("Vendor rejection error:", error);
    return res.status(500).json({ message: "Server error" });
  }
};
