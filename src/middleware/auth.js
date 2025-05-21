import jwt from "jsonwebtoken";
import { JWT_SECRET } from "../config/env.js";
import { Admin } from "../models/Admin.js";
import User from "../models/User.js";
import BlockedUsers from "../models/BlockedUsers.js";

// Utility: Validate presence of JWT_SECRET
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is not defined in your environment variables");
}

// Generate token based on role (admin/user/vendor)
export const generateToken = async (id, type, expiresIn = "1h") => {
  let entity;
  if (type === "admin") {
    entity = await Admin.findById(id);
    if (!entity) throw new Error("Admin not found");
  } else if (["user", "vendor"].includes(type)) {
    entity = await User.findById(id);
    if (!entity) throw new Error("User not found");
  } else {
    throw new Error("Invalid type for token generation");
  }

  return jwt.sign({ id, role: entity.role }, JWT_SECRET, { expiresIn });
};

// Generate short-lived token for OTP/password reset
export const generateResetToken = (otpId, expiresIn = "10m") => {
  return jwt.sign({ otpId }, JWT_SECRET, { expiresIn });
};

// Middleware: Verify JWT and attach user info
export const verifyToken = async (req, res, next) => {
  const token = req.cookies?.token;

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id, role } = decoded;

    // Check if user is blocked
    if (["user", "vendor"].includes(role)) {
      const isBlocked = await BlockedUsers.findOne({ userId: id });
      if (isBlocked) {
        return res.status(403).json({ message: "Your account has been blocked" });
      }
    }

    let entity;
    if (["superadmin", "moderator"].includes(role)) {
      entity = await Admin.findById(id);
      if (!entity) return res.status(404).json({ message: "Admin not found" });
    } else {
      entity = await User.findById(id);
      if (!entity) return res.status(404).json({ message: "User not found" });
    }

    req.user = { id, role };
    next();
  } catch (error) {
    console.error("Token verification failed:", error.message);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// Middleware: Verify reset token
export const verifyResetToken = (req, res, next) => {
  const token = req.cookies?.resetToken;
  if (!token) return res.status(401).json({ message: "No reset token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.otpId = decoded.otpId;
    next();
  } catch (error) {
    console.error("Reset token verification failed:", error.message);
    return res.status(401).json({ message: "Invalid or expired reset token" });
  }
};

// Role checkers

export const adminCheck = (req, res, next) => {
  if (!req.user || !["superadmin", "moderator"].includes(req.user.role)) {
    return res.status(403).json({ message: "Access denied: Admins only" });
  }
  next();
};

export const vendorCheck = (req, res, next) => {
  if (!req.user || req.user.role !== "vendor") {
    return res.status(403).json({ message: "Access denied: Vendors only" });
  }
  next();
};

export const userCheck = (req, res, next) => {
  if (!req.user || !["user", "vendor"].includes(req.user.role)) {
    return res.status(403).json({ message: "Access denied: Users only" });
  }
  next();
};
 