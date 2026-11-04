import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { User } from "../models/User.js";
import type { Router as ExpressRouter } from "express";
import type { Response } from "express";
// import { User, type UserType } from "../models/User.js";

export const authRouter: ExpressRouter = Router();

const COOKIE_NAME = "auth_token";

function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET;

  if (!secret || secret.length < 32) {
    throw new Error("JWT_SECRET must be at least 32 characters long.");
  }

  return secret;
}
// Create a JWT for the authenticated user
function createToken(userId: string) {
  return jwt.sign({ sub: userId }, getJwtSecret(), { expiresIn: "7d" });
}

// Configure the authentication cookie
function setAuthCookie(res: Response, token: string) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/",
  });
}

// Never return the password hash to the frontend
function publicUser(user: any) {
  return {
    id: user._id.toString(),
    name: user.name,
    email: user.email,
  };
}

// SIGNUP: POST /api/auth/signup
authRouter.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body ?? {};

    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        message: "Name, email, and password are required.",
      });
    }

    const cleanName = name.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (cleanName.length < 2 || cleanName.length > 80) {
      return res.status(400).json({
        message: "Name must be between 2 and 80 characters.",
      });
    }

    if (
      cleanEmail.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
    ) {
      return res.status(400).json({
        message: "Please enter a valid email address.",
      });
    }

    if (
      password.length < 8 ||
      password.length > 72 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        message:
          "Password must be at least 8 characters and no more than 72 UTF-8 bytes.",
      });
    }

    const existingUser = await User.findOne({
      email: cleanEmail,
    });

    if (existingUser) {
      return res.status(409).json({
        message: "An account with this email already exists.",
      });
    }

    // Hash the password before saving it
    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      name: cleanName,
      email: cleanEmail,
      password: hashedPassword,
    });

    // Log the user in immediately after signup
    const token = createToken(user._id.toString());
    setAuthCookie(res, token);

    return res.status(201).json({
      message: "Account created successfully.",
      user: publicUser(user),
    });
  } catch (error: unknown) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === 11000
    ) {
      return res.status(409).json({
        message: "An account with this email already exists.",
      });
    }

    console.error("Signup error:", error);

    return res.status(500).json({
      message: "Something went wrong.",
    });
  }
});

// LOGIN: POST /api/auth/login
authRouter.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body ?? {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      email.length > 254 ||
      password.length > 72 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        message: "Please provide valid login details.",
      });
    }

    const user = await User.findOne({
      email: email.trim().toLowerCase(),
    }).select("+password");

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const token = createToken(user._id.toString());
    setAuthCookie(res, token);

    return res.json({
      message: "Login successful.",
      user: publicUser(user),
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      message: "Something went wrong.",
    });
  }
});

// CURRENT USER: GET /api/auth/me
authRouter.get("/me", async (req, res) => {
  try {
    const token = req.cookies?.[COOKIE_NAME];

    if (!token) {
      return res.status(401).json({
        message: "Not authenticated.",
      });
    }

    const payload = jwt.verify(token, getJwtSecret());

    if (typeof payload !== "object" || typeof payload.sub !== "string") {
      return res.status(401).json({
        message: "Invalid authentication token.",
      });
    }

    const user = await User.findById(payload.sub);

    if (!user) {
      res.clearCookie(COOKIE_NAME, { path: "/" });

      return res.status(401).json({
        message: "User no longer exists.",
      });
    }

    return res.json({
      user: publicUser(user),
    });
  } catch {
    res.clearCookie(COOKIE_NAME, { path: "/" });

    return res.status(401).json({
      message: "Invalid or expired session.",
    });
  }
});

// UPDATE PROFILE: PATCH /api/auth/profile
authRouter.patch("/profile", async (req, res) => {
  try {
    // 1. Get the authentication cookie
    const token = req.cookies?.[COOKIE_NAME];

    if (!token) {
      return res.status(401).json({
        message: "Please log in to update your profile.",
      });
    }

    // 2. Verify the JWT
    const payload = jwt.verify(token, getJwtSecret());

    if (typeof payload !== "object" || typeof payload.sub !== "string") {
      return res.status(401).json({
        message: "Invalid authentication token.",
      });
    }

    // 3. Read the updated information
    const { name, password } = req.body ?? {};

    if (typeof name !== "string") {
      return res.status(400).json({
        message: "Name is required.",
      });
    }

    const cleanName = name.trim();

    if (cleanName.length < 2 || cleanName.length > 80) {
      return res.status(400).json({
        message: "Name must be between 2 and 80 characters.",
      });
    }

    // 4. Find the currently authenticated user
    const user = await User.findById(payload.sub).select("+password");

    if (!user) {
      res.clearCookie(COOKIE_NAME, { path: "/" });

      return res.status(401).json({
        message: "User no longer exists. Please log in again.",
      });
    }

    // 5. Update the name
    user.name = cleanName;

    // 6. Update the password only if a new one was provided
    if (password !== undefined && password !== "") {
      if (
        typeof password !== "string" ||
        password.length < 8 ||
        password.length > 72 ||
        Buffer.byteLength(password, "utf8") > 72
      ) {
        return res.status(400).json({
          message:
            "Password must be at least 8 characters and no more than 72 UTF-8 bytes.",
        });
      }

      user.password = await bcrypt.hash(password, 12);
    } else if (password !== undefined && typeof password !== "string") {
      return res.status(400).json({
        message: "Password must be a string.",
      });
    }

    // 7. Save changes to MongoDB
    await user.save();

    // 8. Return safe user information (never return password)
    return res.json({
      message: "Profile updated successfully.",
      user: publicUser(user),
    });
  } catch (error) {
    console.error("Profile update error:", error);

    return res.status(401).json({
      message: "Unable to authenticate or update your profile.",
    });
  }
});

// LOGOUT: POST /api/auth/logout
authRouter.post("/logout", (req, res) => {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
  });

  return res.json({
    message: "Logged out successfully.",
  });
});
