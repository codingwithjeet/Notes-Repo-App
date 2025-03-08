const express = require("express");
const User = require("../models/User");
const rateLimit = require("express-rate-limit"); // Rate limiter middleware
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const passport = require("passport");

const router = express.Router();

// Rate limiting for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per windowMs
  message: { message: "Too many login attempts. Please try again later." },
});

// Helper function to validate password strength
const isPasswordStrong = (password) => {
  // Password must contain at least one number, one uppercase letter, and be at least 6 characters
  const regex = /^(?=.*[0-9])(?=.*[A-Z]).{6,}$/;
  return regex.test(password);
};

// User Signup (Manual)
router.post("/register", async (req, res) => {
  const { username, email, password, userType } = req.body;

  try {
    // Validate userType
    if (!userType || !["student", "teacher"].includes(userType)) {
      return res.status(400).json({ message: "User type must be 'student' or 'teacher'." });
    }

    // Validate username
    if (!username || username.length < 3) {
      return res.status(400).json({ message: "Username must be at least 3 characters long." });
    }

    // Validate email format
    if (!email || !/\S+@\S+\.\S+/.test(email)) {
      return res.status(400).json({ message: "A valid email address is required." });
    }

    // Improved password validation
    if (!password) {
      return res.status(400).json({ message: "Password is required." });
    }

    if (!isPasswordStrong(password)) {
      return res.status(400).json({ 
        message: "Password must be at least 6 characters long, contain at least one number and one uppercase letter." 
      });
    }

    // Check if email already exists
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ message: "This email is already registered." });
    }

    // Check if username already exists
    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.status(400).json({ message: "This username is already taken." });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword, userType });
    await newUser.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: newUser._id, username: newUser.username, userType: newUser.userType },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(201).json({ message: "User registered successfully.", token });
  } catch (error) {
    console.error("❌ Error registering user:", error);
    res.status(500).json({ message: "Internal server error.", error: error.message });
  }
});

// User Login (Manual)
router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate email & password presence
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    // Check if the user has a password (Google users don't)
    if (!user.password) {
      return res.status(401).json({ message: "Please log in using Google authentication." });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, userType: user.userType },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Determine redirect URL based on user type
    const redirectUrl = user.userType === "teacher" ? "/teacher-dashboard" : "/student-dashboard";

    res.status(200).json({ 
      message: "Login successful.", 
      token,
      userType: user.userType,
      redirectUrl 
    });
  } catch (error) {
    console.error("❌ Error logging in:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Google OAuth Callback
router.get("/auth/google/callback", (req, res, next) => {
  passport.authenticate("google", { session: false }, (err, user) => {
    if (err || !user) {
      console.error("❌ Google OAuth authentication failed:", err);
      return res.redirect("/login?error=authentication_failed");
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, userType: user.userType },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Redirect user to frontend with token
    const redirectUrl = user.userType === "teacher" ? "/teacher-dashboard" : "/student-dashboard";
    res.redirect(`${redirectUrl}?token=${token}`);
  })(req, res, next);
});

module.exports = router;