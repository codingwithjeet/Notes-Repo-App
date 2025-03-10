const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const passport = require("passport");
const path = require("path");
const crypto = require('crypto');
const { authenticateToken, authorizeRole, verifyRefreshToken } = require("../middleware/authMiddleware");

const router = express.Router();

// Generate CSRF token
const generateCSRFToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Helper function to create JWT tokens
const generateTokens = (user) => {
  // Access token - short lived (from env or default to 15 minutes)
  const accessTokenExpiry = process.env.ACCESS_TOKEN_EXPIRY || '3600'; // 60 minutes in seconds by default
  
  // Create the token payload
  const payload = { 
    userId: user._id, 
    email: user.email, 
    userType: user.userType 
  };
  
  // Log the payload and expiration for debugging
  console.log("Token payload:", payload);
  console.log("Token will expire in:", accessTokenExpiry, "seconds");
  console.log("Token will expire at:", new Date(Date.now() + parseInt(accessTokenExpiry) * 1000));
  
  const accessToken = jwt.sign(
    payload,
    process.env.JWT_SECRET,
    { expiresIn: `${accessTokenExpiry}s` }
  );
  
  // Refresh token - longer lived (from env or default to 7 days)
  const refreshTokenExpiry = process.env.REFRESH_TOKEN_EXPIRY || '604800'; // 7 days in seconds
  
  const refreshToken = jwt.sign(
    { userId: user._id },
    process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
    { expiresIn: `${refreshTokenExpiry}s` }
  );
  
  // Generate CSRF token
  const csrfToken = generateCSRFToken();
  
  return { accessToken, refreshToken, csrfToken };
};

// Cookie options for HTTP-only cookies
const cookieOptions = {
  httpOnly: process.env.COOKIE_HTTP_ONLY === 'true', // Makes cookie inaccessible to client-side JavaScript
  secure: process.env.COOKIE_SECURE === 'true', // Only send cookie over HTTPS in production
  sameSite: process.env.COOKIE_SAME_SITE || 'strict', // Protects against CSRF attacks
  maxAge: (parseInt(process.env.REFRESH_TOKEN_EXPIRY) || 604800) * 1000, // Convert seconds to milliseconds
  path: '/' // Cookie available across the entire site
};

router.get("/signup.html", (req, res) => {
  res.sendFile(path.resolve(__dirname, '..', '..', 'frontend', process.env.NODE_ENV === 'production' ? 'dist' : 'src', 'signup.html'));
});

router.get("/user/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json(user);
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// 🔒 Login route
router.post("/login", async (req, res) => {
  try {
    console.log("Login attempt:", req.body.email);
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      console.log("Missing email or password");
      return res.status(400).json({ 
        success: false,
        message: "Email and password are required" 
      });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      console.log("User not found:", email);
      return res.status(401).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    }

    // For Google OAuth users who don't have a password
    if (!user.password) {
      console.log("User has no password (OAuth user):", email);
      return res.status(401).json({ 
        success: false,
        message: "Please login with Google" 
      });
    }

    // Verify password
    console.log("Verifying password for:", email);
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log("Password verification failed for:", email);
      return res.status(401).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    }
    
    console.log("Password verified successfully for:", email);

    // Generate tokens
    const { accessToken, refreshToken, csrfToken } = generateTokens(user);

    // Set refresh token as HTTP-only cookie
    res.cookie('refreshToken', refreshToken, cookieOptions);
    
    // Set CSRF token as a regular cookie (accessible to JavaScript)
    res.cookie('csrf_token', csrfToken, { 
      ...cookieOptions,
      httpOnly: false // Make accessible to client JavaScript
    });

    // Log token information (remove in production)
    console.log(`Login successful for ${email}. Tokens generated.`);
    console.log(`CSRF token set: ${csrfToken.substring(0, 10)}...`);

    // Determine redirect URL
    let redirectUrl = "/index.html";
    if (user.userType === "student") {
      redirectUrl = "/student-dashboard";
    } else if (user.userType === "teacher") {
      redirectUrl = "/teacher-dashboard";
    }

    // Send response with access token (but not refresh token)
    res.json({
      success: true,
      accessToken: accessToken, // Use consistent naming (accessToken instead of token)
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        userType: user.userType
      },
      csrfToken: csrfToken,
      location: redirectUrl
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error during login",
      details: error.message
    });
  }
});

// Refresh token endpoint
router.post("/refresh-token", verifyRefreshToken, async (req, res) => {
  try {
    // Get user from database
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    // Generate new tokens
    const { accessToken, refreshToken, csrfToken } = generateTokens(user);
    
    // Set new refresh token as HTTP-only cookie
    res.cookie('refreshToken', refreshToken, cookieOptions);
    
    // Update CSRF token
    res.cookie('csrf_token', csrfToken, { 
      ...cookieOptions,
      httpOnly: false 
    });
    
    // Log refreshed tokens (remove in production)
    console.log(`Tokens refreshed for user ${user._id}`);
    console.log(`New CSRF token set: ${csrfToken.substring(0, 10)}...`);
    
    // Send new access token with consistent naming
    res.json({ 
      accessToken: accessToken,
      csrfToken: csrfToken 
    });
  } catch (error) {
    console.error("Token refresh error:", error);
    res.status(500).json({ 
      message: "Error refreshing token",
      details: error.message
    });
  }
});

// Logout route
router.post("/logout", (req, res) => {
  // Clear the refresh token cookie
  res.clearCookie('refreshToken', {
    ...cookieOptions,
    maxAge: 0
  });
  
  // Clear CSRF token
  res.clearCookie('csrf_token', {
    ...cookieOptions,
    httpOnly: false,
    maxAge: 0
  });
  
  res.json({ success: true, message: "Logged out successfully" });
});

// CSRF token endpoint
router.get("/csrf-token", (req, res) => {
  try {
    // Generate a new CSRF token
    const csrfToken = generateCSRFToken();
    
    // Set CSRF token as a cookie accessible to JavaScript
    res.cookie('csrf_token', csrfToken, { 
      ...cookieOptions,
      httpOnly: false // Make accessible to client JavaScript
    });
    
    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error generating CSRF token:", error);
    res.status(500).json({ 
      message: "Error generating security token",
      details: error.message
    });
  }
});

// 🔐 Registration route
router.post("/register", async (req, res) => {
  try {
    const { username, email, password, userType } = req.body;

    // Validate input
    if (!username || !email || !password || !userType) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (!["student", "teacher"].includes(userType)) {
      return res.status(400).json({ message: "Invalid user type" });
    }
    
    // Validate password strength
    const passwordRegex = /^(?=.*[0-9])(?=.*[A-Z]).{6,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({ 
        message: "Password must be at least 6 characters long, contain at least one number and one uppercase letter." 
      });
    }

    // Check if email exists
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // Check if username exists
    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.status(400).json({ message: "Username already taken" });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      userType
    });

    await user.save();

    // Generate tokens
    const { accessToken, refreshToken, csrfToken } = generateTokens(user);
    
    // Set refresh token as HTTP-only cookie
    res.cookie('refreshToken', refreshToken, cookieOptions);
    
    // Set CSRF token as a regular cookie (accessible to JavaScript)
    res.cookie('csrf_token', csrfToken, { 
      ...cookieOptions,
      httpOnly: false // Make accessible to client JavaScript
    });
    
    // Log token information (remove in production)
    console.log(`Registration successful for ${email}. Tokens generated.`);
    console.log(`CSRF token set: ${csrfToken.substring(0, 10)}...`);

    // Send response
    res.status(201).json({
      token: accessToken,
      userType: user.userType,
      csrfToken: csrfToken,
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        userType: user.userType
      }
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Server error during registration", error: error.message });
  }
});

// Get current user
router.get("/me", authenticateToken, async (req, res) => {
  try {
    // Get full user data from database
    const user = await User.findById(req.user.userId).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Send complete user data (excluding password)
    res.json({
      userId: user._id,
      email: user.email,
      userType: user.userType,
      username: user.username,
      name: user.name,
      fullName: user.fullName
    });
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Forgot Password - Request reset
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    // Validate email
    if (!email || !/\S+@\S+\.\S+/.test(email)) {
      return res.status(400).json({ message: "A valid email address is required." });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "No account found with this email address." });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now

    // Save reset token and expiry to user
    user.resetToken = resetToken;
    user.resetTokenExpiry = resetTokenExpiry;
    await user.save();

    // TODO: Send email with reset link
    // For now, we'll just return the token in the response
    // In production, you should send this via email
    res.json({ 
      message: "Password reset instructions have been sent to your email.",
      resetToken // Remove this in production
    });
  } catch (error) {
    console.error("Password reset request error:", error);
    res.status(500).json({ message: "Error processing password reset request." });
  }
});

// Reset Password - Using token
router.post("/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    // Validate password
    if (!newPassword) {
      return res.status(400).json({ message: "New password is required." });
    }

    if (!isPasswordStrong(newPassword)) {
      return res.status(400).json({ 
        message: "Password must be at least 6 characters long, contain at least one number and one uppercase letter." 
      });
    }

    // Find user with valid reset token
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired reset token." });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user's password and clear reset token
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.json({ message: "Password has been reset successfully." });
  } catch (error) {
    console.error("Password reset error:", error);
    res.status(500).json({ message: "Error resetting password." });
  }
});

module.exports = router;