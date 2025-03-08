const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const passport = require("passport");
const authenticateToken = require("../middleware/authMiddleware"); // Import the authenticateToken middleware

const router = express.Router();


// Helper function to create a JWT token
const generateToken = (user) => {
  return jwt.sign(
    { userId: user._id, email: user.email, userType: user.userType },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
};

router.get("/signup.html", (req, res) => {
  res.sendFile(path.resolve(__dirname, '..', '..', 'frontend', 'src', 'signup.html'));
});


router.get("/user/me", authenticateToken, async (req, res) => { 


    try {
    const user = await User.findById(req.user.userId).select("-password"); 
    if (!user) return res.status(404).json({ message: "User not found" });

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
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        message: "Email and password are required" 
      });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    }

    // For Google OAuth users who don't have a password
    if (!user.password) {
      return res.status(401).json({ 
        success: false,
        message: "Please login with Google" 
      });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    }

    // Generate token
    const token = generateToken(user);

    // Determine redirect URL
    let redirectUrl = "/index.html";
    if (user.userType === "student") {
      redirectUrl = "/student-dashboard.html";
    } else if (user.userType === "teacher") {
      redirectUrl = "/teacher-dashboard.html";
    }

    // Send response
    res.json({
      success: true,
      token,
      userType: user.userType,
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        userType: user.userType
      },
      location: redirectUrl
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ 
      success: false,
      message: "Server error during login" 
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

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already registered" });
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

    // Generate token
    const token = generateToken(user);

    // Send response
    res.status(201).json({
      token,
      userType: user.userType,
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        userType: user.userType
      }
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Server error during registration" });
  }
});

// Get current user
router.get("/me", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select("-password");
    
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (error) {
    console.error("Get user error:", error);
    res.status(500).json({ message: "Server error while getting user data" });
  }
});

// Google OAuth routes
router.get("/google",
  passport.authenticate("google", {
    scope: ["profile", "email"]
  })
);

router.get("/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: "/login" }),
  (req, res) => {
    try {
      const token = generateToken(req.user);
      const redirectUrl = req.user.userType === "teacher" ? "/teacher-dashboard" : "/student-dashboard";
      
      // Redirect with token
      res.redirect(`${redirectUrl}?token=${token}`);
    } catch (error) {
      console.error("Google callback error:", error);
      res.redirect("/login?error=auth_failed");
    }
  }
);

// Check if user exists by email
router.post("/check-user", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required"
      });
    }

    // Check if user exists
    const user = await User.findOne({ email }).select("email userType");
    
    res.json({
      success: true,
      exists: !!user,
      userType: user?.userType
    });
  } catch (error) {
    console.error("Check user error:", error);
    res.status(500).json({
      success: false,
      message: "Server error while checking user"
    });
  }
});

// 🔥 Global error handler middleware
router.use((err, req, res, next) => {
  res.status(500).json({ message: "Internal Server Error" });
});

module.exports = router;
