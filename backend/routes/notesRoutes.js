const express = require("express");
const noteController = require("../controllers/noteController");
const jwt = require("jsonwebtoken");

const router = express.Router();

// Middleware to check JWT and attach userId to request
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Access denied. No token provided." });
    }

    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId; // Ensure this matches your token payload structure

    next();
  } catch (error) {
    console.error("Authentication error:", error.message);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// 📝 Notes Routes
router.get("/", authenticate, noteController.getNotes);
router.get("/:id", authenticate, noteController.getNoteById);
router.put("/:id", authenticate, noteController.updateNote);
router.delete("/:id", authenticate, noteController.deleteNote);

module.exports = router;
