const express = require("express");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const noteController = require("../controllers/noteController");

const router = express.Router();

// Configure storage for file uploads
const storage = multer.diskStorage({
  destination: process.env.UPLOADS_PATH || "uploads/",
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});

// Multer configuration with file type and size validation
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "application/pdf",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "text/plain",
    ];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Only PDF, DOCX, and TXT files are allowed"));
    }
    cb(null, true);
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

// Middleware for authentication
const authenticate = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Access denied. No token provided." });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId; // Ensure this matches your JWT payload structure

    next();
  } catch (error) {
    console.error("Authentication error:", error.message);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// Upload route: first process file upload, then call createNote controller
router.post(
  "/",
  upload.single("file"), // Ensure file upload runs before authentication
  authenticate,
  async (req, res, next) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "File upload is required" });
      }
      next();
    } catch (error) {
      console.error("File upload error:", error.message);
      return res.status(500).json({ message: "Error processing file upload" });
    }
  },
  noteController.createNote
);

module.exports = router;
