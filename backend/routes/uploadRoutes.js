const express = require("express");
const multer = require("multer");
const noteController = require("../controllers/noteController");
const path = require("path");
const { authenticateToken, authorizeRole } = require("../middleware/authMiddleware");

const router = express.Router();

// Configure storage for file uploads
const storage = multer.diskStorage({
  destination: process.env.UPLOADS_PATH || "uploads/",
  filename: (req, file, cb) => {
    // Create a safe filename
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});

// Validate file type by both extension and MIME type
const fileFilter = (req, file, cb) => {
  // Get file extension
  const ext = path.extname(file.originalname).toLowerCase();
  
  // Check both extension and MIME type
  const allowedExtensions = ['.pdf', '.docx', '.txt'];
  const allowedMimeTypes = [
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
  ];
  
  if (allowedExtensions.includes(ext) && allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("Only PDF, DOCX, and TXT files are allowed!"), false);
  }
};

// Configure multer with our settings
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB size limit
  },
});

// 📤 Upload Routes - Teachers only can upload notes
router.post("/", 
  authenticateToken, 
  authorizeRole(['teacher']), 
  upload.single("file"), 
  noteController.uploadNote
);

// Get teacher's uploaded notes
router.get("/teacher-notes", 
  authenticateToken, 
  authorizeRole(['teacher']), 
  noteController.getTeacherNotes
);

// Get student-accessible notes
router.get("/user-notes", 
  authenticateToken, 
  noteController.getUserNotes
);

module.exports = router;