const express = require("express");
const multer = require("multer");
const noteController = require("../controllers/noteController");
const path = require("path");
const fs = require("fs");
const { authenticateToken, authorizeRole } = require("../middleware/authMiddleware");

const router = express.Router();

// Ensure uploads directory exists
const uploadsDir = process.env.UPLOADS_PATH || "./uploads";
if (!fs.existsSync(uploadsDir)) {
  try {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log(`✅ Uploads directory created at ${uploadsDir}`);
  } catch (error) {
    console.error(`❌ Error creating uploads directory: ${error.message}`);
  }
}

// Configure storage for file uploads
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    // Make sure the directory exists
    if (!fs.existsSync(uploadsDir)) {
      return cb(new Error(`Uploads directory ${uploadsDir} does not exist`), null);
    }
    cb(null, uploadsDir);
  },
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
  const allowedExtensions = ['.pdf', '.docx', '.txt', '.doc', '.ppt', '.pptx'];
  const allowedMimeTypes = [
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/msword",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "text/plain",
  ];
  
  if (allowedExtensions.includes(ext) && allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`Invalid file type. Only ${allowedExtensions.join(', ')} files are allowed!`), false);
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

// Error handling middleware for multer
const handleMulterErrors = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    // A Multer error occurred when uploading
    console.error('Multer error:', err);
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File is too large. Maximum size is 10MB.' });
    }
    return res.status(400).json({ message: `Upload error: ${err.message}` });
  } else if (err) {
    // An unknown error occurred
    console.error('Unknown error during upload:', err);
    return res.status(500).json({ message: err.message || 'Internal server error during file upload' });
  }
  
  // No error, continue
  next();
};

// 📤 Upload Routes - Teachers only can upload notes
router.post("/", 
  authenticateToken, 
  authorizeRole(['teacher']),
  (req, res, next) => {
    console.log('Processing file upload request');
    upload.single("file")(req, res, (err) => {
      if (err) {
        console.error('Error during upload:', err);
        return res.status(400).json({ message: err.message || 'File upload failed' });
      }
      next();
    });
  },
  (req, res, next) => {
    if (!req.file) {
      console.error('No file in the request');
      return res.status(400).json({ message: 'No file uploaded' });
    }
    console.log('File uploaded successfully:', req.file.filename);
    next();
  },
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