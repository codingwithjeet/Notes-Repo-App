const express = require("express");
const noteController = require("../controllers/noteController");
const { authenticateToken, authorizeRole } = require("../middleware/authMiddleware");

const router = express.Router();

// Get all user-accessible notes (for students)
router.get("/user-notes", 
  authenticateToken, 
  noteController.getUserNotes
);

// Get teacher's uploaded notes
router.get("/teacher-notes", 
  authenticateToken, 
  authorizeRole(['teacher']), 
  noteController.getTeacherNotes
);

// Download a note (authenticated users only)
router.get("/download/:id", 
  authenticateToken, 
  noteController.downloadNote
);

// Get a specific note
router.get("/:id", 
  authenticateToken, 
  noteController.getNote
);

// Delete a note (teachers only)
router.delete("/:id", 
  authenticateToken, 
  authorizeRole(['teacher']), 
  noteController.deleteNote
);

module.exports = router;
