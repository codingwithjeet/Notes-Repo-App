const express = require("express");
const noteController = require("../controllers/noteController");
const { authenticateToken, authorizeRole } = require("../middleware/authMiddleware");

const router = express.Router();

// 📝 Notes Routes - All authenticated users can access
router.get("/", authenticateToken, noteController.getNotes);
router.get("/:id", authenticateToken, noteController.getNoteById);

// 📝 Notes Routes - Only teachers can modify notes
router.put("/:id", 
  authenticateToken, 
  authorizeRole(['teacher']),
  noteController.updateNote
);

router.delete("/:id", 
  authenticateToken, 
  authorizeRole(['teacher']),
  noteController.deleteNote
);

module.exports = router;
