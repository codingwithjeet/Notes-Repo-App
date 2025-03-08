const Note = require("../models/Note");
const User = require("../models/User");
const fs = require('fs');
const path = require('path');

// Upload a new note (for teachers)
exports.uploadNote = async (req, res) => {
  try {
    const { title, description, category } = req.body;

    if (!title || !description || !category || !req.file) {
      return res.status(400).json({ message: "All fields (title, description, category, and file) are required" });
    }

    // Validate title length
    if (title.length < 3 || title.length > 100) {
      return res.status(400).json({ message: "Title must be between 3 and 100 characters" });
    }

    // Validate description length
    if (description.length < 10 || description.length > 500) {
      return res.status(400).json({ message: "Description must be between 10 and 500 characters" });
    }

    // File path saved by multer
    const fileUrl = req.file.path;

    const newNote = new Note({
      title,
      description,
      category,
      fileUrl,
      user: req.user.userId, // Now using req.user.userId from JWT
    });

    await newNote.save();
    res.status(201).json({ message: "Note created successfully", note: newNote });

    console.log("✅ New note created:", newNote);
  } catch (error) {
    console.error("❌ Error creating note:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Get all notes (for admin purposes)
exports.getNotes = async (req, res) => {
  try {
    // Using req.user.userId from JWT
    const notes = await Note.find();
    res.status(200).json(notes);
  } catch (error) {
    console.error("❌ Error fetching notes:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Get notes uploaded by the teacher
exports.getTeacherNotes = async (req, res) => {
  try {
    // Get notes created by this teacher
    const notes = await Note.find({ user: req.user.userId });
    res.status(200).json(notes);
  } catch (error) {
    console.error("❌ Error fetching teacher notes:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Get notes for students to access
exports.getUserNotes = async (req, res) => {
  try {
    // For students, return all notes
    // For teachers, return their own notes
    let notes;
    
    if (req.user.userType === 'student') {
      notes = await Note.find().populate('user', 'username');
    } else {
      notes = await Note.find({ user: req.user.userId });
    }
    
    res.status(200).json(notes);
  } catch (error) {
    console.error("❌ Error fetching user notes:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Get a specific note
exports.getNoteById = async (req, res) => {
  try {
    const note = await Note.findById(req.params.id);
    
    if (!note) {
      return res.status(404).json({ message: "Note not found" });
    }
    
    // For non-teacher users, check if they have access
    if (req.user.userType !== 'teacher' && note.user.toString() !== req.user.userId) {
      // Check if note is marked as restricted
      if (note.isRestricted) {
        return res.status(403).json({ message: "You don't have permission to access this note" });
      }
    }
    
    res.status(200).json(note);
  } catch (error) {
    console.error("❌ Error fetching note:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Update a note (teachers only)
exports.updateNote = async (req, res) => {
  try {
    const { title, description, category, isRestricted } = req.body;
    
    // Find the note
    const note = await Note.findById(req.params.id);
    
    if (!note) {
      return res.status(404).json({ message: "Note not found" });
    }
    
    // Check if user owns this note
    if (note.user.toString() !== req.user.userId) {
      return res.status(403).json({ message: "You don't have permission to update this note" });
    }
    
    // Update fields if provided
    if (title) note.title = title;
    if (description) note.description = description;
    if (category) note.category = category;
    if (isRestricted !== undefined) note.isRestricted = isRestricted;
    
    await note.save();
    res.status(200).json({ message: "Note updated successfully", note });
  } catch (error) {
    console.error("❌ Error updating note:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Delete a note (teachers only)
exports.deleteNote = async (req, res) => {
  try {
    // Find the note
    const note = await Note.findById(req.params.id);
    
    if (!note) {
      return res.status(404).json({ message: "Note not found" });
    }
    
    // Check if user owns this note
    if (note.user.toString() !== req.user.userId) {
      return res.status(403).json({ message: "You don't have permission to delete this note" });
    }
    
    // Delete the associated file if it exists
    if (note.fileUrl) {
      const filePath = path.resolve(note.fileUrl);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }
    
    // Delete the note from the database
    await Note.findByIdAndDelete(req.params.id);
    
    res.status(200).json({ message: "Note deleted successfully" });
  } catch (error) {
    console.error("❌ Error deleting note:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Export all functions
module.exports = {
  uploadNote: exports.uploadNote,
  getNotes: exports.getNotes,
  getTeacherNotes: exports.getTeacherNotes,
  getUserNotes: exports.getUserNotes,
  getNoteById: exports.getNoteById,
  updateNote: exports.updateNote,
  deleteNote: exports.deleteNote,
};