const Note = require("../models/Note");

// Create a new note (from file upload)
exports.createNote = async (req, res) => {
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
      user: req.userId, // Ensure userId is assigned from authentication middleware
    });

    await newNote.save();
    res.status(201).json({ message: "Note created successfully", note: newNote });

    console.log("✅ New note created:", newNote);
  } catch (error) {
    console.error("❌ Error creating note:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Get all notes for authenticated user
exports.getNotes = async (req, res) => {
  try {
    const notes = await Note.find({ user: req.userId });
    res.status(200).json(notes);
  } catch (error) {
    console.error("❌ Error fetching notes:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Get a specific note by ID (only for the owner)
exports.getNoteById = async (req, res) => {
  try {
    const note = await Note.findOne({ _id: req.params.id, user: req.userId });

    if (!note) {
      return res.status(404).json({ message: "Note not found or unauthorized" });
    }

    res.status(200).json(note);
  } catch (error) {
    console.error("❌ Error fetching note by ID:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Update a note
exports.updateNote = async (req, res) => {
  try {
    const note = await Note.findOne({ _id: req.params.id, user: req.userId });

    if (!note) {
      return res.status(404).json({ message: "Note not found or unauthorized" });
    }

    // Validate updated fields (only allow valid fields to be updated)
    const { title, description, category } = req.body;

    if (title && (title.length < 3 || title.length > 100)) {
      return res.status(400).json({ message: "Title must be between 3 and 100 characters" });
    }

    if (description && (description.length < 10 || description.length > 500)) {
      return res.status(400).json({ message: "Description must be between 10 and 500 characters" });
    }

    Object.assign(note, req.body);
    await note.save();

    res.status(200).json({ message: "Note updated successfully", note });
  } catch (error) {
    console.error("❌ Error updating note:", error);
    res.status(400).json({ message: "Failed to update note" });
  }
};

// Delete a note
exports.deleteNote = async (req, res) => {
  try {
    const note = await Note.findOneAndDelete({ _id: req.params.id, user: req.userId });

    if (!note) {
      return res.status(404).json({ message: "Note not found or unauthorized" });
    }

    res.status(200).json({ message: "Note deleted successfully", deletedNote: note });
  } catch (error) {
    console.error("❌ Error deleting note:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Export all functions
module.exports = {
  createNote: exports.createNote,
  getNotes: exports.getNotes,
  getNoteById: exports.getNoteById,
  updateNote: exports.updateNote,
  deleteNote: exports.deleteNote,
};
