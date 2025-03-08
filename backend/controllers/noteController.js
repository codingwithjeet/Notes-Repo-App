const Note = require("../models/Note");
const User = require("../models/User");
const fs = require('fs');
const path = require('path');

// Upload a new note (for teachers)
exports.uploadNote = async (req, res) => {
  try {
    console.log('Starting note upload process');
    
    if (!req.file) {
      console.error('No file found in request');
      return res.status(400).json({ message: 'No file uploaded' });
    }

    console.log('File details:', {
      path: req.file.path,
      originalname: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype
    });

    const { title, description, category } = req.body;
    console.log('Note details:', { title, description, category });
    
    if (!title || !description || !category) {
      // Delete the uploaded file if request is invalid
      console.error('Missing required fields');
      if (req.file && req.file.path) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ message: 'Please provide title, description, and category' });
    }

    console.log('Request user:', req.user);

    // Make sure we have all required user data
    if (!req.user || !req.userId) {
      console.error('Missing user data in request');
      if (req.file && req.file.path) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(401).json({ message: 'User authentication data missing' });
    }

    // Create new note
    const newNote = new Note({
      title,
      description,
      category,
      teacherId: req.userId,
      teacher: req.user.email || 'Teacher',
      filePath: req.file.path,
      fileOriginalName: req.file.originalname,
      fileSize: req.file.size,
      fileType: req.file.mimetype
    });

    console.log('Created new note object:', newNote);

    // Save to database
    const savedNote = await newNote.save();
    console.log('Note saved successfully with ID:', savedNote._id);
    
    res.status(201).json({
      message: 'Note uploaded successfully',
      note: {
        id: savedNote._id,
        title: savedNote.title,
        description: savedNote.description,
        category: savedNote.category,
        uploadDate: savedNote.uploadDate,
        downloadUrl: `/api/notes/download/${savedNote._id}`
      }
    });
  } catch (error) {
    console.error('Error uploading note:', error);
    
    // Delete the uploaded file if saving to database fails
    if (req.file && req.file.path) {
      try {
        fs.unlinkSync(req.file.path);
        console.log('Deleted temporary file after error:', req.file.path);
      } catch (unlinkError) {
        console.error('Error deleting temporary file:', unlinkError);
      }
    }
    
    // Send detailed error response for debugging
    if (error.name === 'ValidationError') {
      const validationErrors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({ 
        message: 'Validation error', 
        errors: validationErrors,
        details: error.message
      });
    }
    
    res.status(500).json({ 
      message: 'Failed to upload note', 
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
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
    const teacherId = req.userId;
    const notes = await Note.find({ teacherId })
      .sort({ uploadDate: -1 });
    
    res.status(200).json(notes);
  } catch (error) {
    console.error('Error fetching teacher notes:', error);
    res.status(500).json({ message: 'Failed to fetch your notes', error: error.message });
  }
};

// Get notes for students to access
exports.getUserNotes = async (req, res) => {
  try {
    const notes = await Note.find({})
      .select('title description category uploadDate teacher')
      .sort({ uploadDate: -1 });
    
    res.status(200).json(notes);
  } catch (error) {
    console.error('Error fetching notes:', error);
    res.status(500).json({ message: 'Failed to fetch notes', error: error.message });
  }
};

// Get a specific note
exports.getNote = async (req, res) => {
  try {
    const noteId = req.params.id;
    const note = await Note.findById(noteId);
    
    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }
    
    res.status(200).json(note);
  } catch (error) {
    console.error('Error fetching note:', error);
    res.status(500).json({ message: 'Failed to fetch note', error: error.message });
  }
};

// Download a note
exports.downloadNote = async (req, res) => {
  try {
    const noteId = req.params.id;
    const note = await Note.findById(noteId);
    
    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }
    
    // Check if file exists
    if (!fs.existsSync(note.filePath)) {
      return res.status(404).json({ message: 'File not found' });
    }
    
    // Set appropriate headers
    res.setHeader('Content-Disposition', `attachment; filename="${note.fileOriginalName}"`);
    res.setHeader('Content-Type', note.fileType);
    
    // Stream the file to the client
    const fileStream = fs.createReadStream(note.filePath);
    fileStream.pipe(res);
  } catch (error) {
    console.error('Error downloading note:', error);
    res.status(500).json({ message: 'Failed to download note', error: error.message });
  }
};

// Delete a note (teachers only)
exports.deleteNote = async (req, res) => {
  try {
    const noteId = req.params.id;
    const teacherId = req.userId;
    
    const note = await Note.findById(noteId);
    
    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }
    
    // Ensure the teacher owns this note
    if (note.teacherId.toString() !== teacherId) {
      return res.status(403).json({ message: 'You are not authorized to delete this note' });
    }
    
    // Delete the file from the filesystem
    if (fs.existsSync(note.filePath)) {
      fs.unlinkSync(note.filePath);
    }
    
    // Delete from database
    await Note.findByIdAndDelete(noteId);
    
    res.status(200).json({ message: 'Note deleted successfully' });
  } catch (error) {
    console.error('Error deleting note:', error);
    res.status(500).json({ message: 'Failed to delete note', error: error.message });
  }
};

// Export all functions
module.exports = {
  uploadNote: exports.uploadNote,
  getNotes: exports.getNotes,
  getTeacherNotes: exports.getTeacherNotes,
  getUserNotes: exports.getUserNotes,
  getNote: exports.getNote,
  downloadNote: exports.downloadNote,
  deleteNote: exports.deleteNote,
};