const Note = require("../models/Note");
const User = require("../models/User");
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

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

    const { title, description, category, tags, topic, unit, academicYear, semester, isClassSpecific, allowedClasses } = req.body;
    console.log('Note details:', { title, description, category, tags, topic, unit, academicYear, semester, isClassSpecific, allowedClasses });
    
    if (!title || !description || !category || !academicYear || !semester) {
      // Delete the uploaded file if request is invalid
      console.error('Missing required fields');
      if (req.file && req.file.path) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ message: 'Please provide title, description, category, academic year, and semester' });
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

    // Parse tags if provided
    const parsedTags = tags ? JSON.parse(tags) : [];
    
    // Parse allowed classes if provided
    const parsedAllowedClasses = allowedClasses ? JSON.parse(allowedClasses) : [];

    // Create new note
    const newNote = new Note({
      title,
      description,
      category,
      tags: parsedTags,
      topic,
      unit,
      academicYear,
      semester: parseInt(semester),
      isClassSpecific: isClassSpecific === 'true',
      allowedClasses: parsedAllowedClasses,
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
    // Get the user's information
    const user = await User.findById(req.userId).select('userType class');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    let query = {};
    
    // For students, apply class-specific filtering
    if (user.userType === 'student') {
      if (!user.class) {
        return res.status(400).json({ message: 'Your class is not set. Please update your profile.' });
      }

      query = {
        $or: [
          { isClassSpecific: false }, // Include non-class-specific notes
          { 
            isClassSpecific: true,
            allowedClasses: user.class // Include class-specific notes for user's class
          }
        ]
      };
    }
    // For teachers, show all notes
    else if (user.userType === 'teacher') {
      query = {};
    }

    const notes = await Note.find(query)
      .select('_id title description category uploadDate topic academicYear semester fileSize fileOriginalName tags subject unit teacherId')
      .populate({
        path: 'teacherId',
        select: 'firstName lastName username email'
      })
      .sort({ uploadDate: -1 });
    
    // Transform the response to ensure all fields are properly formatted
    const formattedNotes = notes.map(note => {
      // Get teacher name from populated teacherId or fallback to stored teacher field
      let teacherName = 'Unknown Teacher';
      if (note.teacherId) {
        if (note.teacherId.firstName && note.teacherId.lastName) {
          teacherName = `${note.teacherId.firstName} ${note.teacherId.lastName}`;
        } else if (note.teacherId.username) {
          teacherName = note.teacherId.username;
        } else if (note.teacherId.email) {
          teacherName = note.teacherId.email;
        }
      } else if (note.teacher) {
        teacherName = note.teacher;
      }

      return {
        _id: note._id,
        title: note.title || 'Untitled Note',
        description: note.description || 'No description provided',
        category: note.category || 'Uncategorized',
        uploadDate: note.uploadDate,
        teacher: teacherName,
        topic: note.topic || 'Not specified',
        academicYear: note.academicYear || 'Not specified',
        semester: note.semester ? `Semester ${note.semester}` : 'Not specified',
        fileSize: note.fileSize,
        fileOriginalName: note.fileOriginalName || 'Unknown',
        tags: Array.isArray(note.tags) ? note.tags : [],
        subject: note.subject || note.category || 'Not specified',
        unit: note.unit || 'Not specified'
      };
    });
    
    res.status(200).json(formattedNotes);
  } catch (error) {
    console.error('Error fetching notes:', error);
    res.status(500).json({ message: 'Failed to fetch notes', error: error.message });
  }
};

// Get a specific note
exports.getNote = async (req, res) => {
  try {
    const noteId = req.params.id;
    
    if (!mongoose.Types.ObjectId.isValid(noteId)) {
      return res.status(400).json({ message: 'Invalid note ID format' });
    }
    
    const note = await Note.findById(noteId);
    
    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }
    
    // Return note with download URL
    res.status(200).json({
      ...note.toObject(),
      downloadUrl: `/api/notes/download/${note._id}`
    });
  } catch (error) {
    console.error('Error fetching note:', error);
    res.status(500).json({ message: 'Failed to fetch note', error: error.message });
  }
};

// Download a note
exports.downloadNote = async (req, res) => {
  try {
    const noteId = req.params.id;
    
    if (!mongoose.Types.ObjectId.isValid(noteId)) {
      return res.status(400).json({ message: 'Invalid note ID format' });
    }
    
    const note = await Note.findById(noteId);
    
    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }
    
    // Check if file exists
    if (!fs.existsSync(note.filePath)) {
      console.error(`File not found at path: ${note.filePath}`);
      return res.status(404).json({ message: 'File not found on server' });
    }
    
    // Get file stats
    const stats = fs.statSync(note.filePath);
    
    // Set appropriate headers
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(note.fileOriginalName)}"`);
    res.setHeader('Content-Type', note.fileType || 'application/octet-stream');
    res.setHeader('Content-Length', stats.size);
    
    // Optional: Log download activity
    console.log(`User ${req.userId || 'anonymous'} downloaded note: ${note.title} (${note._id})`);
    
    // Stream the file to the client
    const fileStream = fs.createReadStream(note.filePath);
    fileStream.on('error', (error) => {
      console.error('Error streaming file:', error);
      if (!res.headersSent) {
        res.status(500).json({ message: 'Error streaming file' });
      }
    });
    
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