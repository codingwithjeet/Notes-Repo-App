const mongoose = require("mongoose");

const noteSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true
  },
  description: {
    type: String,
    required: [true, 'Description is required'],
    trim: true
  },
  category: {
    type: String,
    required: [true, 'Category is required'],
    trim: true
  },
  teacherId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Teacher ID is required']
  },
  teacher: {
    type: String,
    required: [true, 'Teacher name is required']
  },
  uploadDate: {
    type: Date,
    default: Date.now
  },
  filePath: {
    type: String,
    required: [true, 'File path is required']
  },
  fileOriginalName: {
    type: String,
    required: [true, 'Original file name is required']
  },
  fileSize: {
    type: Number,
    required: [true, 'File size is required']
  },
  fileType: {
    type: String,
    required: [true, 'File type is required']
  }
}, {
  // Enable virtuals
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Add a virtual field for download URL
noteSchema.virtual('downloadUrl').get(function() {
  return `/api/notes/download/${this._id}`;
});

module.exports = mongoose.model("Note", noteSchema);
