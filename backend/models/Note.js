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
  tags: [{
    type: String,
    trim: true
  }],
  topic: {
    type: String,
    trim: true
  },
  unit: {
    type: String,
    trim: true
  },
  academicYear: {
    type: String,
    enum: ['1st year', '2nd year', '3rd year'],
    required: [true, 'Academic year is required']
  },
  semester: {
    type: Number,
    enum: [1, 2, 3, 4, 5, 6],
    required: [true, 'Semester is required']
  },
  isClassSpecific: {
    type: Boolean,
    default: false
  },
  allowedClasses: [{
    type: String,
    trim: true
  }],
  teacherId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Teacher ID is required']
  },
  teacher: {
    type: String,
    required: false
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

// Add a virtual field for download URL (authenticated users only)
noteSchema.virtual('downloadUrl').get(function() {
  return `/api/notes/download/${this._id}`;
});

module.exports = mongoose.model("Note", noteSchema);
