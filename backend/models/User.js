const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true, trim: true, minlength: 3 },
    password: { type: String, required: function() { return !this.googleId; } }, // Only required if not OAuth
    googleId: { type: String, unique: true, sparse: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    userType: { type: String, enum: ['student', 'teacher'], required: true }, // New field for user type
    resetToken: { type: String, sparse: true },
    resetTokenExpiry: { type: Date, sparse: true },
    createdAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", UserSchema);