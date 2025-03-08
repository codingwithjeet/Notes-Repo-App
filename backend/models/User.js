const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true },
    password: { type: String, required: function() { return !this.googleId; } }, // Only required if not OAuth
    googleId: { type: String, unique: true, sparse: true },
    email: { type: String, required: true, unique: true },
    userType: { type: String, enum: ['student', 'teacher'], required: true }, // New field for user type
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", UserSchema);