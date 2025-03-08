const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
  {
    username: { type: String, required: true },
    password: { type: String, required: true },
    googleId: { type: String, unique: true, sparse: true },
    email: { type: String, required: true, unique: true },
    userType: { type: String, enum: ['student', 'teacher'], required: true }, // New field for user type
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", UserSchema);