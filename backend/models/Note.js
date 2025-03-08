const mongoose = require("mongoose");

const NoteSchema = new mongoose.Schema({
  title: { type: String, required: true, index: true },
  description: { type: String, required: true, maxlength: 500 },
  category: {
    type: String,
    required: true,
    enum: ["Math", "Science", "History", "English", "Programming", "Other"],
    default: "Other",
  },
  fileUrl: {
    type: String,
    required: true,
    validate: {
      validator: function (v) {
        return /^(https?:\/\/|\/uploads\/)/.test(v);
      },
      message: "Invalid file URL",
    },
  },
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  isRestricted: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Note", NoteSchema);
