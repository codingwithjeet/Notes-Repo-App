const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
  {
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    username: { type: String, required: true, unique: true, trim: true, minlength: 3 },
    password: { type: String, required: function() { return !this.googleId; } }, // Only required if not OAuth
    googleId: { type: String, unique: true, sparse: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    userType: { type: String, enum: ['student', 'teacher'], required: true }, // New field for user type
    class: { 
      type: String, 
      enum: ['B.Sc St-Cs', 'BCA', 'B.Sc Mt-Cs', 'B.Sc Eco-St'],
      required: function() { return this.userType === 'student'; }
    },
    resetToken: { type: String, sparse: true },
    resetTokenExpiry: { type: Date, sparse: true },
    createdAt: { type: Date, default: Date.now }
  },
  { 
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

// Virtual for full name
UserSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

module.exports = mongoose.model("User", UserSchema);