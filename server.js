require("dotenv").config(); // ⚙️ Load environment variables

const express = require("express"); // 🚀 Express framework
const mongoose = require("mongoose"); // 🗄️ MongoDB ODM
const cors = require("cors"); // 🔄 Enable CORS
const path = require("path");
const passport = require("passport");
require("./backend/passport"); // Import passport config

const app = express();

// Import routes 📂
const authRoutes = require('./backend/routes/authRoutes'); // 🔒 Auth routes
const authController = require('./backend/controllers/authController'); // 🔒 Auth controller
const uploadRoutes = require("./backend/routes/uploadRoutes"); // 📤 Upload routes
const notesRoutes = require("./backend/routes/notesRoutes"); // 📝 Notes routes

const PORT = process.env.PORT || 3000; // 🎯 Set port

// Middleware 🔧
app.use(express.json());

// CORS Configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',') 
  : ['http://localhost:3000', 'http://localhost:5000'];

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));

// Security headers middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Serve static files based on environment
if (process.env.NODE_ENV === 'production') {
  // Serve built files from frontend/dist in production
  app.use(express.static(path.join(__dirname, 'frontend', 'dist'), {
    maxAge: '1h',
    etag: true,
    lastModified: true
  }));
} else {
  // Serve static files from the 'frontend/public' directory in development
  app.use(express.static(path.join(__dirname, 'frontend', 'public'), {
    maxAge: '1h',
    etag: true,
    lastModified: true
  }));

  // Serve HTML files from 'frontend/src' directory in development
  app.use(express.static(path.join(__dirname, 'frontend', 'src'), {
    index: false,
    extensions: ['html']
  }));
}

// Connect to MongoDB 🔗
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Connected!"))
  .catch((err) => console.error("❌ Database Connection Error:", err));

// Route registration 🚦
app.use("/api/auth", authRoutes);
app.use("/api/auth", authController);
app.use("/api/upload", uploadRoutes);
app.use("/api/notes", notesRoutes);

// HTML route handlers 🌐
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'src', 'index.html'));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'src', 'login.html'));
});

app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'src', 'signup.html'));
});

app.get("/student-dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'src', 'student-dashboard.html'));
});

app.get("/teacher-dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'src', 'teacher-dashboard.html'));
});

app.get("/upload", (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'src', 'upload.html'));
});

// Error handler for HTML routes
app.use((req, res, next) => {
  if (req.accepts('html')) {
    res.status(404).sendFile(path.join(__dirname, 'frontend', 'src', 'index.html'));
    return;
  }
  next();
});

// Start server 🚀
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}!`));

app.use(passport.initialize());
