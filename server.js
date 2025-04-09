require("dotenv").config(); // ⚙️ Load environment variables

const express = require("express"); // 🚀 Express framework
const mongoose = require("mongoose"); // 🗄️ MongoDB ODM
const cors = require("cors"); // 🔄 Enable CORS
const path = require("path");
const passport = require("passport");
const fs = require('fs');
const cookieParser = require('cookie-parser'); // 🍪 Cookie parser for HTTP-only cookies
const jwt = require("jsonwebtoken"); // 🔑 JWT for token verification
const User = require("./backend/models/User"); // User model for role verification
const Note = require("./backend/models/Note"); // Add Note model import
const http = require('http'); // Add HTTP module
const WebSocket = require('ws'); // Add WebSocket module
require("./backend/passport"); // Import passport config

const app = express();
const server = http.createServer(app); // Create HTTP server
const wss = new WebSocket.Server({ server }); // Create WebSocket server

// Import routes 📂
const authRoutes = require('./backend/routes/authRoutes'); // 🔒 Auth routes
const uploadRoutes = require("./backend/routes/uploadRoutes"); // 📤 Upload routes
const notesRoutes = require("./backend/routes/notesRoutes"); // 📝 Notes routes
const adminRoutes = require("./backend/routes/adminRoutes"); // 👑 Admin routes

const PORT = process.env.PORT || 3000; // 🎯 Set port

// Ensure uploads directory exists
const uploadsDir = process.env.UPLOADS_PATH || "./uploads";
if (!fs.existsSync(uploadsDir)) {
  try {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log(`✅ Uploads directory created at ${uploadsDir}`);
  } catch (error) {
    console.error(`❌ Error creating uploads directory: ${error.message}`);
  }
}

// Check and set proper permissions for uploads directory
try {
  fs.chmodSync(uploadsDir, 0o755);
  console.log(`✅ Permissions set for uploads directory`);
} catch (error) {
  console.error(`❌ Error setting permissions for uploads directory: ${error.message}`);
}

// Middleware 🔧
app.use(express.json());
app.use(cookieParser()); // Add cookie parser middleware

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
  credentials: true, // Important for cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

// Debugging middleware to log all requests and responses
app.use((req, res, next) => {
  const start = Date.now();
  console.log(`📥 ${req.method} ${req.url} - Request received`);
  
  // Log request body for non-file uploads
  if (req.method !== 'GET' && !req.headers['content-type']?.includes('multipart/form-data')) {
    console.log('Request body:', req.body);
  }
  
  // Log when the response is finished
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`📤 ${req.method} ${req.url} - Response: ${res.statusCode} (${duration}ms)`);
  });
  
  next();
});

// Security headers middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// CSRF protection middleware for state-changing requests
app.use((req, res, next) => {
  // Log full request details for debugging
  console.log(`Request URL: ${req.url}`);
  console.log(`Request originalUrl: ${req.originalUrl}`);
  console.log(`Request path: ${req.path}`);
  console.log(`Request baseUrl: ${req.baseUrl}`);
  console.log(`Request method: ${req.method}`);
  
  // Skip for GET, HEAD, OPTIONS requests
  const isExemptMethod = ['GET', 'HEAD', 'OPTIONS'].includes(req.method);
  
  // Skip for authentication routes - using originalUrl for more accurate matching
  const originalUrl = req.originalUrl;
  const isAuthRoute = originalUrl.includes('/api/auth/');
  const isRegisterRoute = originalUrl.includes('/api/auth/register');
  const isLoginRoute = originalUrl.includes('/api/auth/login');
  const isRefreshRoute = originalUrl.includes('/api/auth/refresh-token');
  const isGoogleRoute = originalUrl.includes('/api/auth/google');
  const isCsrfRoute = originalUrl.includes('/api/auth/csrf-token');
  
  // Authentication routes to exempt from CSRF
  const isExemptAuthRoute = isRegisterRoute || isLoginRoute || isRefreshRoute || isGoogleRoute || isCsrfRoute;
  
 // console.log(`Auth route details:`, {
   // isAuthRoute,
    //isRegisterRoute,
    //isLoginRoute,
    //isRefreshRoute,
    //isGoogleRoute,
    //isCsrfRoute,
    //isExemptAuthRoute
  //});
  
  if (isExemptMethod || isExemptAuthRoute) {
    console.log(`CSRF check skipped for: ${originalUrl}`);
    return next();
  }
  
  // Check CSRF token for other requests
  const csrfToken = req.headers['x-csrf-token'];
  const cookieToken = req.cookies.csrf_token;
  
  // Log CSRF information (remove in production)
  console.log(`CSRF Check - URL: ${originalUrl}, Method: ${req.method}`);
  console.log(`Header Token: ${csrfToken ? 'Present' : 'Missing'}, Cookie Token: ${cookieToken ? 'Present' : 'Missing'}`);
  console.log('Request headers:', req.headers);
  console.log('Content-type:', req.get('Content-Type'));
  
  if (!csrfToken || !cookieToken) {
    console.warn(`CSRF token missing - Header: ${!!csrfToken}, Cookie: ${!!cookieToken}`);
    return res.status(403).json({ 
      message: 'CSRF token missing',
      details: { 
        headerPresent: !!csrfToken, 
        cookiePresent: !!cookieToken 
      }
    });
  }
  
  if (csrfToken !== cookieToken) {
    console.warn(`CSRF token mismatch - Header: ${csrfToken.substring(0, 10)}..., Cookie: ${cookieToken.substring(0, 10)}...`);
    return res.status(403).json({ 
      message: 'CSRF token validation failed',
      details: 'Token mismatch between header and cookie'
    });
  }
  
  next();
});

// Initialize Passport
app.use(passport.initialize());

// Serve uploaded files - use the UPLOADS_PATH environment variable
app.use('/uploads', express.static(path.join(__dirname, process.env.UPLOADS_PATH || 'uploads')));

// Consistent static file serving
const staticOptions = {
  maxAge: '1h',
  etag: true,
  lastModified: true
};

// Serve static files from the appropriate directory
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'frontend', 'dist'), staticOptions));
} else {
  app.use(express.static(path.join(__dirname, 'frontend', 'public'), staticOptions));
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
app.use("/api/upload", uploadRoutes);
app.use("/api/notes", notesRoutes);
app.use("/api/admin", adminRoutes); // Register admin routes
app.use("/api/notes", uploadRoutes);  // Temporary fix to support both endpoints

// CSRF Protection
app.use(function(req, res, next) {
  // Skip CSRF check for GET requests and non-API routes
  if (req.method === 'GET' || !req.path.startsWith('/api/')) {
    return next();
  }
  
  // Skip CSRF check for multipart form data (file uploads)
  const contentType = req.headers['content-type'] || '';
  if (contentType.includes('multipart/form-data')) {
    console.log('Skipping CSRF check for file upload');
    console.log('Upload URL:', originalUrl);
    console.log('Upload headers:', req.headers);
    return next();
  }
  
  // Check for CSRF token in headers
  const csrfToken = req.headers['x-csrf-token'];
  const cookieCsrfToken = req.cookies.csrf_token;
  
  if (!csrfToken || !cookieCsrfToken || csrfToken !== cookieCsrfToken) {
    console.log('CSRF token validation failed:', { 
      headerToken: csrfToken ? 'present' : 'missing',
      cookieToken: cookieCsrfToken ? 'present' : 'missing',
      match: csrfToken === cookieCsrfToken
    });
    
    return res.status(403).json({ 
      message: 'CSRF token missing or invalid',
      error: 'CSRF verification failed'
    });
  }
  
  next();
});

// Create a middleware to verify access to protected pages
const verifyPageAccess = (allowedRoles) => {
  return async (req, res, next) => {
    console.log("Verifying page access for path:", req.path);
    console.log("Allowed roles:", allowedRoles);
    
    // Get token from cookie or header
    const refreshToken = req.cookies.refreshToken;
    const authHeader = req.header("Authorization");
    let token = null;
    
    // Check the authorization header
    if (authHeader) {
      token = authHeader.replace("Bearer ", "");
      console.log("Found token in Authorization header");
    } else {
      console.log("No Authorization header found");
    }
    
    // Check for JWT in cookies
    if (refreshToken) {
      console.log("Found refresh token in cookies");
    } else {
      console.log("No refresh token found in cookies");
    }
    
    // If no tokens are found, try to check for token in the query parameters (for debugging)
    // This would be passed from the login redirect
    const queryToken = req.query.token;
    if (queryToken && !token) {
      token = queryToken;
      console.log("Using token from query parameter");
    }
    
    if (!refreshToken && !token) {
      console.log("No tokens found, redirecting to login");
      return res.redirect('/login.html');
    }
    
    try {
      // Try to verify with one of the tokens
      let decoded;
      let tokenUsed = "";
      
      // First try refresh token (HTTP only cookie)
      if (refreshToken) {
        try {
          decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET);
          tokenUsed = "refresh token";
          console.log("Successfully verified refresh token");
        } catch (error) {
          console.log("Failed to verify refresh token:", error.message);
        }
      }
      
      // If refresh token verification failed, try access token
      if (!decoded && token) {
        try {
          decoded = jwt.verify(token, process.env.JWT_SECRET);
          tokenUsed = "access token";
          console.log("Successfully verified access token");
        } catch (error) {
          console.log("Failed to verify access token:", error.message);
        }
      }
      
      if (!decoded) {
        throw new Error("No valid token");
      }
      
      console.log("Decoded token:", decoded);
      
      if (!decoded.userId) {
        throw new Error("Invalid token structure");
      }
      
      // Get user from database
      const user = await User.findById(decoded.userId);
      console.log("User found:", user ? "Yes" : "No");
      if (user) {
        console.log("User type:", user.userType);
        console.log("Is allowed:", allowedRoles.includes(user.userType));
      }
      
      if (!user || !allowedRoles.includes(user.userType)) {
        // Redirect to appropriate page based on user role
        if (user && user.userType === 'student') {
          console.log("Redirecting teacher to student dashboard");
          return res.redirect('/student-dashboard');
        } else if (user && user.userType === 'teacher') {
          console.log("Redirecting student to teacher dashboard");
          return res.redirect('/teacher-dashboard');
        } else {
          console.log("User not found or has invalid role, redirecting to login");
          return res.redirect('/login.html');
        }
      }
      
      console.log("Access granted to:", req.path);
      next();
    } catch (error) {
      console.error("Auth error:", error.message);
      return res.redirect('/login.html');
    }
  };
};

// HTML route handlers 🌐
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', process.env.NODE_ENV === 'production' ? 'dist' : 'src', 'index.html'));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', process.env.NODE_ENV === 'production' ? 'dist' : 'src', 'login.html'));
});

app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', process.env.NODE_ENV === 'production' ? 'dist' : 'src', 'signup.html'));
});

app.get("/student-dashboard", verifyPageAccess(['student']), (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', process.env.NODE_ENV === 'production' ? 'dist' : 'src', 'student-dashboard.html'));
});

app.get("/teacher-dashboard", verifyPageAccess(['teacher']), (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', process.env.NODE_ENV === 'production' ? 'dist' : 'src', 'teacher-dashboard.html'));
});

app.get("/upload", verifyPageAccess(['teacher']), (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', process.env.NODE_ENV === 'production' ? 'dist' : 'src', 'upload.html'));
});

// Error handler for HTML routes
app.use((req, res, next) => {
  if (req.accepts('html')) {
    res.status(404).sendFile(path.join(__dirname, 'frontend', process.env.NODE_ENV === 'production' ? 'dist' : 'src', 'index.html'));
    return;
  }
  next();
});

// WebSocket connection handling
wss.on('connection', (ws) => {
  console.log('New WebSocket connection');

  // Send initial data
  sendDashboardData(ws);

  // Set up interval for periodic updates
  const interval = setInterval(() => {
    sendDashboardData(ws);
  }, 5000); // Update every 5 seconds

  ws.on('close', () => {
    clearInterval(interval);
  });
});

// Function to fetch and send dashboard data
async function sendDashboardData(ws) {
  try {
    // Fetch users with type-based aggregation
    const userStats = await User.aggregate([
      {
        $group: {
          _id: '$userType',
          count: { $sum: 1 },
          users: { 
            $push: {
              fullName: { $concat: ['$firstName', ' ', '$lastName'] },
              username: '$username',
              email: '$email',
              _id: '$_id'
            }
          }
        }
      }
    ]);

    // Process user statistics
    const stats = {
      teachers: { count: 0, users: [] },
      students: { count: 0, users: [] }
    };

    userStats.forEach(stat => {
      if (stat._id === 'teacher') {
        stats.teachers = { count: stat.count, users: stat.users };
      } else if (stat._id === 'student') {
        stats.students = { count: stat.count, users: stat.users };
      }
    });

    // Fetch notes with teacher information
    const notes = await Note.aggregate([
      {
        $lookup: {
          from: 'users',
          localField: 'teacherId',
          foreignField: '_id',
          as: 'teacher'
        }
      },
      {
        $unwind: '$teacher'
      },
      {
        $group: {
          _id: '$teacherId',
          teacherName: { $first: '$teacher.firstName' },
          notes: {
            $push: {
              title: '$title',
              fileName: '$fileOriginalName',
              uploadDate: '$uploadDate'
            }
          }
        }
      }
    ]);

    // Combine teacher data with their notes
    const teachersWithNotes = stats.teachers.users.map(teacher => {
      const teacherNotes = notes.find(n => n._id.toString() === teacher._id.toString());
      return {
        fullName: teacher.fullName,
        username: teacher.username,
        email: teacher.email,
        notes: teacherNotes ? teacherNotes.notes : []
      };
    });

    // Prepare dashboard data
    const dashboardData = {
      totalUsers: (stats.teachers.count + stats.students.count),
      totalTeachers: stats.teachers.count,
      totalStudents: stats.students.count,
      totalNotes: notes.reduce((sum, teacher) => sum + teacher.notes.length, 0),
      teachers: teachersWithNotes,
      students: stats.students.users
    };

    // Send data only if the connection is still open
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(dashboardData));
    }
  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    // Send error message to client if connection is open
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ 
        error: true, 
        message: 'Error fetching dashboard data'
      }));
    }
  }
}

// Admin authentication middleware
const authenticateAdmin = async (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.header('Authorization');
    if (!authHeader) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.replace('Bearer ', '');
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if user exists and is an admin
    const user = await User.findById(decoded.userId);
    if (!user || user.userType !== 'admin') {
      return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    console.error('Admin authentication error:', error);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Function to broadcast dashboard data to all connected clients
function broadcastDashboardData() {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      sendDashboardData(client);
    }
  });
}

// Admin delete routes
app.delete('/api/admin/delete-user/:userId', authenticateAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Validate user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Delete user's notes if they are a teacher
    if (user.userType === 'teacher') {
      const notes = await Note.find({ teacherId: userId });
      console.log(`Found ${notes.length} notes to delete for teacher ${userId}`);
      
      // Delete associated files
      for (const note of notes) {
        try {
          if (note.fileName) {
            const filePath = path.join(__dirname, 'uploads', note.fileName);
            if (fs.existsSync(filePath)) {
              await fs.promises.unlink(filePath);
            }
          }
        } catch (error) {
          console.error(`Error deleting file for note ${note._id}:`, error);
        }
      }

      // Delete all notes from database
      await Note.deleteMany({ teacherId: userId });
    }

    // Delete the user
    await User.findByIdAndDelete(userId);
    
    // Broadcast update
    broadcastDashboardData();
    
    res.json({ success: true, message: 'User and associated data deleted successfully' });
  } catch (error) {
    console.error('Error in delete user:', error);
    res.status(500).json({ error: 'Failed to delete user', details: error.message });
  }
});

app.delete('/api/admin/delete-note/:noteId', authenticateAdmin, async (req, res) => {
  try {
    const { noteId } = req.params;
    
    // Validate note exists
    const note = await Note.findById(noteId);
    if (!note) {
      return res.status(404).json({ error: 'Note not found' });
    }

    // Delete associated file if exists
    if (note.fileName) {
      try {
        const filePath = path.join(__dirname, 'uploads', note.fileName);
        if (fs.existsSync(filePath)) {
          await fs.promises.unlink(filePath);
        }
      } catch (error) {
        console.error(`Error deleting file for note ${noteId}:`, error);
      }
    }

    // Delete note from database
    await Note.findByIdAndDelete(noteId);
    
    // Broadcast update
    broadcastDashboardData();
    
    res.json({ success: true, message: 'Note deleted successfully' });
  } catch (error) {
    console.error('Error in delete note:', error);
    res.status(500).json({ error: 'Failed to delete note', details: error.message });
  }
});

// Start the server
server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  // Handle multer errors
  if (err.name === 'MulterError') {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File too large' });
    }
    return res.status(400).json({ message: `Upload error: ${err.message}` });
  }
  
  // Handle validation errors
  if (err.name === 'ValidationError') {
    return res.status(400).json({ 
      message: 'Validation error', 
      errors: Object.values(err.errors).map(e => e.message) 
    });
  }
  
  // Default error response
  res.status(500).json({ 
    message: 'An error occurred', 
    error: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
});