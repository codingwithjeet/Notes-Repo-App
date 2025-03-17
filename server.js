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
require("./backend/passport"); // Import passport config

const app = express();

// Import routes 📂
const authRoutes = require('./backend/routes/authRoutes'); // 🔒 Auth routes
const uploadRoutes = require("./backend/routes/uploadRoutes"); // 📤 Upload routes
const notesRoutes = require("./backend/routes/notesRoutes"); // 📝 Notes routes

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

// Start server 🚀
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📁 File uploads directory: ${process.env.UPLOADS_PATH || "./uploads"}`);
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