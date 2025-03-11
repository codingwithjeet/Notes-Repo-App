const jwt = require("jsonwebtoken");

// Middleware to verify access token
const authenticateToken = (req, res, next) => {
  console.log("Authenticating token...");

  // First check for access token in Authorization header
  const authHeader = req.header("Authorization");
  let token = null;
  
  if (authHeader) {
    token = authHeader.replace("Bearer ", "");
  }

  // If no token in header, don't try to authenticate - let the route handler decide
  if (!token) {
    console.log("No token provided.");
    return res.status(401).json({ message: "Access denied. No token provided." });

  }

  try {
    console.log("Token Authenticated ✅");

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;
    req.userId = decoded.userId; // Add userId for consistent access
    next();
  } catch (ex) {
    console.log("Token is valid. User ID:", decoded.userId);
    return res.status(401).json({ message: "Invalid token." });

  }
};

// Middleware to check user role
const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: "Unauthorized. Not authenticated." });
    }

    if (!roles.includes(req.user.userType)) {
      return res.status(403).json({ message: "Forbidden. Insufficient permissions." });
    }

    next();
  };
};

// Middleware to verify the refresh token from HTTP-only cookie
const verifyRefreshToken = (req, res, next) => {
  const refreshToken = req.cookies.refreshToken;
  
  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token not found." });
  }

  try {
    const decoded = jwt.verify(
      refreshToken, 
      process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET
    );
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid refresh token." });
  }
};

module.exports = {
  authenticateToken,
  authorizeRole,
  verifyRefreshToken
};
