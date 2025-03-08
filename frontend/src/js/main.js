// Navigation functionality
function initNavigation() {
    window.addEventListener("scroll", function () {
        const navbar = document.getElementById("navbar");
        if (navbar) {
            if (window.scrollY > 50) {
                navbar.classList.add("scrolled");
            } else {
                navbar.classList.remove("scrolled");
            }
        }
    });
}

// Authentication state
const authState = {
    token: null,
    csrfToken: null,
    user: null,
    initialized: false
};

// Read auth state from storage
function loadAuthState() {
    authState.token = sessionStorage.getItem("accessToken");
    authState.csrfToken = getCookie("csrf_token");
    const userJson = sessionStorage.getItem("user");
    authState.user = userJson ? JSON.parse(userJson) : null;
    authState.initialized = true;
    
    // Update UI based on auth state
    updateAuthUI();
    
    // Log auth state for debugging (remove in production)
    console.log("Auth state loaded:", {
        tokenExists: !!authState.token,
        csrfExists: !!authState.csrfToken,
        userExists: !!authState.user
    });
}

// Check if token is expired
function isTokenExpired(token) {
    if (!token) return true;
    
    try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        // Check if token is expired - add 10 second buffer
        return (payload.exp * 1000) < (Date.now() - 10000);
    } catch (e) {
        console.error("Error checking token expiration:", e);
        return true;
    }
}

// Get cookie by name
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

// Update UI elements based on authentication state
function updateAuthUI() {
    const isAuthenticated = !!authState.token && !!authState.user;
    
    // Update navigation links
    const navLinks = document.querySelectorAll('.nav-links');
    navLinks.forEach(navLink => {
        const teacherLinks = navLink.querySelectorAll('.teacher-only');
        const studentLinks = navLink.querySelectorAll('.student-only');
        const authLinks = navLink.querySelectorAll('.auth-only');
        const guestLinks = navLink.querySelectorAll('.guest-only');
        
        if (isAuthenticated) {
            // Show/hide based on role
            teacherLinks.forEach(link => {
                link.style.display = authState.user.userType === 'teacher' ? 'block' : 'none';
            });
            
            studentLinks.forEach(link => {
                link.style.display = authState.user.userType === 'student' ? 'block' : 'none';
            });
            
            // Show auth-only links
            authLinks.forEach(link => {
                link.style.display = 'block';
            });
            
            // Hide guest-only links
            guestLinks.forEach(link => {
                link.style.display = 'none';
            });
            
        } else {
            // Hide role-based and auth-only links
            teacherLinks.forEach(link => { link.style.display = 'none'; });
            studentLinks.forEach(link => { link.style.display = 'none'; });
            authLinks.forEach(link => { link.style.display = 'none'; });
            
            // Show guest-only links
            guestLinks.forEach(link => { link.style.display = 'block'; });
        }
    });
    
    // Update user info display if present
    const userInfoElement = document.getElementById('userInfo');
    if (userInfoElement && authState.user) {
        userInfoElement.textContent = authState.user.username || authState.user.email;
    }
}

// Authentication functionality
function initAuth() {
    const loginForm = document.getElementById("loginForm");
    const signupForm = document.getElementById("signupForm");
    const logoutBtn = document.getElementById("logoutBtn");

    if (loginForm) {
        loginForm.addEventListener("submit", handleLogin);
    }

    if (signupForm) {
        signupForm.addEventListener("submit", handleSignup);
    }
    
    if (logoutBtn) {
        logoutBtn.addEventListener("click", handleLogout);
    }

    // Load auth state
    loadAuthState();
    
    // Check and refresh token if needed
    if (authState.token && isTokenExpired(authState.token)) {
        refreshToken();
    }

    // Check for authentication on protected pages
    const protectedPages = ['/student-dashboard', '/teacher-dashboard', '/upload'];
    if (protectedPages.some(page => window.location.pathname.includes(page))) {
        if (!authState.token || !authState.user) {
            window.location.href = "/login.html";
            return;
        }
        
        // Check role-based access
        const isTeacherPage = window.location.pathname.includes('teacher-dashboard');
        const isStudentPage = window.location.pathname.includes('student-dashboard');
        
        if (isTeacherPage && authState.user.userType !== 'teacher') {
            window.location.href = "/student-dashboard";
            return;
        }
        
        if (isStudentPage && authState.user.userType !== 'student') {
            window.location.href = "/teacher-dashboard";
            return;
        }
    }
}

// Get authorization headers for API requests
function getAuthHeaders() {
    const headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    };
    
    if (authState.token) {
        headers['Authorization'] = `Bearer ${authState.token}`;
    }
    
    if (authState.csrfToken) {
        headers['X-CSRF-Token'] = authState.csrfToken;
    } else {
        // Try to get CSRF token from cookie again if missing
        const csrfToken = getCookie("csrf_token");
        if (csrfToken) {
            authState.csrfToken = csrfToken;
            headers['X-CSRF-Token'] = csrfToken;
        }
    }
    
    return headers;
}

// Refresh the access token
async function refreshToken() {
    try {
        const response = await fetch('/api/auth/refresh-token', {
            method: 'POST',
            credentials: 'include', // Include cookies
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        });

        if (response.ok) {
            const data = await response.json();
            
            // Update authentication state
            authState.token = data.accessToken;
            sessionStorage.setItem("accessToken", data.accessToken);
            
            // Update CSRF token if provided
            if (data.csrfToken) {
                authState.csrfToken = data.csrfToken;
            } else {
                // Get from cookie if not in response
                authState.csrfToken = getCookie("csrf_token");
            }
            
            return true;
        } else {
            // If refresh token is invalid, clear auth state
            handleLogout();
            return false;
        }
    } catch (error) {
        console.error("Error refreshing token:", error);
        handleLogout();
        return false;
    }
}

// Clear authentication state
function clearAuthState() {
    authState.token = null;
    authState.csrfToken = null;
    authState.user = null;
    
    // Clear session storage
    sessionStorage.removeItem("accessToken");
    sessionStorage.removeItem("user");
    
    // Update UI
    updateAuthUI();
}

async function handleLogin(event) {
    event.preventDefault();
    const errorMessage = document.getElementById("errorMessage");
    errorMessage.style.display = "none";
    
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    try {
        const response = await fetch("/api/auth/login", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({ email, password }),
            credentials: 'include' // Include cookies
        });

        const data = await response.json();

        if (!response.ok) {
            showError(data.message || "Login failed. Please try again.");
            return;
        }

        // Store auth data
        authState.token = data.token;
        authState.csrfToken = data.csrfToken;
        authState.user = data.user;
        
        // Save to session storage (not localStorage for security)
        sessionStorage.setItem("accessToken", data.token);
        sessionStorage.setItem("user", JSON.stringify(data.user));
        
        // Update UI
        updateAuthUI();
        
        // Redirect based on user type
        window.location.href = data.user.userType === "teacher" ? "/teacher-dashboard" : "/student-dashboard";
    } catch (error) {
        console.error("Login error:", error);
        showError("An error occurred. Please try again.");
    }
}

async function handleLogout() {
    try {
        await fetch("/api/auth/logout", {
            method: "POST",
            headers: getAuthHeaders(),
            credentials: 'include' // Include cookies
        });
    } catch (error) {
        console.error("Logout error:", error);
    } finally {
        // Clear auth state regardless of server response
        clearAuthState();
        window.location.href = "/login.html";
    }
}

// API request wrapper with token refresh
async function apiRequest(url, options = {}) {
    // Check token expiration before making request
    if (authState.token && isTokenExpired(authState.token)) {
        const refreshed = await refreshToken();
        if (!refreshed) {
            // If refresh failed and user needs authentication, redirect to login
            if (needsAuthentication()) {
                window.location.href = "/login.html";
                return new Response(JSON.stringify({ error: "Authentication required" }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }
    }
    
    // Set default options
    const requestOptions = {
        ...options,
        headers: {
            ...getAuthHeaders(),
            ...(options.headers || {})
        },
        credentials: 'include' // Include cookies
    };
    
    try {
        // Try the request
        let response = await fetch(url, requestOptions);
        
        // If unauthorized and we have a token, try to refresh
        if (response.status === 401 && authState.token) {
            const refreshed = await refreshToken();
            
            // If refresh succeeded, retry the request with new token
            if (refreshed) {
                requestOptions.headers = {
                    ...getAuthHeaders(),
                    ...(options.headers || {})
                };
                response = await fetch(url, requestOptions);
            }
        }
        
        // Log response status for debugging (remove in production)
        if (response.status >= 400) {
            console.error(`API request error: ${response.status} ${response.statusText}`, { 
                url, 
                method: options.method || 'GET',
                hasToken: !!authState.token,
                hasCsrf: !!authState.csrfToken
            });
        }
        
        return response;
    } catch (error) {
        console.error("API request error:", error);
        throw error;
    }
}

// Upload functionality
function initUpload() {
    const uploadForm = document.getElementById("uploadForm");
    if (uploadForm) {
        const fileInput = document.getElementById("file");
        const fileLabel = document.getElementById("fileLabel");

        fileInput?.addEventListener("change", function () {
            fileLabel.textContent = this.files.length ? this.files[0].name : "No file selected";
        });

        uploadForm.addEventListener("submit", handleUpload);
    }
}

async function handleUpload(event) {
    event.preventDefault();
    const token = localStorage.getItem("jwt");

    if (!token) {
        window.location.href = "/login.html";
        return;
    }

    const formData = new FormData();
    formData.append("title", document.getElementById("title").value.trim());
    formData.append("description", document.getElementById("description").value.trim());
    formData.append("category", document.getElementById("category").value);
    formData.append("file", document.getElementById("file").files[0]);

    try {
        // Get CSRF token
        const csrfToken = getCookie("csrf_token");
        
        const response = await fetch("/api/upload", {
            headers: { 
                "Authorization": `Bearer ${token}`,
                "Accept": "application/json",
                "X-CSRF-Token": csrfToken
            }
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.message || "Upload failed.");
        }

        showSuccess("File uploaded successfully!");
        event.target.reset();
        document.getElementById("fileLabel").textContent = "No file selected";
    } catch (error) {
        showError(error.message || "Upload failed. Please try again.");
    }
}

// Dashboard functionality
function initDashboard() {
    const dashboardContent = document.getElementById("notes-list");
    if (dashboardContent) {
        loadDashboardContent();
    }
}

async function loadDashboardContent() {
    const token = localStorage.getItem("jwt");
    if (!token) {
        window.location.href = "/login.html";
        return;
    }

    try {
        const response = await fetch("/api/notes", {
            headers: { 
                "Authorization": `Bearer ${token}`,
                "Accept": "application/json"
            }
        });

        if (!response.ok) {
            throw new Error("Failed to load notes");
        }

        const data = await response.json();
        const notesList = document.getElementById("notes-list");
        
        if (data.notes.length === 0) {
            notesList.innerHTML = '<p class="text-center">No notes found.</p>';
            return;
        }

        notesList.innerHTML = data.notes
            .map(note => `
                <div class="note-item">
                    <h3>${note.title}</h3>
                    <p>${note.description}</p>
                    <a href="/api/notes/download/${note._id}" class="btn btn-primary">Download</a>
                </div>
            `)
            .join('');
    } catch (error) {
        console.error(error);
        showError("Failed to load notes. Please try again later.");
    }
}

// Initialize all functionality
document.addEventListener("DOMContentLoaded", function() {
    initNavigation();
    initAuth();
    initUpload();
    initDashboard();
});

// Helper functions
function showError(message) {
    const errorMessage = document.getElementById("errorMessage");
    if (errorMessage) {
        errorMessage.textContent = message;
        errorMessage.style.display = "block";
    }
}

function showSuccess(message) {
    const successMessage = document.getElementById("successMessage");
    if (successMessage) {
        successMessage.textContent = message;
        successMessage.style.display = "block";
    }
}

// Helper function to check if current page needs authentication
function needsAuthentication() {
    const protectedPages = ['/student-dashboard', '/teacher-dashboard', '/upload'];
    return protectedPages.some(page => window.location.pathname.includes(page));
} 