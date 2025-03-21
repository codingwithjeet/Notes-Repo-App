/**
 * Common authentication functions for client-side authorization
 */

// Authentication state
const authState = {
    token: null,
    csrfToken: null,
    user: null,
    initialized: false
};

// Check if user is authenticated
function isAuthenticated() {
    const token = localStorage.getItem('jwt');
    const user = sessionStorage.getItem('user');
    return !!token && !!user;
}

// Check if user has the required role
function hasRole(requiredRole) {
    const userStr = sessionStorage.getItem('user');
    if (!userStr) return false;
    
    try {
        const user = JSON.parse(userStr);
        return user.userType === requiredRole;
    } catch (error) {
        console.error('Error parsing user data:', error);
        return false;
    }
}

// Check authentication and redirect appropriately
function checkAuth(requiredRole) {
    if (!isAuthenticated()) {
        window.location.href = '/login.html';
        return false;
    }
    
    if (requiredRole && !hasRole(requiredRole)) {
        // Redirect to appropriate dashboard based on actual role
        const userStr = sessionStorage.getItem('user');
        let redirectPath = '/';
        
        try {
            const user = JSON.parse(userStr);
            redirectPath = user.userType === 'teacher' ? '/teacher-dashboard' : '/student-dashboard';
        } catch (error) {
            console.error('Error parsing user data:', error);
        }
        
        window.location.href = redirectPath;
        return false;
    }
    
    return true;
}

// Get CSRF token from storage
function getCsrfToken() {
    return localStorage.getItem('csrfToken');
}

// Add CSRF token to headers
function addCsrfHeader(headers = {}) {
    const csrfToken = getCsrfToken();
    if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
    }
    return headers;
}

// Helper for API calls with authorization
async function fetchWithAuth(url, options = {}) {
    const token = localStorage.getItem('jwt');
    const headers = options.headers || {};
    
    // Add Authorization header if token exists
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }
    
    // Add CSRF token for non-GET requests
    if (options.method && options.method !== 'GET') {
        addCsrfHeader(headers);
    }
    
    // Update options with headers
    const updatedOptions = {
        ...options,
        headers: headers,
        credentials: 'include' // Include cookies
    };
    
    return fetch(url, updatedOptions);
}

// Logout function
function logout() {
    // Clear tokens and user data
    localStorage.removeItem('jwt');
    localStorage.removeItem('csrfToken');
    sessionStorage.removeItem('user');
    
    // Redirect to login page
    window.location.href = '/login.html';
}

// Handle signup form submission
async function handleSignup(event) {
    event.preventDefault();
    const errorMessage = document.getElementById("errorMessage");
    errorMessage.style.display = "none";
    
    const firstName = document.getElementById("firstName").value;
    const lastName = document.getElementById("lastName").value;
    const username = document.getElementById("username").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirmPassword").value;
    const userType = document.getElementById("userType").value;
    const userClass = document.getElementById("class")?.value;

    // Validate passwords match
    if (password !== confirmPassword) {
        showError("Passwords do not match");
        return;
    }

    // Validate class field for students
    if (userType === 'student' && !userClass) {
        showError("Please select your class");
        return;
    }

    try {
        const response = await fetch("/api/auth/register", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({
                firstName,
                lastName,
                username,
                email,
                password,
                userType,
                ...(userType === 'student' && { class: userClass })
            }),
            credentials: 'include' // Include cookies
        });

        const data = await response.json();

        if (!response.ok) {
            showError(data.message || "Registration failed. Please try again.");
            return;
        }

        // Store auth data
        authState.token = data.token;
        authState.csrfToken = data.csrfToken;
        authState.user = data.user;
        
        // Save to session storage
        sessionStorage.setItem("accessToken", data.token);
        sessionStorage.setItem("user", JSON.stringify(data.user));
        
        // Update UI
        updateAuthUI();
        
        // Redirect based on user type
        window.location.href = data.user.userType === "teacher" ? "/teacher-dashboard" : "/student-dashboard";
    } catch (error) {
        console.error("Registration error:", error);
        showError("An error occurred. Please try again.");
    }
}

// Helper function to show error messages
function showError(message) {
    const errorMessage = document.getElementById("errorMessage");
    if (errorMessage) {
        errorMessage.textContent = message;
        errorMessage.style.display = "block";
    }
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