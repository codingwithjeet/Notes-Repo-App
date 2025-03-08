/**
 * Common authentication functions for client-side authorization
 */

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