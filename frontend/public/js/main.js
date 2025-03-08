async function handleLogin(event) {
    event.preventDefault();
    console.log("Login form submitted");
    
    const errorMessage = document.getElementById("errorMessage");
    errorMessage.style.display = "none";
    
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    
    console.log("Login attempt for email:", email);

    try {
        console.log("Sending login request to server...");
        
        const response = await fetch("/api/auth/login", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({ email, password }),
            credentials: 'include' // Include cookies
        });

        console.log("Server response status:", response.status);
        const data = await response.json();
        console.log("Server response data:", data);

        if (!response.ok) {
            showError(data.message || "Login failed. Please try again.");
            return;
        }

        // Get token from the response (might be accessToken or token)
        const token = data.accessToken || data.token;
        console.log("Token received from server");
        
        // Store the token
        localStorage.setItem("jwt", token);
        console.log("Token stored in localStorage");
        
        // Store user information if available
        if (data.user) {
            sessionStorage.setItem("user", JSON.stringify(data.user));
            console.log("User data stored in sessionStorage:", data.user);
        }
        
        // Store CSRF token if available
        if (data.csrfToken) {
            localStorage.setItem("csrfToken", data.csrfToken);
            console.log("CSRF token stored in localStorage");
        }
        
        // Get redirect location - check for explicit location first, 
        // then use userType to determine where to redirect
        const redirectPath = data.location || 
                          (data.user && data.user.userType === "teacher" ? 
                           "/teacher-dashboard" : "/student-dashboard");
        
        console.log("User role:", data.user ? data.user.userType : "unknown");                   
        console.log("Redirecting to:", redirectPath);
        
        // Add the token to the URL for the initial redirect
        // This helps with server-side authentication when the page first loads
        window.location.href = redirectPath + (redirectPath.includes('?') ? '&' : '?') + 'token=' + token;
    } catch (error) {
        console.error("Login error:", error);
        showError("An error occurred. Please try again.");
    }
}

async function handleSignup(event) {
    event.preventDefault();
    console.log("Signup form submitted");
    
    const errorMessage = document.getElementById("errorMessage");
    errorMessage.style.display = "none";
    
    const username = document.getElementById("fullName").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirmPassword").value;
    const userType = document.getElementById("userType").value;
    
    console.log("Form data:", { username, email, userType });
    
    // Validate passwords match
    if (password !== confirmPassword) {
        showError("Passwords do not match");
        return;
    }
    
    // Validate user type is selected
    if (!userType) {
        showError("Please select whether you are a student or teacher");
        return;
    }

    try {
        console.log("Sending registration request to server...");
        
        const requestBody = { username, email, password, userType };
        console.log("Request payload:", requestBody);
        
        const response = await fetch("/api/auth/register", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify(requestBody),
            credentials: 'include' // Include cookies
        });

        console.log("Server response status:", response.status);
        const data = await response.json();
        console.log("Server response data:", data);

        if (!response.ok) {
            showError(data.message || "Registration failed. Please try again.");
            return;
        }

        // Store the token
        localStorage.setItem("jwt", data.token);
        console.log("Token stored in localStorage");
        
        // Store CSRF token if available
        if (data.csrfToken) {
            localStorage.setItem("csrfToken", data.csrfToken);
            console.log("CSRF token stored in localStorage");
        }
        
        // Store user information if available
        if (data.user) {
            sessionStorage.setItem("user", JSON.stringify(data.user));
            console.log("User data stored in sessionStorage");
        }
        
        // Show success message before redirect
        showSuccess("Registration successful! Redirecting to login...");
        
        // Redirect to login page after successful registration (with a slight delay for the success message)
        console.log("Will redirect to login page in 1.5 seconds");
        setTimeout(() => {
            window.location.href = "/login.html";
        }, 1500);
    } catch (error) {
        console.error("Registration error:", error);
        showError("An error occurred. Please try again.");
    }
}

// Update the fetchNotes function to include CSRF token
async function fetchNotes() {
    try {
        const response = await fetchWithAuth("/api/notes");
        
        if (!response.ok) {
            throw new Error(`Failed to fetch notes: ${response.status}`);
        }
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error fetching notes:", error);
        showError("Failed to load notes. Please try again.");
        return [];
    }
}

// Update the deleteNote function to include CSRF token
async function deleteNote(noteId) {
    try {
        if (!confirm("Are you sure you want to delete this note?")) {
            return false;
        }
        
        const response = await fetchWithAuth(`/api/notes/${noteId}`, {
            method: "DELETE"
        });
        
        if (!response.ok) {
            throw new Error(`Failed to delete note: ${response.status}`);
        }
        
        return true;
    } catch (error) {
        console.error("Error deleting note:", error);
        showError("Failed to delete note. Please try again.");
        return false;
    }
}

// Update downloadNote function
async function downloadNote(noteId, filename) {
    try {
        const response = await fetchWithAuth(`/api/notes/download/${noteId}`);
        
        if (!response.ok) {
            throw new Error(`Failed to download note: ${response.status}`);
        }
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename || 'download';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        return true;
    } catch (error) {
        console.error("Error downloading note:", error);
        showError("Failed to download note. Please try again.");
        return false;
    }
}

// Add logout function
function handleLogout() {
    try {
        // Call the logout API endpoint
        fetchWithAuth("/api/auth/logout", {
            method: "POST"
        }).then(() => {
            // Clear local storage regardless of response
            localStorage.removeItem("jwt");
            localStorage.removeItem("csrfToken");
            sessionStorage.removeItem("user");
            
            // Redirect to login page
            window.location.href = "/login.html";
        }).catch(error => {
            console.error("Logout API error:", error);
            
            // Clear storage and redirect anyway
            localStorage.removeItem("jwt");
            localStorage.removeItem("csrfToken");
            sessionStorage.removeItem("user");
            window.location.href = "/login.html";
        });
    } catch (error) {
        console.error("Logout error:", error);
        
        // Clear storage and redirect anyway
        localStorage.removeItem("jwt");
        localStorage.removeItem("csrfToken");
        sessionStorage.removeItem("user");
        window.location.href = "/login.html";
    }
}

// Attach event listener to logout button if it exists
document.addEventListener('DOMContentLoaded', function() {
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }
});

// Helper functions for showing error and success messages
function showError(message) {
    const errorMessage = document.getElementById("errorMessage");
    if (errorMessage) {
        errorMessage.textContent = message;
        errorMessage.style.display = "block";
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            errorMessage.style.display = "none";
        }, 5000);
    }
}

function showSuccess(message) {
    const successMessage = document.getElementById("successMessage");
    if (successMessage) {
        successMessage.textContent = message;
        successMessage.style.display = "block";
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            successMessage.style.display = "none";
        }, 5000);
    }
}