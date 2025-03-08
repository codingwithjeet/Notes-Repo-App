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

// Authentication functionality
function initAuth() {
    const loginForm = document.getElementById("loginForm");
    const signupForm = document.getElementById("signupForm");

    if (loginForm) {
        loginForm.addEventListener("submit", handleLogin);
    }

    if (signupForm) {
        signupForm.addEventListener("submit", handleSignup);
    }

    // Check for authentication on protected pages
    const protectedPages = ['/student-dashboard', '/teacher-dashboard', '/upload'];
    if (protectedPages.some(page => window.location.pathname.includes(page))) {
        const token = localStorage.getItem("jwt");
        if (!token) {
            window.location.href = "/login.html";
        }
    }
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
            credentials: 'same-origin'
        });

        const data = await response.json();

        if (!response.ok) {
            showError(data.message || "Login failed. Please try again.");
            return;
        }

        localStorage.setItem("jwt", data.token);
        window.location.href = data.userType === "teacher" ? "/teacher-dashboard" : "/student-dashboard";
    } catch (error) {
        console.error("Login error:", error);
        showError("An error occurred. Please try again.");
    }
}

async function handleSignup(event) {
    event.preventDefault();
    const errorMessage = document.getElementById("errorMessage");
    errorMessage.style.display = "none";

    const formData = {
        username: document.getElementById("fullName").value,
        email: document.getElementById("email").value,
        password: document.getElementById("password").value,
        confirmPassword: document.getElementById("confirmPassword").value,
        userType: document.getElementById("userType").value
    };

    if (formData.password !== formData.confirmPassword) {
        showError("Passwords do not match");
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
                username: formData.username,
                email: formData.email,
                password: formData.password,
                userType: formData.userType
            }),
            credentials: 'same-origin'
        });

        const data = await response.json();

        if (!response.ok) {
            showError(data.message || "Registration failed. Please try again.");
            return;
        }

        // Store the token
        localStorage.setItem("jwt", data.token);
        
        // Redirect to login page after successful registration
        window.location.href = "/login.html";
    } catch (error) {
        console.error("Registration error:", error);
        showError("An error occurred. Please try again.");
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
        const response = await fetch("/api/upload", {
            method: "POST",
            body: formData,
            headers: { 
                "Authorization": `Bearer ${token}`
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