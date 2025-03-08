// Check authentication state
function checkAuth() {
    const token = localStorage.getItem("jwt");
    const userData = sessionStorage.getItem("user") || localStorage.getItem("user");

    try {
        if (token) return { token }; // Return token if available
        return userData ? JSON.parse(userData) : null;
    } catch (error) {
        console.error("Error parsing user data:", error);
        return null;
    }
}

// Redirect user based on their role (student/teacher)
async function handleUserRedirect() {
    const user = checkAuth();

    if (!user) {
        window.location.href = "login.html"; // Redirect if not authenticated
        return;
    }

    try {
        const response = await fetch("http://localhost:3000/api/user", {
            headers: { "Authorization": `Bearer ${localStorage.getItem("jwt")}` },
        });

        if (!response.ok) throw new Error("Failed to fetch user data");

        const userData = await response.json();
        localStorage.setItem("userType", userData.userType); // Store userType

        // Redirect user based on their role
        if (userData.userType === "teacher") {
            window.location.href = "/teacher-dashboard.html";
        } else {
            window.location.href = "/student-dashboard.html";
        }
    } catch (error) {
        console.error("Error fetching user data:", error);
        logout(); // Logout on error
    }
}

// Update navigation based on authentication state
function updateNavigation() {
    const user = checkAuth();
    const navLinks = document.querySelector(".nav-links");

    if (!navLinks) return; // Prevent errors if nav element is missing

    if (user) {
        navLinks.innerHTML = `
            <a href="#features">Features</a>
            <a href="#how-it-works">How It Works</a>
            <a href="#" id="dashboard-link" class="login-btn">Dashboard</a>
            <a href="#" id="logout-btn" class="signup-btn">Logout</a>
            <span class="user-greeting">Welcome, <strong>${sanitizeHTML(user.name || "User")}</strong>!</span>
        `;

        // Attach event listeners safely
        setTimeout(() => {
            document.getElementById("logout-btn")?.addEventListener("click", handleLogout);
            document.getElementById("dashboard-link")?.addEventListener("click", handleUserRedirect);
        }, 100);
    } else {
        navLinks.innerHTML = `
            <a href="#features">Features</a>
            <a href="#how-it-works">How It Works</a>
            <a href="login.html" class="login-btn">Login</a>
            <a href="signup.html" class="signup-btn">Sign Up</a>
        `;
    }
}

// Sanitize HTML to prevent XSS attacks
function sanitizeHTML(str) {
    const temp = document.createElement("div");
    temp.textContent = str;
    return temp.innerHTML;
}

// Handle logout
function handleLogout(event) {
    event.preventDefault(); // Prevent accidental redirection
    sessionStorage.clear();
    localStorage.removeItem("user");
    localStorage.removeItem("jwt");
    localStorage.removeItem("userType");
    updateNavigation();
    window.location.href = "login.html"; // Redirect to login
}

// Protect routes (Ensure only authenticated users access restricted pages)
function protectRoute() {
    const user = checkAuth();
    if (!user) {
        window.location.href = "login.html"; // Redirect to login if not authenticated
    }
}

// Initialize the dashboard (Ensures only authenticated users access it)
function initializeDashboard() {
    protectRoute();
    const user = checkAuth();

    if (user) {
        const greetingElement = document.querySelector(".user-greeting");
        if (greetingElement) {
            greetingElement.innerHTML = `Welcome, <strong>${sanitizeHTML(user.name || "User")}</strong>!`;
        }
    }
}

// Run navigation update on page load
document.addEventListener("DOMContentLoaded", updateNavigation);

// Redirect user to the correct dashboard on login
if (window.location.pathname === "/dashboard.html") {
    document.addEventListener("DOMContentLoaded", handleUserRedirect);
}

// If the user is on a dashboard page, ensure they are authenticated
if (window.location.pathname.includes("student-dashboard.html") || window.location.pathname.includes("teacher-dashboard.html")) {
    document.addEventListener("DOMContentLoaded", initializeDashboard);
}
