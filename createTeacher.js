require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const User = require("./backend/models/User");
const readline = require("readline");

// Create readline interface for user input
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

async function createTeacherAccount() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("Connected to MongoDB");

    // Get user input
    const email = await promptUser("Enter teacher email: ");
    
    // Check if teacher already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log("User with this email already exists!");
      mongoose.connection.close();
      rl.close();
      return;
    }
    
    const username = await promptUser("Enter username (or press enter for auto-generated): ");
    const finalUsername = username || "teacher_" + Math.floor(Math.random() * 10000);
    
    // Check if username exists
    if (username) {
      const existingUsername = await User.findOne({ username });
      if (existingUsername) {
        console.log("Username already taken. Please try another.");
        mongoose.connection.close();
        rl.close();
        return;
      }
    }
    
    const password = await promptUser("Enter password (or press enter for auto-generated): ");
    // Ensure password meets requirements (uppercase, number, 6+ chars)
    const passwordRegex = /^(?=.*[0-9])(?=.*[A-Z]).{6,}$/;
    const finalPassword = password || "Teacher" + Math.floor(Math.random() * 10000);
    
    if (password && !passwordRegex.test(password)) {
      console.log("Password must be at least 6 characters long, contain at least one number and one uppercase letter.");
      mongoose.connection.close();
      rl.close();
      return;
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(finalPassword, salt);

    // Create teacher user
    const user = new User({
      username: finalUsername,
      email,
      password: hashedPassword,
      userType: "teacher"
    });

    await user.save();
    console.log("\nTeacher account created successfully!");
    console.log("------------------------------");
    console.log("Email:", email);
    console.log("Username:", finalUsername);
    console.log("Password:", finalPassword);
    console.log("User Type: teacher");
    console.log("------------------------------");
    
    if (!password) {
      console.log("Please make sure to change your auto-generated password after first login");
    }
    
    mongoose.connection.close();
    rl.close();
  } catch (error) {
    console.error("Error creating teacher account:", error);
    mongoose.connection.close();
    rl.close();
  }
}

function promptUser(question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer);
    });
  });
}

createTeacherAccount(); 