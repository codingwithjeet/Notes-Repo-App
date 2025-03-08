require("dotenv").config();
const passport = require("passport");
const { Strategy: GoogleStrategy } = require("passport-google-oauth20");
const User = require("./models/User");

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/api/auth/google/callback",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Check if user already exists
        let user = await User.findOne({ googleId: profile.id });
        
        if (!user) {
          // Check if email is already registered
          const email = profile.emails?.[0]?.value;
          if (!email) {
            return done(new Error("No email found in Google profile"));
          }

          user = await User.findOne({ email });
          
          if (user) {
            // Update existing user with Google ID
            user.googleId = profile.id;
            await user.save();
          } else {
            // Look for existing accounts with educational domain to determine user type
            const isEducationalDomain = email.endsWith('.edu') || 
                                       email.includes('teacher') || 
                                       email.includes('faculty');
            
            // Generate a unique username
            let username = profile.displayName || email.split("@")[0];
            let isUnique = false;
            let counter = 0;
            
            // Check if username is unique, if not add a number suffix
            while (!isUnique) {
              const existingUser = await User.findOne({ 
                username: counter === 0 ? username : `${username}${counter}` 
              });
              
              if (!existingUser) {
                isUnique = true;
                if (counter > 0) {
                  username = `${username}${counter}`;
                }
              } else {
                counter++;
              }
            }
            
            // Create new user
            user = new User({
              googleId: profile.id,
              email: email,
              username: username,
              // Set user type based on email domain hint, default to student otherwise
              userType: isEducationalDomain ? "teacher" : "student",
              password: null // No password for Google auth users
            });
            await user.save();
          }
        }

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

module.exports = passport;