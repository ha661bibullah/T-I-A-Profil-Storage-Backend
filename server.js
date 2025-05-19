require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const port = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Serve static files from uploads directory
app.use("/uploads", express.static(uploadDir));

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, "profile-" + uniqueSuffix + ext);
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max size
  fileFilter: function (req, file, cb) {
    // Only accept image files
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only images are allowed"), false);
    }
    cb(null, true);
  },
});

// MongoDB connection
const uri = process.env.MONGO_URI;
const client = new MongoClient(uri);

async function connectDB() {
  try {
    await client.connect();
    console.log("✅ Connected to MongoDB");

    const db = client.db("userAuth");
    const users = db.collection("users");

    // JWT token verification middleware
    function verifyToken(req, res, next) {
      const authHeader = req.headers.authorization;

      if (!authHeader) {
        return res.status(401).json({
          success: false,
          message: "Authorization required",
        });
      }

      const token = authHeader.split(" ")[1];

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.id;
        next();
      } catch (error) {
        return res.status(401).json({
          success: false,
          message: "Invalid token",
        });
      }
    }

    // 1. Token validation API
    app.post("/validate-token", (req, res) => {
      const authHeader = req.headers.authorization;

      if (!authHeader) {
        return res.json({
          valid: false,
        });
      }

      const token = authHeader.split(" ")[1];

      try {
        jwt.verify(token, process.env.JWT_SECRET);
        res.json({
          valid: true,
        });
      } catch (error) {
        res.json({
          valid: false,
        });
      }
    });

    // 2. User profile API
    app.get("/user-profile", verifyToken, async (req, res) => {
      try {
        const userId = req.userId;

        const user = await users.findOne({ _id: new ObjectId(userId) });

        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        // Remove password from response
        const { password, ...userWithoutPassword } = user;

        res.json({
          success: true,
          user: userWithoutPassword,
        });
      } catch (error) {
        console.error("❌ Profile fetch error:", error);
        res.status(500).json({
          success: false,
          message: "Server error",
        });
      }
    });

    // 3. Profile picture upload API
    app.post("/upload-profile-picture", verifyToken, upload.single("profilePicture"), async (req, res) => {
      try {
        if (!req.file) {
          return res.status(400).json({
            success: false,
            message: "No file provided",
          });
        }

        // File path on server
        const fileUrl = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;

        res.json({
          success: true,
          message: "Picture uploaded successfully",
          pictureUrl: fileUrl,
        });
      } catch (error) {
        console.error("❌ Profile picture upload error:", error);
        res.status(500).json({
          success: false,
          message: "Server error",
        });
      }
    });

    // 4. Profile update API
    app.put("/update-profile", verifyToken, async (req, res) => {
      try {
        const userId = req.userId;
        const { name, phone, birthday, gender, address, profilePicture } = req.body;

        // Update data
        const updateData = {
          $set: {
            name: name,
            updatedAt: new Date(),
          },
        };

        // Optional fields
        if (phone) updateData.$set.phone = phone;
        if (birthday) updateData.$set.birthday = birthday;
        if (gender) updateData.$set.gender = gender;
        if (address) updateData.$set.address = address;
        if (profilePicture) updateData.$set.profilePicture = profilePicture;

        // Update user
        await users.updateOne({ _id: new ObjectId(userId) }, updateData);

        // Get updated user data
        const updatedUser = await users.findOne({ _id: new ObjectId(userId) });

        if (!updatedUser) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        // Remove password from response
        const { password, ...userWithoutPassword } = updatedUser;

        res.json({
          success: true,
          message: "Profile updated successfully",
          user: userWithoutPassword,
        });
      } catch (error) {
        console.error("❌ Profile update error:", error);
        res.status(500).json({
          success: false,
          message: "Server error",
        });
      }
    });

    // 5. Password change API
    app.post("/change-password", verifyToken, async (req, res) => {
      try {
        const userId = req.userId;
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
          return res.status(400).json({
            success: false,
            message: "Provide current and new password",
          });
        }

        // Find user
        const user = await users.findOne({ _id: new ObjectId(userId) });

        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        // Verify current password
        const isMatch = await bcrypt.compare(currentPassword, user.password);

        if (!isMatch) {
          return res.status(400).json({
            success: false,
            message: "Current password is incorrect",
          });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update password
        await users.updateOne(
          { _id: new ObjectId(userId) },
          {
            $set: {
              password: hashedPassword,
              passwordLastUpdated: new Date(),
              updatedAt: new Date(),
            },
          }
        );

        // Get updated user data
        const updatedUser = await users.findOne({ _id: new ObjectId(userId) });

        // Remove password from response
        const { password, ...userWithoutPassword } = updatedUser;

        res.json({
          success: true,
          message: "Password changed successfully",
          user: userWithoutPassword,
        });
      } catch (error) {
        console.error("❌ Password change error:", error);
        res.status(500).json({
          success: false,
          message: "Server error",
        });
      }
    });

    // 6. Login route
    app.post("/login", async (req, res) => {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          message: "Email and password required",
        });
      }

      try {
        // Find user
        const user = await users.findOne({ email });

        if (!user) {
          return res.json({
            success: false,
            message: "Incorrect email or password",
          });
        }

        // Verify password
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
          return res.json({
            success: false,
            message: "Incorrect email or password",
          });
        }

        // Create JWT token
        const token = jwt.sign(
          { id: user._id },
          process.env.JWT_SECRET,
          { expiresIn: "1d" }
        );

        // Remove password from response
        const { password: userPass, ...userWithoutPassword } = user;

        res.json({
          success: true,
          message: "Login successful",
          user: userWithoutPassword,
          token: token,
        });
      } catch (error) {
        console.error("❌ Login error:", error);
        res.status(500).json({
          success: false,
          message: "Server error",
        });
      }
    });

    // 7. Register route
    app.post("/register", async (req, res) => {
      const { name, email, password } = req.body;
      
      if (!name || !email || !password) {
        return res.status(400).json({
          success: false,
          message: "All fields are required",
        });
      }
      
      try {
        // Check if email already exists
        const existingUser = await users.findOne({ email });
        
        if (existingUser) {
          return res.json({
            success: false,
            message: "An account with this email already exists",
          });
        }
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Create user
        const result = await users.insertOne({
          name,
          email,
          password: hashedPassword,
          createdAt: new Date(),
          updatedAt: new Date(),
          passwordLastUpdated: new Date()
        });

        // Create JWT token
        const token = jwt.sign(
          { id: result.insertedId },
          process.env.JWT_SECRET,
          { expiresIn: "1d" }
        );
        
        res.json({
          success: true,
          message: "Registration successful",
          userId: result.insertedId,
          token: token
        });
      } catch (error) {
        console.error("❌ Registration error:", error);
        res.status(500).json({
          success: false,
          message: "Server error",
        });
      }
    });

    // 8. Email check API for registration
    app.post("/check-email", async (req, res) => {
      const { email } = req.body;
      
      if (!email) {
        return res.status(400).json({
          success: false,
          message: "Email is required",
        });
      }
      
      try {
        const existingUser = await users.findOne({ email });
        
        return res.json({
          exists: !!existingUser,
          message: existingUser ? "Email already exists" : "Email is available"
        });
      } catch (error) {
        console.error("❌ Email check error:", error);
        return res.status(500).json({
          success: false,
          message: "Server error",
        });
      }
    });

    // 9. OTP send API
    app.post("/send-otp", async (req, res) => {
      const { email } = req.body;
      
      if (!email) {
        return res.status(400).json({
          success: false,
          message: "Email is required",
        });
      }
      
      try {
        // Generate a random 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Store OTP in database with expiration (10 minutes)
        await users.updateOne(
          { email },
          { 
            $set: {
              otp: otp,
              otpExpires: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
            }
          },
          { upsert: true }
        );
        
        // In production, send email with OTP
        console.log(`OTP for ${email}: ${otp}`);
        
        res.json({
          success: true,
          message: "OTP sent successfully"
        });
      } catch (error) {
        console.error("❌ OTP send error:", error);
        return res.status(500).json({
          success: false,
          message: "Server error",
        });
      }
    });

    // 10. OTP verification API
    app.post("/verify-otp", async (req, res) => {
      const { email, otp } = req.body;
      
      if (!email || !otp) {
        return res.status(400).json({
          success: false,
          message: "Email and OTP are required",
        });
      }
      
      try {
        const user = await users.findOne({ 
          email,
          otp: otp,
          otpExpires: { $gt: new Date() }
        });
        
        if (!user) {
          return res.json({
            success: false,
            message: "Invalid or expired OTP",
          });
        }
        
        // Clear OTP after successful verification
        await users.updateOne(
          { email },
          { 
            $unset: {
              otp: "",
              otpExpires: ""
            }
          }
        );
        
        res.json({
          success: true,
          message: "OTP verified successfully"
        });
      } catch (error) {
        console.error("❌ OTP verification error:", error);
        return res.status(500).json({
          success: false,
          message: "Server error",
        });
      }
    });

    // Test route
    app.get("/", (req, res) => {
      res.send("Profile server is running! 🚀");
    });
  } catch (err) {
    console.error("❌ Database connection error:", err);
  }
}

// Start server
connectDB().then(() => {
  app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
  });
});

// Handle server shutdown
process.on("SIGINT", async () => {
  await client.close();
  console.log("MongoDB connection closed");
  process.exit(0);
});