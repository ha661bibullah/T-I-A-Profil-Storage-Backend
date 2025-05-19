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

// সার্ভারে আপলোড ফোল্ডার তৈরি (যদি না থাকে)
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// আপলোড করা ফাইলের স্ট্যাটিক সার্ভিং
app.use("/uploads", express.static(uploadDir));

// মুলটার কনফিগারেশন
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
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB ম্যাক্স সাইজ
  fileFilter: function (req, file, cb) {
    // শুধু ইমেজ ফাইল গ্রহণ করবে
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("শুধুমাত্র ছবি আপলোড করা যাবে"), false);
    }
    cb(null, true);
  },
});

// MongoDB কানেকশন
const uri = process.env.MONGO_URI;
const client = new MongoClient(uri);

async function connectDB() {
  try {
    await client.connect();
    console.log("✅ Connected to MongoDB");

    const db = client.db("userAuth");
    const users = db.collection("users");

    // JWT টোকেন ভেরিফাই করার ফাংশন
    function verifyToken(req, res, next) {
      const authHeader = req.headers.authorization;

      if (!authHeader) {
        return res.status(401).json({
          success: false,
          message: "অনুমতি নেই",
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
          message: "অবৈধ টোকেন",
        });
      }
    }

    // 1. টোকেন বৈধতা যাচাই API
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

    // 2. ব্যবহারকারীর প্রোফাইল তথ্য API
    app.get("/user-profile", verifyToken, async (req, res) => {
      try {
        const userId = req.userId;

        const user = await users.findOne({ _id: new ObjectId(userId) });

        if (!user) {
          return res.status(404).json({
            success: false,
            message: "ব্যবহারকারী পাওয়া যায়নি",
          });
        }

        // পাসওয়ার্ড সরিয়ে দিন
        const { password, ...userWithoutPassword } = user;

        res.json({
          success: true,
          user: userWithoutPassword,
        });
      } catch (error) {
        console.error("❌ Profile fetch error:", error);
        res.status(500).json({
          success: false,
          message: "সার্ভার এরর",
        });
      }
    });

    // 3. প্রোফাইল ছবি আপলোড API
    app.post("/upload-profile-picture", verifyToken, upload.single("profilePicture"), async (req, res) => {
      try {
        if (!req.file) {
          return res.status(400).json({
            success: false,
            message: "কোন ফাইল পাওয়া যায়নি",
          });
        }

        // সার্ভারে ফাইলের পাথ
        const fileUrl = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;

        res.json({
          success: true,
          message: "ছবি সফলভাবে আপলোড হয়েছে",
          pictureUrl: fileUrl,
        });
      } catch (error) {
        console.error("❌ Profile picture upload error:", error);
        res.status(500).json({
          success: false,
          message: "সার্ভার এরর",
        });
      }
    });

    // 4. প্রোফাইল আপডেট API
    app.put("/update-profile", verifyToken, async (req, res) => {
      try {
        const userId = req.userId;
        const { name, phone, birthday, gender, address, profilePicture } = req.body;

        // আপডেট ডাটা
        const updateData = {
          $set: {
            name: name,
            updatedAt: new Date(),
          },
        };

        // অপশনাল ফিল্ড
        if (phone) updateData.$set.phone = phone;
        if (birthday) updateData.$set.birthday = birthday;
        if (gender) updateData.$set.gender = gender;
        if (address) updateData.$set.address = address;
        if (profilePicture) updateData.$set.profilePicture = profilePicture;

        // আপডেট করুন
        await users.updateOne({ _id: new ObjectId(userId) }, updateData);

        // আপডেট করা ব্যবহারকারীর তথ্য নিন
        const updatedUser = await users.findOne({ _id: new ObjectId(userId) });

        if (!updatedUser) {
          return res.status(404).json({
            success: false,
            message: "ব্যবহারকারী পাওয়া যায়নি",
          });
        }

        // পাসওয়ার্ড সরিয়ে দিন
        const { password, ...userWithoutPassword } = updatedUser;

        res.json({
          success: true,
          message: "প্রোফাইল সফলভাবে আপডেট করা হয়েছে",
          user: userWithoutPassword,
        });
      } catch (error) {
        console.error("❌ Profile update error:", error);
        res.status(500).json({
          success: false,
          message: "সার্ভার এরর",
        });
      }
    });

    // 5. পাসওয়ার্ড পরিবর্তন API
    app.post("/change-password", verifyToken, async (req, res) => {
      try {
        const userId = req.userId;
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
          return res.status(400).json({
            success: false,
            message: "বর্তমান এবং নতুন পাসওয়ার্ড প্রদান করুন",
          });
        }

        // ব্যবহারকারী খুঁজুন
        const user = await users.findOne({ _id: new ObjectId(userId) });

        if (!user) {
          return res.status(404).json({
            success: false,
            message: "ব্যবহারকারী পাওয়া যায়নি",
          });
        }

        // বর্তমান পাসওয়ার্ড যাচাই করুন
        const isMatch = await bcrypt.compare(currentPassword, user.password);

        if (!isMatch) {
          return res.status(400).json({
            success: false,
            message: "বর্তমান পাসওয়ার্ড ভুল",
          });
        }

        // নতুন পাসওয়ার্ড হ্যাশ করুন
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // পাসওয়ার্ড আপডেট করুন
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

        // আপডেট করা ব্যবহারকারীর তথ্য নিন
        const updatedUser = await users.findOne({ _id: new ObjectId(userId) });

        // পাসওয়ার্ড সরিয়ে দিন
        const { password, ...userWithoutPassword } = updatedUser;

        res.json({
          success: true,
          message: "পাসওয়ার্ড সফলভাবে পরিবর্তন করা হয়েছে",
          user: userWithoutPassword,
        });
      } catch (error) {
        console.error("❌ Password change error:", error);
        res.status(500).json({
          success: false,
          message: "সার্ভার এরর",
        });
      }
    });

    // 6. Login route - প্রথম কোড থেকে অনুরূপ
    app.post("/login", async (req, res) => {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          message: "ইমেইল এবং পাসওয়ার্ড প্রদান করুন",
        });
      }

      try {
        // ব্যবহারকারী খুঁজুন
        const user = await users.findOne({ email });

        if (!user) {
          return res.json({
            success: false,
            message: "ভুল ইমেইল বা পাসওয়ার্ড",
          });
        }

        // পাসওয়ার্ড যাচাই করুন
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
          return res.json({
            success: false,
            message: "ভুল ইমেইল বা পাসওয়ার্ড",
          });
        }

        // JWT টোকেন তৈরি করুন
        const token = jwt.sign(
          { id: user._id },
          process.env.JWT_SECRET,
          { expiresIn: "1d" }
        );

        // পাসওয়ার্ড সরিয়ে দিন
        const { password: userPass, ...userWithoutPassword } = user;

        res.json({
          success: true,
          message: "লগইন সফল হয়েছে",
          user: userWithoutPassword,
          token: token,
        });
      } catch (error) {
        console.error("❌ Login error:", error);
        res.status(500).json({
          success: false,
          message: "সার্ভার এরর",
        });
      }
    });

    // 7. Register route - প্রথম কোড থেকে অনুরূপ
    app.post("/register", async (req, res) => {
      const { name, email, password } = req.body;
      
      if (!name || !email || !password) {
        return res.status(400).json({
          success: false,
          message: "সকল তথ্য প্রদান করুন",
        });
      }
      
      try {
        // ইমেইল আগে থেকে আছে কিনা তা যাচাই করুন
        const existingUser = await users.findOne({ email });
        
        if (existingUser) {
          return res.json({
            success: false,
            message: "এই ইমেইল দিয়ে একাউন্ট ইতিমধ্যে আছে",
          });
        }
        
        // পাসওয়ার্ড হ্যাশ করুন
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // ব্যবহারকারী তৈরি করুন
        const result = await users.insertOne({
          name,
          email,
          password: hashedPassword,
          createdAt: new Date(),
          updatedAt: new Date(),
          passwordLastUpdated: new Date()
        });

        // JWT টোকেন তৈরি করুন
        const token = jwt.sign(
          { id: result.insertedId },
          process.env.JWT_SECRET,
          { expiresIn: "1d" }
        );
        
        res.json({
          success: true,
          message: "রেজিস্ট্রেশন সফল হয়েছে",
          userId: result.insertedId,
          token: token
        });
      } catch (error) {
        console.error("❌ Registration error:", error);
        res.status(500).json({
          success: false,
          message: "সার্ভার এরর",
        });
      }
    });

    // স্যাম্পল টেস্ট রাউট
    app.get("/", (req, res) => {
      res.send("প্রোফাইল সার্ভার চালু আছে! 🚀");
    });

    // সার্ভার শুরু করুন
    app.listen(port, () => {
      console.log(`🚀 Server running on port ${port}`);
    });
  } catch (err) {
    console.error("❌ Database connection error:", err);
  }
}

// সার্ভার শুরু করুন
connectDB();

// সার্ভার বন্ধ করার ব্যবস্থা
process.on("SIGINT", async () => {
  await client.close();
  console.log("MongoDB connection closed");
  process.exit(0);
});