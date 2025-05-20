// backend/server.js - মূল সার্ভার ফাইল

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const path = require('path');

// .env ফাইল লোড করুন
dotenv.config();

// এক্সপ্রেস অ্যাপ তৈরি করুন
const app = express();

// মিডলওয়্যার সেটআপ
app.use(cors());
app.use(express.json({ limit: '10mb' })); // প্রোফাইল ছবি আপলোডের জন্য লিমিট বাড়ানো
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// MongoDB সংযোগ
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://admin:Kw5FmYPNbFMtWCPS@talimulcluster.irmh5p4.mongodb.net/?retryWrites=true&w=majority&appName=TalimulCluster', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB সংযোগ সফল হয়েছে'))
.catch(err => console.error('MongoDB সংযোগ ব্যর্থ হয়েছে:', err));

// ইউজার মডেল স্কিমা
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String },
  birthday: { type: Date },
  gender: { type: String },
  address: { type: String },
  profilePicture: { type: String },
  passwordLastUpdated: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// JWT টোকেন যাচাই মিডলওয়্যার
const authenticateToken = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'অনুরোধ করা হয়েছে কিন্তু টোকেন প্রদান করা হয়নি' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key', (err, user) => {
      if (err) {
        return res.status(403).json({ message: 'টোকেন অবৈধ বা মেয়াদ শেষ হয়েছে' });
      }
      
      req.user = user;
      next();
    });
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ message: 'অ্যাকাউন্ট যাচাইকরণে ত্রুটি ঘটেছে' });
  }
};

// নতুন ব্যবহারকারী নিবন্ধন
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // ইমেইল যাচাই করুন
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'এই ইমেইল দিয়ে ইতিমধ্যে একটি অ্যাকাউন্ট রয়েছে' });
    }
    
    // পাসওয়ার্ড হ্যাশ করুন
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // নতুন ইউজার তৈরি করুন
    const newUser = new User({
      name,
      email,
      password: hashedPassword
    });
    
    await newUser.save();
    
    // JWT টোকেন তৈরি করুন
    const token = jwt.sign(
      { id: newUser._id, email: newUser.email },
      process.env.JWT_SECRET || 'your_jwt_secret_key',
      { expiresIn: '7d' }
    );
    
    // পাসওয়ার্ড ছাড়া ইউজার ডাটা পাঠান
    const userData = {
      _id: newUser._id,
      name: newUser.name,
      email: newUser.email,
      phone: newUser.phone,
      birthday: newUser.birthday,
      gender: newUser.gender,
      address: newUser.address,
      profilePicture: newUser.profilePicture,
      passwordLastUpdated: newUser.passwordLastUpdated
    };
    
    res.status(201).json({
      message: 'ব্যবহারকারী সফলভাবে নিবন্ধিত হয়েছে',
      token,
      user: userData
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'নিবন্ধন প্রক্রিয়ায় ত্রুটি ঘটেছে' });
  }
});

// ব্যবহারকারী লগইন
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // ইউজার খুঁজুন
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'ইমেইল বা পাসওয়ার্ড ভুল' });
    }
    
    // পাসওয়ার্ড যাচাই করুন
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'ইমেইল বা পাসওয়ার্ড ভুল' });
    }
    
    // JWT টোকেন তৈরি করুন
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET || 'your_jwt_secret_key',
      { expiresIn: '7d' }
    );
    
    // পাসওয়ার্ড ছাড়া ইউজার ডাটা পাঠান
    const userData = {
      _id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      birthday: user.birthday,
      gender: user.gender,
      address: user.address,
      profilePicture: user.profilePicture,
      passwordLastUpdated: user.passwordLastUpdated
    };
    
    res.status(200).json({
      message: 'সফলভাবে লগইন হয়েছে',
      token,
      user: userData
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'লগইন প্রক্রিয়ায় ত্রুটি ঘটেছে' });
  }
});

// প্রোফাইল আপডেট
app.post('/api/update-profile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { name, phone, birthday, gender, address, profilePicture } = req.body;
    
    // ইউজার আপডেট করুন
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        $set: {
          name: name,
          phone: phone,
          birthday: birthday,
          gender: gender,
          address: address,
          profilePicture: profilePicture,
          updatedAt: new Date()
        }
      },
      { new: true, select: '-password' } // আপডেট হওয়া ডাটা ফেরত দিন, পাসওয়ার্ড বাদ দিয়ে
    );
    
    if (!updatedUser) {
      return res.status(404).json({ message: 'ব্যবহারকারী পাওয়া যায়নি' });
    }
    
    res.status(200).json({
      message: 'প্রোফাইল সফলভাবে আপডেট করা হয়েছে',
      user: updatedUser
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ message: 'প্রোফাইল আপডেট করতে ত্রুটি ঘটেছে' });
  }
});

// পাসওয়ার্ড পরিবর্তন
app.post('/api/change-password', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { currentPassword, newPassword } = req.body;
    
    // ইউজার খুঁজুন
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'ব্যবহারকারী পাওয়া যায়নি' });
    }
    
    // বর্তমান পাসওয়ার্ড যাচাই করুন
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'বর্তমান পাসওয়ার্ড ভুল' });
    }
    
    // নতুন পাসওয়ার্ড হ্যাশ করুন
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    
    // পাসওয়ার্ড আপডেট করুন
    user.password = hashedNewPassword;
    user.passwordLastUpdated = new Date();
    user.updatedAt = new Date();
    
    await user.save();
    
    res.status(200).json({ message: 'পাসওয়ার্ড সফলভাবে পরিবর্তন করা হয়েছে' });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ message: 'পাসওয়ার্ড পরিবর্তন করতে ত্রুটি ঘটেছে' });
  }
});

// প্রোফাইল তথ্য পান
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // ইউজার খুঁজুন, পাসওয়ার্ড বাদ দিয়ে 
    const user = await User.findById(userId).select('-password');
    
    if (!user) {
      return res.status(404).json({ message: 'ব্যবহারকারী পাওয়া যায়নি' });
    }
    
    res.status(200).json({ user });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ message: 'প্রোফাইল তথ্য আনতে ত্রুটি ঘটেছে' });
  }
});

// সার্ভার শুরু করুন
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`সার্ভার চালু আছে পোর্ট ${PORT} এ`);
});