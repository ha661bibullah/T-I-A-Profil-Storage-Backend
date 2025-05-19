// server.js - মূল এপ্লিকেশন ফাইল
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// পরিবেশ ভেরিয়েবলগুলো লোড করুন
dotenv.config();

// এক্সপ্রেস অ্যাপ তৈরি করুন
const app = express();
const PORT = process.env.PORT || 5000;

// মিডলওয়্যার সেটআপ
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// স্ট্যাটিক ফাইল সার্ভ করার জন্য
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// প্রোফাইল ছবি আপলোডের জন্য মাল্টার কনফিগারেশন
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        const uploadDir = 'uploads/profile';
        
        // ডিরেক্টরি না থাকলে তৈরি করুন
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        
        cb(null, uploadDir);
    },
    filename: function(req, file, cb) {
        const userId = req.user.id;
        const fileExt = path.extname(file.originalname);
        cb(null, `profile_${userId}_${Date.now()}${fileExt}`);
    }
});

// ফাইল ফিল্টার - শুধুমাত্র ছবি আপলোড করতে দিন
const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('শুধুমাত্র ছবি আপলোড করুন'), false);
    }
};

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 2 * 1024 * 1024 // 2MB সর্বোচ্চ ফাইল সাইজ
    },
    fileFilter: fileFilter
});

// মঙ্গোডিবি সংযোগ
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/userProfile', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('MongoDB সংযুক্ত হয়েছে'))
.catch(err => console.error('MongoDB সংযোগ ত্রুটি:', err));

// ইউজার মডেল স্কিমা
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true
    },
    phone: {
        type: String,
        trim: true
    },
    birthday: {
        type: Date
    },
    gender: {
        type: String,
        enum: ['পুরুষ', 'মহিলা', 'অন্যান্য', '']
    },
    address: {
        type: String,
        trim: true
    },
    profilePicture: {
        type: String
    },
    passwordLastUpdated: {
        type: Date,
        default: Date.now
    },
    createdAt: {
        type: Date,
        default: Date.now,
        immutable: true
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// সেশন মডেল স্কিমা
const sessionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    token: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: '7d' // 7 দিন পরে সেশন শেষ হবে
    }
});

// মডেল তৈরি করুন
const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);

// অথেনটিকেশন মিডলওয়্যার
const auth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ 
                error: 'অথেনটিকেশন টোকেন প্রয়োজন' 
            });
        }
        
        const token = authHeader.split(' ')[1];
        
        // টোকেন যাচাই করুন
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default_jwt_secret');
        
        // সেশন খুঁজুন
        const session = await Session.findOne({ 
            token: token, 
            userId: decoded.id 
        });
        
        if (!session) {
            return res.status(401).json({ 
                error: 'সেশন শেষ হয়ে গেছে, অনুগ্রহ করে আবার লগইন করুন' 
            });
        }
        
        // ইউজার আইডি দিয়ে ডাটাবেস থেকে ইউজার খুঁজুন
        const user = await User.findById(decoded.id).select('-password');
        
        if (!user) {
            return res.status(401).json({ 
                error: 'অবৈধ ব্যবহারকারী' 
            });
        }
        
        // ইউজার রিকোয়েস্টে যোগ করুন
        req.user = user;
        req.token = token;
        req.session = session;
        
        next();
    } catch (error) {
        console.error('অথেনটিকেশন ত্রুটি:', error);
        res.status(401).json({ 
            error: 'অথেনটিকেশন ব্যর্থ হয়েছে' 
        });
    }
};

// GET সার্ভার স্ট্যাটাস রুট
app.get('/api/status', (req, res) => {
    res.json({ status: 'active', message: 'সার্ভার সক্রিয় আছে' });
});

// POST রেজিস্ট্রেশন রুট
app.post('/api/users/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        // সব ফিল্ড আছে কিনা চেক করুন
        if (!name || !email || !password) {
            return res.status(400).json({ 
                error: 'সব প্রয়োজনীয় তথ্য দিন' 
            });
        }
        
        // ইমেইল বৈধ কিনা চেক করুন
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                error: 'অবৈধ ইমেইল ঠিকানা' 
            });
        }
        
        // পাসওয়ার্ড দৈর্ঘ্য চেক করুন
        if (password.length < 6) {
            return res.status(400).json({ 
                error: 'পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে' 
            });
        }
        
        // ইমেইল আগে থেকে আছে কিনা চেক করুন
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ 
                error: 'এই ইমেইল দিয়ে ইতিমধ্যে নিবন্ধিত আছে' 
            });
        }
        
        // পাসওয়ার্ড হ্যাশ করুন
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // নতুন ইউজার তৈরি করুন
        const user = new User({
            name,
            email,
            password: hashedPassword
        });
        
        // ডাটাবেসে ইউজার সেভ করুন
        await user.save();
        
        // JWT টোকেন তৈরি করুন
        const token = jwt.sign(
            { id: user._id }, 
            process.env.JWT_SECRET || 'default_jwt_secret', 
            { expiresIn: '7d' }
        );
        
        // সেশন তৈরি করুন
        const session = new Session({
            userId: user._id,
            token
        });
        
        await session.save();
        
        // ইউজার ডাটা পাঠান (পাসওয়ার্ড ছাড়া)
        res.status(201).json({
            message: 'ব্যবহারকারী সফলভাবে নিবন্ধিত হয়েছে',
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            },
            sessionToken: token
        });
    } catch (error) {
        console.error('রেজিস্ট্রেশন ত্রুটি:', error);
        res.status(500).json({ 
            error: 'সার্ভার ত্রুটি, দয়া করে আবার চেষ্টা করুন' 
        });
    }
});

// POST লগইন রুট
app.post('/api/users/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // সব ফিল্ড আছে কিনা চেক করুন
        if (!email || !password) {
            return res.status(400).json({ 
                error: 'ইমেইল এবং পাসওয়ার্ড প্রয়োজন' 
            });
        }
        
        // ইউজার খুঁজুন
        const user = await User.findOne({ email });
        
        if (!user) {
            return res.status(400).json({ 
                error: 'অবৈধ ইমেইল বা পাসওয়ার্ড' 
            });
        }
        
        // পাসওয়ার্ড যাচাই করুন
        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            return res.status(400).json({ 
                error: 'অবৈধ ইমেইল বা পাসওয়ার্ড' 
            });
        }
        
        // JWT টোকেন তৈরি করুন
        const token = jwt.sign(
            { id: user._id }, 
            process.env.JWT_SECRET || 'default_jwt_secret', 
            { expiresIn: '7d' }
        );
        
        // সেশন তৈরি করুন
        const session = new Session({
            userId: user._id,
            token
        });
        
        await session.save();
        
        // ইউজার ডাটা পাঠান (পাসওয়ার্ড ছাড়া)
        res.status(200).json({
            message: 'সফলভাবে লগইন হয়েছে',
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            },
            sessionToken: token
        });
    } catch (error) {
        console.error('লগইন ত্রুটি:', error);
        res.status(500).json({ 
            error: 'সার্ভার ত্রুটি, দয়া করে আবার চেষ্টা করুন' 
        });
    }
});

// GET সেশন যাচাই রুট
app.get('/api/users/validate-session', auth, (req, res) => {
    try {
        // auth মিডলওয়্যার থেকে ইউজার পাওয়া যাবে
        res.status(200).json({
            valid: true,
            user: req.user
        });
    } catch (error) {
        console.error('সেশন যাচাই ত্রুটি:', error);
        res.status(500).json({ 
            error: 'সার্ভার ত্রুটি' 
        });
    }
});

// GET ইউজার প্রোফাইল রুট
app.get('/api/users/profile', auth, (req, res) => {
    try {
        // auth মিডলওয়্যার থেকে ইউজার পাওয়া যাবে
        res.status(200).json({
            user: req.user
        });
    } catch (error) {
        console.error('প্রোফাইল লোড ত্রুটি:', error);
        res.status(500).json({ 
            error: 'সার্ভার ত্রুটি' 
        });
    }
});

// PUT ইউজার প্রোফাইল আপডেট রুট
app.put('/api/users/profile', auth, async (req, res) => {
    try {
        const { name, phone, birthday, gender, address } = req.body;
        const userId = req.user.id;
        
        // বাধ্যতামূলক নাম চেক করুন
        if (!name) {
            return res.status(400).json({ 
                error: 'নাম প্রয়োজন' 
            });
        }
        
        // ফোন নাম্বার বৈধ কিনা চেক করুন (যদি থাকে)
        if (phone) {
            const phoneRegex = /^01[3-9]\d{8}$/;
            if (!phoneRegex.test(phone)) {
                return res.status(400).json({ 
                    error: 'অবৈধ ফোন নাম্বার' 
                });
            }
        }
        
        // ইউজার আপডেট করুন
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            {
                name,
                phone,
                birthday,
                gender,
                address,
                updatedAt: Date.now()
            },
            { new: true }
        ).select('-password');
        
        if (!updatedUser) {
            return res.status(404).json({ 
                error: 'ব্যবহারকারী পাওয়া যায়নি' 
            });
        }
        
        res.status(200).json({
            message: 'প্রোফাইল সফলভাবে আপডেট করা হয়েছে',
            user: updatedUser
        });
    } catch (error) {
        console.error('প্রোফাইল আপডেট ত্রুটি:', error);
        res.status(500).json({ 
            error: 'সার্ভার ত্রুটি, দয়া করে আবার চেষ্টা করুন' 
        });
    }
});

// POST প্রোফাইল ছবি আপলোড রুট
app.post('/api/users/profile-picture', auth, upload.single('profilePicture'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ 
                error: 'কোন ফাইল আপলোড করা হয়নি' 
            });
        }
        
        const userId = req.user.id;
        
        // সার্ভারে ফাইলের পাথ
        const profilePictureUrl = `/uploads/profile/${req.file.filename}`;
        
        // পুরানো প্রোফাইল ছবি মুছুন (যদি থাকে)
        if (req.user.profilePicture) {
            const oldPicturePath = path.join(
                __dirname, 
                req.user.profilePicture.replace(/^\//, '')
            );
            
            if (fs.existsSync(oldPicturePath)) {
                fs.unlinkSync(oldPicturePath);
            }
        }
        
        // ইউজার আপডেট করুন
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            {
                profilePicture: profilePictureUrl,
                updatedAt: Date.now()
            },
            { new: true }
        ).select('-password');
        
        if (!updatedUser) {
            return res.status(404).json({ 
                error: 'ব্যবহারকারী পাওয়া যায়নি' 
            });
        }
        
        res.status(200).json({
            message: 'প্রোফাইল ছবি সফলভাবে আপডেট করা হয়েছে',
            profilePictureUrl: profilePictureUrl
        });
    } catch (error) {
        console.error('প্রোফাইল ছবি আপলোড ত্রুটি:', error);
        res.status(500).json({ 
            error: 'সার্ভার ত্রুটি, দয়া করে আবার চেষ্টা করুন' 
        });
    }
});

// PUT পাসওয়ার্ড পরিবর্তন রুট
app.put('/api/users/change-password', auth, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user.id;
        
        // সব ফিল্ড আছে কিনা চেক করুন
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ 
                error: 'বর্তমান এবং নতুন পাসওয়ার্ড প্রয়োজন' 
            });
        }
        
        // নতুন পাসওয়ার্ড দৈর্ঘ্য চেক করুন
        if (newPassword.length < 6) {
            return res.status(400).json({ 
                error: 'নতুন পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে' 
            });
        }
        
        // পূর্ণ ইউজার তথ্য নিন (পাসওয়ার্ডসহ)
        const user = await User.findById(userId);
        
        if (!user) {
            return res.status(404).json({ 
                error: 'ব্যবহারকারী পাওয়া যায়নি' 
            });
        }
        
        // বর্তমান পাসওয়ার্ড যাচাই করুন
        const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
        
        if (!isPasswordValid) {
            return res.status(400).json({ 
                error: 'INVALID_PASSWORD',
                message: 'বর্তমান পাসওয়ার্ড ভুল' 
            });
        }
        
        // নতুন পাসওয়ার্ড হ্যাশ করুন
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        
        // ইউজার আপডেট করুন
        user.password = hashedPassword;
        user.passwordLastUpdated = Date.now();
        user.updatedAt = Date.now();
        
        await user.save();
        
        res.status(200).json({
            message: 'পাসওয়ার্ড সফলভাবে পরিবর্তন করা হয়েছে'
        });
    } catch (error) {
        console.error('পাসওয়ার্ড পরিবর্তন ত্রুটি:', error);
        res.status(500).json({ 
            error: 'সার্ভার ত্রুটি, দয়া করে আবার চেষ্টা করুন' 
        });
    }
});

// POST লগআউট রুট
app.post('/api/users/logout', auth, async (req, res) => {
    try {
        // সেশন মুছুন
        await Session.findOneAndDelete({ token: req.token });
        
        res.status(200).json({
            message: 'সফলভাবে লগআউট হয়েছে'
        });
    } catch (error) {
        console.error('লগআউট ত্রুটি:', error);
        res.status(500).json({ 
            error: 'সার্ভার ত্রুটি' 
        });
    }
});

// 404 এরর হ্যান্ডলার
app.use((req, res) => {
    res.status(404).json({
        error: 'এই পাথ পাওয়া যায়নি'
    });
});

// সার্ভার শুরু করুন
app.listen(PORT, () => {
    console.log(`সার্ভার চালু হয়েছে: http://localhost:${PORT}`);
});