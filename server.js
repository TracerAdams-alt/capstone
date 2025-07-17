const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const cors = require('cors');
const morgan = require('morgan');
const winston = require('winston');
require('dotenv').config();

const app = express();
const PORT = 3000;

// === Winston Logger Setup ===
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/server.log' }),
    new winston.transports.File({ filename: 'logs/errors.log', level: 'error' })
  ]
});

// === Morgan HTTP Logger ===
app.use(morgan('combined', {
  stream: {
    write: (message) => logger.info(message.trim())
  }
}));

// === Middleware ===
app.use(cors());
app.use(express.json());
app.use(passport.initialize());

// === MongoDB Connection ===
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/auth-demo', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// === User Schema ===
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role:     { type: String, enum: ['user', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now },
  isActive:  { type: Boolean, default: true }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.password;
  return user;
};

const User = mongoose.model('User', userSchema);

// === Course Schema ===
const courseSchema = new mongoose.Schema({
  title:       { type: String, required: true },
  description: String,
  createdBy:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt:   { type: Date, default: Date.now },
  isPublished: { type: Boolean, default: false }
});

const Course = mongoose.model('Course', courseSchema);

// === Passport Strategies ===
passport.use(new LocalStrategy(
  { usernameField: 'email', passwordField: 'password' },
  async (email, password, done) => {
    try {
      const user = await User.findOne({ email, isActive: true });
      if (!user) return done(null, false, { message: 'Invalid email or password' });
      const isMatch = await user.comparePassword(password);
      if (!isMatch) return done(null, false, { message: 'Invalid email or password' });
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

passport.use(new JwtStrategy(
  {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET || 'your-secret-key-change-this'
  },
  async (payload, done) => {
    try {
      const user = await User.findById(payload.id);
      if (user && user.isActive) return done(null, user);
      return done(null, false);
    } catch (error) {
      return done(error, false);
    }
  }
));

// === Token Generators ===
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, role: user.role },
    process.env.JWT_SECRET || 'your-secret-key-change-this',
    { expiresIn: '24h', issuer: 'your-app-name' }
  );
};

const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user._id },
    process.env.JWT_REFRESH_SECRET || 'your-refresh-secret',
    { expiresIn: '7d' }
  );
};

const authenticateToken = (req, res, next) => {
  passport.authenticate('jwt', { session: false }, (err, user) => {
    if (err) return res.status(500).json({ message: 'Authentication error' });
    if (!user) return res.status(401).json({ message: 'Access denied. Invalid token.' });
    req.user = user;
    next();
  })(req, res, next);
};

const validateRegistration = (req, res, next) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ message: 'Username, email, and password are required' });
  if (password.length < 6)
    return res.status(400).json({ message: 'Password must be at least 6 characters long' });
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email))
    return res.status(400).json({ message: 'Please provide a valid email address' });
  next();
};

// === Routes ===
app.get('/', (req, res) => {
  res.send('listening on port 3000');
});

app.post('/api/register', validateRegistration, async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'User with this email or username already exists' });
    }

    const user = new User({ username, email, password });
    await user.save();

    const token = generateToken(user);
    const refreshToken = generateRefreshToken(user);

    res.status(201).json({
      message: 'User registered successfully',
      user: user.toJSON(),
      token,
      refreshToken
    });
  } catch (error) {
    logger.error(`Registration error: ${error.message}`);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

app.post('/api/login', (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err) return res.status(500).json({ message: 'Authentication error' });
    if (!user) return res.status(401).json({ message: info.message || 'Invalid credentials' });

    const token = generateToken(user);
    const refreshToken = generateRefreshToken(user);

    res.json({
      message: 'Login successful',
      user: user.toJSON(),
      token,
      refreshToken
    });
  })(req, res, next);
});

app.post('/api/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: 'Refresh token required' });

    const decoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET || 'your-refresh-secret'
    );

    const user = await User.findById(decoded.id);
    if (!user || !user.isActive) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    const newToken = generateToken(user);
    const newRefreshToken = generateRefreshToken(user);

    res.json({ token: newToken, refreshToken: newRefreshToken });
  } catch (error) {
    res.status(401).json({ message: 'Invalid refresh token' });
  }
});

app.get('/api/me', authenticateToken, (req, res) => {
  res.json({ user: req.user.toJSON() });
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { username, email } = req.body;
    const userId = req.user._id;

    const existingUser = await User.findOne({
      $and: [{ _id: { $ne: userId } }, { $or: [{ email }, { username }] }]
    });

    if (existingUser) {
      return res.status(400).json({ message: 'Email or username already taken' });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { username, email },
      { new: true }
    );

    res.json({
      message: 'Profile updated successfully',
      user: updatedUser.toJSON()
    });
  } catch (error) {
    logger.error(`Profile update error: ${error.message}`);
    res.status(500).json({ message: 'Server error updating profile' });
  }
});

app.post('/api/logout', (req, res) => {
  res.json({ message: 'Logout successful' });
});

// === Filtered Course Routes ===
app.get('/api/courses', async (req, res) => {
  try {
    const { title, isPublished, createdBy } = req.query;

    const filter = {};
    if (title) filter.title = { $regex: title, $options: 'i' };
    if (isPublished !== undefined) filter.isPublished = isPublished === 'true';
    if (createdBy) filter.createdBy = createdBy;

    const courses = await Course.find(filter).populate('createdBy', 'username email');
    res.json(courses);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching courses' });
  }
});

app.post('/api/courses', authenticateToken, async (req, res) => {
  try {
    const { title, description, isPublished } = req.body;

    const course = new Course({
      title,
      description,
      isPublished,
      createdBy: req.user._id
    });

    await course.save();
    res.status(201).json({ message: 'Course created', course });
  } catch (err) {
    res.status(500).json({ message: 'Server error creating course' });
  }
});

app.get('/api/courses/:id', async (req, res) => {
  try {
    const course = await Course.findById(req.params.id).populate('createdBy', 'username email');
    if (!course) return res.status(404).json({ message: 'Course not found' });
    res.json(course);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching course' });
  }
});

app.put('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ message: 'Course not found' });

    if (!course.createdBy.equals(req.user._id) && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized to update this course' });
    }

    const { title, description, isPublished } = req.body;
    course.title = title || course.title;
    course.description = description || course.description;
    course.isPublished = isPublished !== undefined ? isPublished : course.isPublished;

    await course.save();
    res.json({ message: 'Course updated', course });
  } catch (err) {
    res.status(500).json({ message: 'Error updating course' });
  }
});

app.delete('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ message: 'Course not found' });

    if (!course.createdBy.equals(req.user._id) && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized to delete this course' });
    }

    await course.deleteOne();
    res.json({ message: 'Course deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting course' });
  }
});

// === Get Admin Users ===
app.get('/api/admins', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const admins = await User.find({ role: 'admin' }).select('-password');
    res.json(admins);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching admins' });
  }
});

// === Error Handler ===
app.use((err, req, res, next) => {
  logger.error(`${err.message} - ${req.method} ${req.originalUrl} - ${req.ip}`);
  res.status(500).json({ message: 'Something went wrong!' });
});

app.listen(PORT, () => {
  logger.info(`Server running on http://localhost:${PORT}`);
});

module.exports = app;
