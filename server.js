// ============= FIREBASE ADMIN SDK WITH ENVIRONMENT VARIABLES =============
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const admin = require('firebase-admin');

// Load environment variables
require('dotenv').config(); // npm install dotenv
gr
const app = express();
app.use(cors());
app.use(express.json());
const port = process.env.PORT || 3000;
const secretKey = process.env.JWT_SECRET || 'tamil';

const serviceAccount ={
  "type": "service_account",
  "project_id": "trainertrack-e6238",
  "private_key_id": "9b496a765754492c521a3736205c8b2442665795",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXN+CYonP3gVsE\nZxNp/3LzCxaKPTL9bAHHnk/WL2liHwoXr6Chb0qjc4XbV3tADz3kumclpkg1RFDI\n9pkZA6xbKaXXgnNU1ylvZA+a0g6XHHuuzQTnGh+zMo7yyq1semd8ybLEExGR0Rqd\n9uyuRdm8p/gfTzXrg357cDZ4WFXzXJovOrBWjbciEMjHQ4NL+TY/+PWZMmVQCX8a\n9Hv4DVQG1ZoFPjQTA1kAVtl5rMctEd/euzdPcc/o9vAtj4WVUh09FtIIGUlwsbtf\no51lQNSQKLkKMkBdc8cNM9v2wVPi7On5S+EPm8GshK1yqeJx5xpTjmZGGEOyucSs\npqyxkAhfAgMBAAECggEAF3fx52MLp0k1TiEZVl0zQTqLzi5HQahF92kVhqMr6DW/\nSX7u0rvKlVFTHuyGtaET3D3RYqMjy58z+f4eCsLCSDyd54bDodRGoe104CqYybSi\n7hhQOQ05uLZCLUqZp7MfVtW9xzDXISH+t4wGGijmyfI9Fdjy5cg0gixl3DCxyrQy\nqOoufjmb1RlFhybtCSuvjkVlEloJqbVaBOIBX+La+RFrYsVkzAsznkQom0F6W1KZ\nEJPQ60vaKqBetyC1qwGTJsicm+MS4p2Mnytrdddv9eSCBJVfIgSiAAWoZZE0LdVl\n8UiME4sxEBDyCgj2wSf9YBwrWee/55aGC+KpAC73QQKBgQDzB+xgDrZv/6coxvbz\nPljU8ccsdWfa3B5sPiZBPbktlaQYIhSF+TY7AuEPc91lhkrgwdhoFQeYHM7CD+Fn\ngLANr5p7jasyAPYJBduv0E5JaAVCWgHOk+nPmEHtCSjecC7vdbsGhsKVihi/gMJ0\nRX1yn5Q9ptWNk8tuzFxou0zhwQKBgQDitABeame+rpjjIkJ9dVKMnY8tt+j9IJQX\nIoOIKRA4JA4d/dufQUJIwysR0AC4y4OesT72BOM1CjwVtBko/51qi4GNwE/LZecI\nUKUazCJtKYTP+HtAG0G2quw4/9fWJctUhwXjZa4A3tf2yymnhRAQVbFaNvGwgKxU\nP998J2kyHwKBgGwsw68B/Xyeq9X/sd4Vi07Fi6UjYSXOwo/lnft+MNW0fMTtLntv\nsQ7VOj45kXtmKiAeyGeTrLytXe6NSQRcCIEe/8EtDt2EBf+AJwf7zUzpSyX8kD9W\nIUVw/S8324QfJRUbLzM5epU7Ucaz1loQsET7+Oz0PKv29B8OQbewXwlBAoGAHLYH\nRe3b7b5XBo0UNqdhKQXbWELucwBpQPTSC7CHqVSHpSy9X9H3/xcYoUziioTbyoFQ\nJABCdjkxmt4QQaz91ryMT9OHR49ETz1Ha7lmssSLWXtywI+zJttGx4E/aJOoyK/B\nAyehfeK7HzpjsB+eBTOVHoPO4Derm4/rUeH75KkCgYEAuQT+9tumKIzE8FmhiXL5\nnR8NT2qJ9RMxCCwnfwZ2oNA8aBd7hJ1Lzk311jNQI9iEmsWt4qsyL3qy41j95R4C\nff3MNkqv+p2UXdJBty/A0hQ/E10SZfmEGf94pxZEvDvtWUV5ERpWHGBHPERRmhuX\nIepIHS8yqEAx4kK7NSzZE0Q=\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-fbsvc@trainertrack-e6238.iam.gserviceaccount.com",
  "client_id": "117021301682543078913",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40trainertrack-e6238.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
};

let initTime = Date.now();

// ============= FIREBASE INITIALIZATION WITH ERROR HANDLING =============
async function initializeFirebaseWithRetry(maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      // Delete existing apps if any
      admin.apps.forEach(app => app.delete());
      
      // Initialize with fresh credentials
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
      });
      
      // Test the connection immediately
      await admin.app().options.credential.getAccessToken();
      console.log(`✅ Firebase Admin initialized successfully (attempt ${i + 1})`);
      initTime = Date.now();
      return;
    } catch (error) {
      console.error(`❌ Firebase init attempt ${i + 1} failed:`, error.message);
      if (i === maxRetries - 1) {
        throw new Error(`Failed to initialize Firebase after ${maxRetries} attempts: ${error.message}`);
      }
      
      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, 2000 * (i + 1)));
    }
  }
}

// ============= TOKEN REFRESH UTILITIES =============
async function ensureFreshFirebaseToken() {
  try {
    // Force token refresh
    await admin.app().options.credential.getAccessToken(true);
    return true;
  } catch (error) {
    console.warn('🔄 Token refresh failed, reinitializing Firebase...', error.message);
    await initializeFirebaseWithRetry();
    return true;
  }
}

// Wrapper function for Firebase operations with retry logic
async function withFirebaseRetry(operation, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await operation();
    } catch (error) {
      const isAuthError = error.message.includes('invalid_grant') || 
                         error.message.includes('Invalid JWT') ||
                         error.message.includes('credential');
      
      if (isAuthError && i < maxRetries - 1) {
        console.log(`🔄 Retry ${i + 1} after credential error: ${error.message}`);
        
        // Reinitialize Firebase
        await initializeFirebaseWithRetry();
        
        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, 1000));
        continue;
      }
      throw error;
    }
  }
}

// ============= AUTOMATIC TOKEN REFRESH =============
function setupAutomaticTokenRefresh() {
  // Refresh token every 20 minutes (before it expires)
  setInterval(async () => {
    try {
      console.log('🔄 Refreshing Firebase token...');
      await ensureFreshFirebaseToken();
      console.log('✅ Token refreshed successfully');
    } catch (error) {
      console.error('❌ Scheduled token refresh failed:', error.message);
    }
  }, 20 * 60 * 1000); // 20 minutes
  
  console.log('⏰ Automatic token refresh scheduled every 20 minutes');
}

// ============= INITIALIZE FIREBASE =============
async function startFirebase() {
  try {
    await initializeFirebaseWithRetry();
    setupAutomaticTokenRefresh();
    
    // Log initialization info
    console.log('📊 Firebase initialized at:', new Date().toISOString());
    console.log('🕐 Server timezone:', Intl.DateTimeFormat().resolvedOptions().timeZone);
    
  } catch (error) {
    console.error('💥 Critical Firebase initialization error:', error);
    process.exit(1); // Exit if Firebase can't be initialized
  }
}

// ============= ERROR HANDLING MIDDLEWARE =============
process.on('unhandledRejection', (error) => {
  if (error.message && error.message.includes('invalid_grant')) {
    console.error('🚨 JWT signature error detected at:', new Date().toISOString());
    console.error('⏱️  Time since last init:', Math.floor((Date.now() - initTime) / 1000 / 60), 'minutes');
    
    // Try to recover automatically
    initializeFirebaseWithRetry().catch(err => {
      console.error('💥 Failed to recover from JWT error:', err);
    });
  }
});

// ============= HELPER FUNCTIONS FOR YOUR ROUTES =============

// Use this function to wrap any Firestore operations
async function safeFirestoreOperation(operation) {
  return withFirebaseRetry(operation);
}



// MongoDB connection
mongoose.connect('mongodb+srv://covailabs1:dpBIwF4ZZcJQkgjA@cluster0.jr1ju8f.mongodb.net/trainer_track?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('Connected to MongoDB')).catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  number: { type: String, required: true, unique: true },
  isAdmin: { type: Boolean, default: false },
});
const User = mongoose.model('User', userSchema);

// Destination Schema
const destinationSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  latitude: { type: Number, required: true },
  longitude: { type: Number, required: true },
  date: { type: String, required: true },
  assignedAt: { type: Date, default: Date.now },
});
destinationSchema.index({ userId: 1, date: 1 }, { unique: true });
const Destination = mongoose.model('Destination', destinationSchema);

// Location Schema
const locationSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  latitude: { type: Number, required: true },
  longitude: { type: Number, required: true },
  speed: { type: Number, default: 0.0 },
  appStatus: { type: String, enum: ['foreground', 'background','offline'], default: 'offline' },
  timestamp: { type: Date, default: Date.now },
});
const Location = mongoose.model('Location', locationSchema);

// History Schema
const historySchema = new mongoose.Schema({
  userId: { type: String, required: true },
  date: { type: String, required: true },
  distance: { type: Number, required: true },
  timeTaken: { type: String, required: true },
  path: [{ latitude: Number, longitude: Number }],
  startLatitude: { type: Number },
  startLongitude: { type: Number },
});
const History = mongoose.model('History', historySchema);

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    req.userId = decoded.userId;
    req.isAdmin = decoded.isAdmin;
    next();
  });
};

// Log all incoming requests for debugging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('Login request:', req.body);
  try {
    const user = await User.findOne({ username });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, secretKey, { expiresIn: '1h' });
    res.json({ userId: user._id, token, isAdmin: user.isAdmin });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Tracking started endpoint (admin receives notification) - WITH FIREBASE RETRY
app.post('/api/tracking-started', async (req, res) => {
  const { userId, timestamp } = req.body;
  
  try {
    // Fetch user details from User model
    const user = await User.findById(userId, '-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const userName = user.name || user.username || 'Unknown User';

    // Send notification with Firebase retry logic
    const messagingResult = await safeFirestoreOperation(async () => {
      const adminMessage = {
        notification: {
          title: 'User Tracking Started',
          body: `${userName} started location tracking`
        },
        data: {
          userId: userId.toString(),
          userName: userName,
          action: 'tracking_started',
          timestamp: timestamp ? timestamp.toString() : new Date().toISOString()
        },
        topic: 'admin_notifications'
      };
      
      return await admin.messaging().send(adminMessage);
    });
    
    res.status(200).json({
      success: true,
      message: 'Tracking started notification sent',
      user: userName,
      messageId: messagingResult
    });
    
  } catch (err) {
    console.error('Full error stack:', err.stack);
    
    if (err.code && err.code.startsWith('messaging/')) {
      console.error('🔥 Firebase Messaging Error Details:');
      console.error('Error code:', err.code);
      console.error('Error details:', err.details);
    }
    
    if (err.name === 'CastError') {
      console.error('🔍 MongoDB CastError - Invalid userId format');
    }
    
    res.status(500).json({ 
      message: 'Server error',
      error: err.message,
      errorCode: err.code
    });
  }
});

app.post('/api/tracking-stopped', async (req, res) => {
  const { userId, timestamp } = req.body;
  
  try {
    const user = await User.findById(userId, '-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const userName = user.name || user.username || 'Unknown User';
    
    // Send notification with Firebase retry logic
    const messagingResult = await safeFirestoreOperation(async () => {
      const adminMessage = {
        notification: {
          title: 'User Tracking Stopped',
          body: `${userName} stopped location tracking`
        },
        data: {
          userId: userId.toString(),
          userName: userName,
          action: 'tracking_stopped',
          timestamp: timestamp ? timestamp.toString() : new Date().toISOString()
        },
        topic: 'admin_notifications'
      };
      
      return await admin.messaging().send(adminMessage);
    });
    
    console.log('✅ Notification sent successfully!');
    
    res.status(200).json({
      success: true,
      message: 'Tracking stopped notification sent',
      user: userName,
      messageId: messagingResult
    });
    
  } catch (err) {
    console.error('Full error stack:', err.stack);
    
    if (err.code && err.code.startsWith('messaging/')) {
      console.error('🔥 Firebase Messaging Error Details:');
      console.error('Error code:', err.code);
      console.error('Error details:', err.details);
    }
    
    if (err.name === 'CastError') {
      console.error('🔍 MongoDB CastError - Invalid userId format');
    }
    
    res.status(500).json({ 
      message: 'Server error',
      error: err.message,
      errorCode: err.code
    });
  }
});

// Get all users (admin only)
app.get('/users', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  try {
    const users = await User.find({}, '-password');
    res.json(users);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user statuses (admin only)
app.get('/users/status', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  try {
    const users = await User.find({}, '-password');
    const locations = await Location.aggregate([
      { $sort: { userId: 1, timestamp: -1 } },
      {
        $group: {
          _id: '$userId',
          userId: { $first: '$userId' },
          appStatus: { $first: '$appStatus' },
          timestamp: { $first: '$timestamp' },
        },
      },
    ]);
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    const userStatuses = users.map(user => {
      const location = locations.find(loc => loc.userId === user._id.toString());
      const status = location && location.timestamp >= fiveMinutesAgo ? location.appStatus : 'offline';
      return {
        _id: user._id,
        username: user.username,
        name: user.name,
        email: user.email,
        number: user.number,
        isAdmin: user.isAdmin,
        status,
        isSendingLocation: !!location && location.timestamp >= fiveMinutesAgo,
      };
    });
    res.json(userStatuses);
  } catch (err) {
    console.error('Get user statuses error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add user (admin only)
app.post('/users', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  try {
    const { username, password, name, email, number } = req.body;
    console.log('Add user request:', req.body);
    if (!username || !password || !name || !email || !number) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    const existingUser = await User.findOne({ $or: [{ username }, { email }, { number }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Username, email, or number already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword, name, email, number });
    await user.save();
    res.status(201).json({ message: 'User created' });
  } catch (err) {
    console.error('Add user error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update user (admin only)
app.put('/users/:userId', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  try {
    const { username, password, name, email, number } = req.body;
    const updateData = { username, name, email, number };
    if (password) updateData.password = await bcrypt.hash(password, 10);
    const existingUser = await User.findOne({
      $or: [{ username }, { email }, { number }],
      _id: { $ne: req.params.userId },
    });
    if (existingUser) {
      return res.status(400).json({ message: 'Username, email, or number already exists' });
    }
    const updatedUser = await User.findByIdAndUpdate(req.params.userId, updateData, { new: true });
    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User updated' });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete user (admin only)
app.delete('/users/:userId', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  try {
    const user = await User.findByIdAndDelete(req.params.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    await Destination.deleteMany({ userId: req.params.userId });
    await Location.deleteMany({ userId: req.params.userId });
    await History.deleteMany({ userId: req.params.userId });
    res.json({ message: 'User and associated data deleted' });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Assign destination (admin only) - WITH FIREBASE RETRY
app.post('/destination', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  
  try {
    const { userId, latitude, longitude,date } = req.body;
    console.log('Assign destination request:', req.body);
    
    if (!userId || !latitude || !longitude) {
      return res.status(400).json({ message: 'userId, latitude, and longitude are required' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const destination = await Destination.findOneAndUpdate(
      { userId },
      { latitude, longitude },
      {date},
      { new: true, upsert: true }
    );

    // Send notification with Firebase retry logic
    await safeFirestoreOperation(async () => {
      const adminMessage = {
        notification: {
          title: 'Destination assigned',
          body: `You have been assigned with a new destination`
        },
        data: {
          action: 'destination_assigned',
        },
        topic: `destination_${userId}`
      };
      
      const messagingResult = await admin.messaging().send(adminMessage);
      console.log('✅ Destination notification sent successfully:', messagingResult);
      return messagingResult;

    });
    
    const message = destination.isNew ? 'Destination assigned' : 'Destination updated';
    res.status(201).json({ message });
  } catch (err) {
    console.error('Assign destination error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user destination
app.get('/destination/:userId', verifyToken, async (req, res) => {
  try {
    const destination = await Destination.findOne({ 
      userId: req.params.userId
    });
    
    if (!destination) {
      return res.status(404).json({ message: 'No destination found' });
    }
    
    res.json({ 
      userId: destination.userId, 
      latitude: destination.latitude, 
      longitude: destination.longitude,
      date: destination.date 
    });
  } catch (err) {
    console.error('Get destination error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete destination (admin only)
app.delete('/destination/:userId', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  
  try {
    const destination = await Destination.findOneAndDelete({ 
      userId: req.params.userId
    });
    
    if (!destination) {
      return res.status(404).json({ message: 'No destination found' });
    }
    
    res.json({ message: 'Destination deleted' });
  } catch (err) {
    console.error('Delete destination error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user tracking data
app.get('/tracking/:userId', verifyToken, async (req, res) => {
  try {
    const locations = await Location.find({ userId: req.params.userId }).sort({ timestamp: -1 }).limit(1);
    if (!locations.length) return res.status(404).json({ message: 'No tracking data found' });
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    console.log('Tracking data:', locations)
    res.json({
      userId: locations[0].userId,
      latitude: locations[0].latitude,
      longitude: locations[0].longitude,
      speed: locations[0].speed ?? 0.0,
      appStatus: locations[0].timestamp >= fiveMinutesAgo ? locations[0].appStatus : 'offline',
      isSendingLocation: locations[0].timestamp >= fiveMinutesAgo,
      timestamp: locations[0].timestamp,
    });
  } catch (err) {
    console.error('Get tracking data error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all user locations (admin only)
app.get('/locations', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  try {
    const locations = await Location.aggregate([
      { $sort: { userId: 1, timestamp: -1 } },
      {
        $group: {
          _id: '$userId',
          userId: { $first: '$userId' },
          latitude: { $first: '$latitude' },
          longitude: { $first: '$longitude' },
          speed: { $first: '$speed' },
          appStatus: { $first: '$appStatus' },
          timestamp: { $first: '$timestamp' },
        },
      },
    ]);
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    res.json(locations.map(loc => ({
      userId: loc.userId,
      latitude: loc.latitude,
      longitude: loc.longitude,
      speed: loc.speed ?? 0.0,
      appStatus: loc.timestamp >= fiveMinutesAgo ? loc.appStatus : 'offline',
      isSendingLocation: loc.timestamp >= fiveMinutesAgo,
      timestamp: loc.timestamp,
    })));
  } catch (err) {
    console.error('Get locations error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user history
app.get('/history/:userId', verifyToken, async (req, res) => {
  try {
    const history = await History.find({ userId: req.params.userId }).sort({ date: -1 });
    res.json(history);
  } catch (err) {
    console.error('Get history error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Send location data
app.post('/location', verifyToken, async (req, res) => {
  try {
    const { userId, latitude, longitude, speed, timestamp, startLatitude, startLongitude, isStartLocation, appStatus } = req.body;
    console.log('Send location request:', req.body);

    if (!userId || !latitude || !longitude) {
      return res.status(400).json({ message: 'userId, latitude, and longitude are required' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const locationData = {
      userId,
      latitude,
      longitude,
      speed: speed ?? 0.0,
      appStatus: appStatus,
      timestamp: timestamp ? new Date(timestamp) : Date.now(),
    };

    await Location.findOneAndUpdate(
      { userId },
      locationData,
      { upsert: true, new: true }
    );

    const date = new Date(timestamp || Date.now()).toISOString().split('T')[0];
    const locations = await Location.find({ 
      userId, 
      timestamp: { $gte: new Date(date) } 
    }).sort({ timestamp: 1 });

    let path = locations.map(loc => ({ 
      latitude: loc.latitude, 
      longitude: loc.longitude 
    }));

    const historyData = {
      userId,
      date,
      distance: 0,
      timeTaken: '0.00 minutes',
      path,
    };

    if (isStartLocation && startLatitude != null && startLongitude != null) {
      historyData.startLatitude = startLatitude;
      historyData.startLongitude = startLongitude;
      historyData.path = [{ latitude: startLatitude, longitude: startLongitude }, ...path];
    }

    if (historyData.path.length > 1) {
      historyData.distance = calculateDistance(historyData.path);
      historyData.timeTaken = calculateTimeTaken(locations);
    }

    await History.findOneAndUpdate(
      { userId, date },
      historyData,
      { upsert: true, new: true }
    );

    res.status(201).json({ message: 'Location saved' });
  } catch (err) {
    console.error('Send location error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Helper function to calculate distance (Haversine formula)
function calculateDistance(locations) {
  let totalDistance = 0;
  for (let i = 1; i < locations.length; i++) {
    const lat1 = locations[i - 1].latitude;
    const lon1 = locations[i - 1].longitude;
    const lat2 = locations[i].latitude;
    const lon2 = locations[i].longitude;
    const R = 6371e3;
    const φ1 = lat1 * Math.PI / 180;
    const φ2 = lat2 * Math.PI / 180;
    const Δφ = (lat2 - lat1) * Math.PI / 180;
    const Δλ = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
              Math.cos(φ1) * Math.cos(φ2) *
              Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    totalDistance += R * c / 1000;
  }
  return Number(totalDistance.toFixed(2));
}

// Helper function to calculate time taken
function calculateTimeTaken(locations) {
  if (locations.length < 2) return '0.00 minutes';
  const start = new Date(locations[0].timestamp);
  const end = new Date(locations[locations.length - 1].timestamp);
  const diff = (end - start) / 1000 / 60;
  return `${diff.toFixed(2)} minutes`;
}

// ============= START THE APPLICATION =============
async function startServer() {
  try {
    // Initialize Firebase first
    await startFirebase();
    
    // Start the Express server
    app.listen(port, () => {
      console.log(`🚀 Server running on port ${port}`);
      console.log('🔥 Firebase Admin SDK ready with error recovery');
    });
  } catch (error) {
    console.error('💥 Failed to start server:', error);
    process.exit(1);
  }
}

// Start the server
startServer();

// ============= EXPORT UTILITIES FOR YOUR ROUTES =============
module.exports = {
  safeFirestoreOperation,
  withFirebaseRetry,
  ensureFreshFirebaseToken
};