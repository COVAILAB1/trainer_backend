// ============= FIREBASE ADMIN SDK WITH ENVIRONMENT VARIABLES =============
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const admin = require('firebase-admin');
const { CronJob } = require('cron');

// Load environment variables
require('dotenv').config(); // npm install dotenv
const app = express();
app.use(cors());
app.use(express.json());
const port = process.env.PORT || 3000;
const secretKey = process.env.JWT_SECRET || 'tamil';

const serviceAccount ={
  "type": "service_account",
  "project_id": "trainertrack-e6238",
  "private_key_id": "79b4f6f5ffe1ede79aaadff262a3f83caf8ebf82",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCkUfoXv1hrkMyL\nO6sJcCdJwuviCGHBnbegtcROqDY8nxHiHy/jl9XU7OysYpyfa/3eBvMNvPgxaBut\npH6iuX1YB2vcelstyxkawksAGYfs7fH10AENeCR6rJHKE0EIczKcRiCiutTsB+x9\ntIKk4IavduMyxXiAYfQfw8Ro00NjCSf3eanGhzP9hmWb3Nl9iLyzpf2IgDeftyDU\nXLafX1LEM6zbLd22US+M+iRaoWVVlwUvEdWv97JYytnEGA0IYxAWueH4ag7LrHzI\nYyDFaukGOoFxap7U9xO4i1Lyw3nonU6rSz6/53xe8os2HwmyemaehRJFfH3RFooQ\nUyzZ9LP3AgMBAAECggEANcOIw6pcwN0gv9GnFbB3el/nlA5QBeyXv2KZt268SDt3\nu3ee0KXGViOrEIA3ZMYNy06UygLxZiD9JWRz9sQgKeRLu1jhamtQbHvz1DWGTtRP\n3bDQF1se/HBoRyjjl2MxxQYA+Z2NuyigjUS5lj7Mcq7AicUot0DVgmsoYW/2VXmL\nbOoxqIHq11JNnZHm+uILdg8xDtZKGkAmkPs2Z3uYYqjPAZYWEMhwMv/f8dJot/gF\nVhQ7jtTzZvy+uurbD5slGV/xAgj4X/RFpq8BeKObgfEYNJCiaIW41SkUem2KFx/2\nYn+Ue0FhNI4qsDPNbJ3G/nxwHt47sxZ47cgT8KGwWQKBgQDlA79sM99OAmD8sfwK\nBrIXv789wu4VlBOuCAFaIir6MXHiqvygsIXtBvt7npRa9EOXsoJo/sFFJgrlsbrO\nbOERLjUkHGYbVWbDcDScd6BmFERv+5aS9x3txvkrqn2Ti96kCjuTEILsHNVwJs0f\nypIXJlFLNrc/yFdyCwP6mqyB+wKBgQC3rrb/kTRUClef206OPv0/8FLsch2c2gfL\ndwKg+QIP40rrvjaRMQeZD7Gq5iqL37w1mcRsqucmuaqfWOoe4YmOcLCluEV9PBNl\nPMNFMEcgCfyJhOig/Xjb48VZwLWv3dALBy9Fvj8C0nWOW9QrKE1Q3Pullw7A7Opb\n9d9k9DpxNQKBgE7HS0HdViNvjg1e7GRGiVzCCPcl5uBlX5+uAUkQF9iYyaQ/TUe5\ncVhn3npXwpDHFblJHrMfbzxqKbV5vdjke0d9raoOWtFsPz1bi72HKRX0QtaCpPlJ\nKHJyz6PFsgzfQGcNXhDozSCLiqBZuJYHCNoNxEkrOT4nnG0OfP/n1Q+hAoGAIBdc\nTYZW+B/ec0VjkiKbKGKaekjtt4u4NOoUAX+/xnrVih5vdip0w18kkVEpOcrbHRpC\nYSHyxKdHkhN8w+xvlf1GP43URi8KzHMzQpFOu+BCyNv5sLbYOMKwph+vHozIXkTh\nE3RLmfifJUIR7YBbEbeqF6Iup7I8t9hbMU4iL8kCgYB9VAF8cPRTLch9Ici9ZHM6\n7Ga1cMy28oj6N0uSWKGQjJcaifEugxV8NJ9Knx/iJk1cK1OBH0rQ7URA06jSiEVt\np3tQeKWcZjGuy3vZKLOWVTs/qe3zU75s4Hk1jW6qoEspXjSDkJI4wORJc0jlOQme\nnFuvPaHGoDoooTsi1p6QzA==\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-fbsvc@trainertrack-e6238.iam.gserviceaccount.com",
  "client_id": "117021301682543078913",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40trainertrack-e6238.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
};

let initTime = Date.now();
// ============= TIME SYNC UTILITIES =============
async function syncSystemTime() {
  try {
    console.log('🕐 Attempting to sync system time...');
    
    // Get current time from a reliable source
    const response = await fetch('http://worldtimeapi.org/api/timezone/Etc/UTC');
    const timeData = await response.json();
    const correctTime = new Date(timeData.datetime);
    const systemTime = new Date();
    
    const timeDiff = Math.abs(correctTime.getTime() - systemTime.getTime());
    console.log(`⏰ Time difference: ${timeDiff}ms`);
    console.log(`🌍 Correct UTC time: ${correctTime.toISOString()}`);
    console.log(`💻 System time: ${systemTime.toISOString()}`);
    
    if (timeDiff > 30000) { // More than 30 seconds difference
      console.warn('⚠️  Significant time drift detected!');
      console.log('🔧 Consider using NTP sync in your deployment');
    }
    
    return { timeDiff, correctTime, systemTime };
  } catch (error) {
    console.warn('⚠️  Time sync check failed:', error.message);
    return null;
  }
}

// ============= FIREBASE INITIALIZATION WITH ERROR HANDLING =============
async function initializeFirebaseWithRetry(maxRetries = 5) {
  // First attempt: Check time sync
  await syncSystemTime();
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      // Delete existing apps if any
      admin.apps.forEach(app => app.delete());
      
      console.log(`🔥 Initializing Firebase (attempt ${i + 1}/${maxRetries})...`);
      
      // Add some randomness to avoid repeated failures
      if (i > 0) {
        const delay = Math.random() * 2000 + 1000; // 1-3 seconds
        console.log(`⏳ Waiting ${delay.toFixed(0)}ms before retry...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
      
      // Initialize with fresh credentials
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
      });
      
      // Test the connection immediately with timeout
      const tokenPromise = admin.app().options.credential.getAccessToken();
      const timeoutPromise = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Token fetch timeout')), 10000)
      );
      
      await Promise.race([tokenPromise, timeoutPromise]);
      
      console.log(`✅ Firebase Admin initialized successfully (attempt ${i + 1})`);
      initTime = Date.now();
      return;
    } catch (error) {
      console.error(`❌ Firebase init attempt ${i + 1} failed:`, error.message);
      
      // Log additional debug info
      if (error.message.includes('invalid_grant')) {
        console.log('🔍 JWT signature error - likely time sync issue');
        console.log('📅 Current time:', new Date().toISOString());
        console.log('🔑 Private key ID:', serviceAccount.private_key_id);
        
        // Try time sync again on JWT errors
        if (i < maxRetries - 1) {
          console.log('🔄 Re-checking time sync...');
          await syncSystemTime();
        }
      }
      
      if (i === maxRetries - 1) {
        throw new Error(`Failed to initialize Firebase after ${maxRetries} attempts: ${error.message}`);
      }
      
      // Progressive backoff
      const backoff = Math.min(5000 * (i + 1), 15000);
      console.log(`⏳ Backing off for ${backoff}ms...`);
      await new Promise(resolve => setTimeout(resolve, backoff));
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
     // Exit if Firebase can't be initialized
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

// ============= DAILY DESTINATION REMINDER FUNCTION =============
async function sendDailyDestinationNotifications() {
  const today = new Date().toISOString().split('T')[0];
  console.log(`📅 Sending daily destination reminders for ${today}`);

  try {
    const destinations = await Destination.find({ date: today });
    
    if (!destinations.length) {
      console.log('ℹ️ No destinations found for today');
      return;
    }

    const userIds = [...new Set(destinations.map(d => d.userId))];

    for (const userId of userIds) {
      try {
        const dest = destinations.find(d => d.userId === userId);
        
        if (!dest) continue;

        const messagingResult = await safeFirestoreOperation(async () => {
          const message = {
            notification: {
              title: 'Tracking Reminder',
              body: 'You have a destination assigned for today,Please open the app and start tracking your journey.'
            },
            data: {
              action: 'destination_reminder',
              latitude: dest.latitude.toString(),
              longitude: dest.longitude.toString(),
              date: dest.date
            },
            topic: `user_${userId}`  // Using user_{userId} as specified
          };
          
          return await admin.messaging().send(message);
        });

        console.log(`✅ Reminder sent to user_${userId}:`, messagingResult);
        
      } catch (err) {
        console.error(`❌ Error sending reminder to user ${userId}:`, err.message);
      }
    }
    
  } catch (err) {
    console.error('❌ Error in daily reminders:', err);
  }
}

// MongoDB connection
mongoose.connect('mongodb+srv://covailabs1:dpBIwF4ZZcJQkgjA@cluster0.jr1ju8f.mongodb.net/trainer_track?retryWrites=true&w=majority&appName=Cluster0', {
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
app.post('/api/notify-proximity', verifyToken, async (req, res) => {
  try {
    const { userId, userName,  distanceToDestination, timestamp,} = req.body;

    // Validate required fields
    if (!userId ||  !distanceToDestination || !timestamp) {
      return res.status(400).json({ message: 'userId,, distanceToDestination, and timestamp are required' });
    }

    // Send FCM notification with retry logic
    const messagingResult = await safeFirestoreOperation(async () => {
      const message = {
        notification: {
          title: 'User Approaching Destination',
          body: `${userName} is within ${distanceToDestination.toFixed(1)} meters of their destination.`,
        },
        data: {
          userName: userName || userId,
          distanceToDestination: distanceToDestination.toString(),
          timestamp: timestamp.toString(),
          action: 'proximity_alert',
        },
        topic: 'admin_notifications',
      };

      return await admin.messaging().send(message);
    });

    res.status(200).json({ message: 'Proximity notification sent successfully', messageId: messagingResult });
  } catch (err) {
    console.error('❌ Error sending proximity notification:', err.stack);
    if (err.code && err.code.startsWith('messaging/')) {
      console.error('🔥 Firebase Messaging Error Details:');
      console.error('Error code:', err.code);
      console.error('Error details:', err.details);
    }
    res.status(500).json({ message: 'Server error', error: err.message, errorCode: err.code });
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
    const { userId, latitude, longitude, date } = req.body;

    if (!userId || !latitude || !longitude || !date) {
      return res.status(400).json({ message: 'userId, latitude, longitude, and date are required' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Ensure date is in the correct format (e.g., YYYY-MM-DD)
    const formattedDate = new Date(date).toISOString().split('T')[0];
    if (!formattedDate) {
      return res.status(400).json({ message: 'Invalid date format' });
    }

    const destination = await Destination.findOneAndUpdate(
      { userId, date: formattedDate }, // Match both userId and date
      { latitude, longitude, date: formattedDate },
      { new: true, upsert: true }
    );

    if (!destination) {
      throw new Error('Failed to create or update destination');
    }

    // Send notification with Firebase retry logic
    await safeFirestoreOperation(async () => {
      const adminMessage = {
        notification: {
          title: 'Destination assigned',
          body: `You have been assigned a new destination for ${formattedDate}`
        },
        data: {
          action: 'destination_assigned',
          latitude: latitude.toString(),
          longitude: longitude.toString(),
          date: formattedDate
        },
        topic: `destination_${userId}`
      };

      const messagingResult = await admin.messaging().send(adminMessage);
      console.log('✅ Destination notification sent successfully:', messagingResult);
      return messagingResult;
    });

    const message = destination.isNew ? 'Destination assigned' : 'Destination updated';
    res.status(201).json({ message, destination: { userId, latitude, longitude, date: formattedDate } });
  } catch (err) {
    console.error('Assign destination error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
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
    try {
      await startFirebase();
      console.log('✅ Firebase initialized successfully');
    } catch (error) {
      console.error('💥 Firebase initialization failed:', error.message);
      console.log('⚠️  Starting server WITHOUT Firebase - some features will be disabled');
      
      // Set a flag to disable Firebase-dependent features
      global.FIREBASE_DISABLED = true;
      
      // Still start the server for other functionality
      console.log('🔄 Server will continue without Firebase...');
    }
    
    // Schedule daily reminder at 8 AM (using server timezone)
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const dailyJob = new CronJob('0 0 8 * * *', async () => {
      await sendDailyDestinationNotifications();
    }, null, true, timezone);
    
    console.log('⏰ Daily destination reminder scheduled at 8 AM every day');
    
    // Start the Express server
    app.listen(port, () => {
      console.log(`🚀 Server running on port ${port}`);
      console.log('Server time:', new Date().toISOString());



      console.log('🔥 Firebase Admin SDK ready with error recovery');
    });
  } catch (error) {
    console.error('💥 Failed to start server:', error);
    process.exit(1);
  }
}
async function safeFirebaseOperation(operation, fallbackResponse = null) {
  if (global.FIREBASE_DISABLED) {
    console.warn('⚠️  Firebase operation skipped - Firebase is disabled');
    return fallbackResponse;
  }
  
  try {
    return await withFirebaseRetry(operation);
  } catch (error) {
    console.error('🚨 Firebase operation failed completely:', error.message);
    
    // If it's a critical JWT error, disable Firebase temporarily
    if (error.message.includes('invalid_grant') || 
        error.message.includes('Invalid JWT') ||
        error.message.includes('credential')) {
      console.warn('🚫 Temporarily disabling Firebase due to auth errors');
      global.FIREBASE_DISABLED = true;
      
      // Try to re-enable after 5 minutes
      setTimeout(() => {
        console.log('🔄 Attempting to re-enable Firebase...');
        global.FIREBASE_DISABLED = false;
        initializeFirebaseWithRetry().catch(err => {
          console.error('💥 Failed to re-initialize Firebase:', err.message);
          global.FIREBASE_DISABLED = true;
        });
      }, 5 * 60 * 1000); // 5 minutes
    }
    
    return fallbackResponse;
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