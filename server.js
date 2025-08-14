const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const admin = require('firebase-admin');
const { CronJob } = require('cron');
require('dotenv').config();
const axios = require('axios');
const { initializeApp, applicationDefault, getApp } = require('firebase-admin/app');
const { getMessaging } = require('firebase-admin/messaging');
const keepAliveUrl = 'https://trainer-backend-soj9.onrender.com/ping';
const app = express();
app.use(cors());
app.use(express.json());
const port = process.env.PORT || 3000;
const secretKey = process.env.JWT_SECRET || 'tamil';
const projectId = process.env.GOOGLE_CLOUD_PROJECT || 'trainertrack-e6238';

let initTime = Date.now();
global.FIREBASE_DISABLED = false;

async function syncSystemTime(maxRetries = 3) {
  const debugPrefix = `[${new Date().toISOString()}] [SyncSystemTime]`;
  const timeApis = [
    'http://worldtimeapi.org/api/timezone/Etc/UTC',
    'https://time.google.com',
    'http://api.timezonedb.com/v2.1/get-time?key=92A1NWPV4QG5&format=json&by=zone&zone=Etc/UTC'
  ];

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    for (const api of timeApis) {
      try {
        console.log(`${debugPrefix} Attempt ${attempt}/${maxRetries} with ${api}`);
        const response = await fetch(api);
        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }
        const timeData = await response.json();
        const correctTime = new Date(timeData.datetime || timeData.utc_datetime);
        const systemTime = new Date();
        const timeDiff = Math.abs(correctTime.getTime() - systemTime.getTime());
        console.log(`${debugPrefix} Time sync successful: difference=${timeDiff}ms, correctTime=${correctTime}, systemTime=${systemTime}`);
        if (timeDiff > 30000) {
          console.warn(`${debugPrefix} Significant time drift detected: ${timeDiff}ms`);
        }
        return { timeDiff, correctTime, systemTime };
      } catch (error) {
        console.error(`${debugPrefix} Time sync failed with ${api}: ${error.message}, stack: ${error.stack}`);
        if (attempt === maxRetries && api === timeApis[timeApis.length - 1]) {
          console.error(`${debugPrefix} All time sync attempts failed`);
          return null;
        }
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
      }
    }
  }
}

async function initializeFirebaseWithRetry(maxRetries = 3) {
  const debugPrefix = `[${new Date().toISOString()}] [InitializeFirebase]`;
  console.log(`${debugPrefix} Starting Firebase initialization with ADC`);
  await syncSystemTime();
  for (let i = 0; i < maxRetries; i++) {
    try {
      console.log(`${debugPrefix} Attempt ${i + 1}/${maxRetries} to initialize Firebase`);
      admin.apps.forEach(app => {
        console.log(`${debugPrefix} Deleting existing Firebase app: ${app.name}`);
        app.delete();
      });
      const defaultApp = initializeApp({
        credential: applicationDefault(),
        projectId: projectId
      });
      console.log(`${debugPrefix} Fetching Firebase access token`);
      const token = await Promise.race([
        defaultApp.options.credential.getAccessToken(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Token fetch timeout')), 10000))
      ]);
      console.log(`${debugPrefix} Firebase Admin initialized successfully for app ${defaultApp.name}, token: ${token.access_token.substring(0, 10)}...`);
      initTime = Date.now();
      global.FIREBASE_DISABLED = false;
      return true;
    } catch (error) {
      console.error(`${debugPrefix} Firebase init attempt ${i + 1} failed: ${error.message}, stack: ${error.stack}`);
      if (error.message.includes('invalid_grant')) {
        console.warn(`${debugPrefix} Invalid JWT Signature detected, check GOOGLE_APPLICATION_CREDENTIALS and system time`);
        console.log(`${debugPrefix} Environment: GOOGLE_CLOUD_PROJECT=${process.env.GOOGLE_CLOUD_PROJECT}, GOOGLE_APPLICATION_CREDENTIALS=${process.env.GOOGLE_APPLICATION_CREDENTIALS}`);
      }
      if (i === maxRetries - 1) {
        console.warn(`${debugPrefix} Disabling Firebase due to repeated failures`);
        global.FIREBASE_DISABLED = true;
        console.error(`${debugPrefix} CRITICAL: Firebase initialization failed after ${maxRetries} attempts`);
        try {
          await axios.post('https://your-logging-service.com/alert', {
            message: 'Firebase initialization failed',
            error: error.message,
            stack: error.stack,
            timestamp: new Date().toISOString()
          });
        } catch (alertError) {
          console.error(`${debugPrefix} Failed to send alert: ${alertError.message}`);
        }
        return false;
      }
      console.log(`${debugPrefix} Waiting ${2000 * (i + 1)}ms before retry`);
      await new Promise(resolve => setTimeout(resolve, 2000 * (i + 1)));
    }
  }
}

async function ensureFreshFirebaseToken() {
  const debugPrefix = `[${new Date().toISOString()}] [EnsureFreshFirebaseToken]`;
  if (global.FIREBASE_DISABLED) {
    console.warn(`${debugPrefix} Skipped - Firebase is disabled`);
    return false;
  }
  try {
    console.log(`${debugPrefix} Attempting to refresh Firebase token`);
    const defaultApp = getApp();
    await defaultApp.options.credential.getAccessToken(true);
    console.log(`${debugPrefix} Token refreshed successfully`);
    return true;
  } catch (error) {
    console.error(`${debugPrefix} Token refresh failed: ${error.message}, stack: ${error.stack}`);
    global.FIREBASE_DISABLED = true;
    return false;
  }
}

async function withFirebaseRetry(operation, maxRetries = 3) {
  const debugPrefix = `[${new Date().toISOString()}] [WithFirebaseRetry]`;
  if (global.FIREBASE_DISABLED) {
    console.warn(`${debugPrefix} Firebase operation skipped - Firebase is disabled`);
    return null;
  }
  for (let i = 0; i < maxRetries; i++) {
    try {
      console.log(`${debugPrefix} Attempt ${i + 1}/${maxRetries} for Firebase operation`);
      const result = await operation();
      console.log(`${debugPrefix} Firebase operation successful`);
      return result;
    } catch (error) {
      console.error(`${debugPrefix} Operation attempt ${i + 1} failed: ${error.message}, stack: ${error.stack}`);
      if ((error.message.includes('invalid_grant') || error.message.includes('Invalid JWT') || error.message.includes('credential')) && i < maxRetries - 1) {
        console.log(`${debugPrefix} Credential error detected, retrying after reinitialization`);
        await initializeFirebaseWithRetry();
        await new Promise(resolve => setTimeout(resolve, 1000));
        continue;
      }
      throw error;
    }
  }
}

function setupAutomaticTokenRefresh() {
  const debugPrefix = `[${new Date().toISOString()}] [SetupAutomaticTokenRefresh]`;
  console.log(`${debugPrefix} Setting up automatic Firebase token refresh every 20 minutes`);
  setInterval(async () => {
    if (!global.FIREBASE_DISABLED) {
      console.log(`${debugPrefix} Initiating scheduled token refresh`);
      const success = await ensureFreshFirebaseToken();
      console.log(`${debugPrefix} Token refresh ${success ? 'successful' : 'skipped'}`);
    } else {
      console.warn(`${debugPrefix} Token refresh skipped - Firebase is disabled`);
    }
  }, 20 * 60 * 1000);
}

async function startFirebase() {
  const debugPrefix = `[${new Date().toISOString()}] [StartFirebase]`;
  console.log(`${debugPrefix} Starting Firebase initialization process`);
  const success = await initializeFirebaseWithRetry();
  if (success) {
    console.log(`${debugPrefix} Firebase initialized successfully at: ${new Date().toISOString()}`);
    setupAutomaticTokenRefresh();
  } else {
    console.warn(`${debugPrefix} Starting server without Firebase`);
  }
}

process.on('unhandledRejection', async (error) => {
  const debugPrefix = `[${new Date().toISOString()}] [UnhandledRejection]`;
  if (error.message?.includes('invalid_grant')) {
    console.error(`${debugPrefix} JWT signature error detected: ${error.message}, stack: ${error.stack}`);
    console.log(`${debugPrefix} Environment: GOOGLE_CLOUD_PROJECT=${process.env.GOOGLE_CLOUD_PROJECT}, GOOGLE_APPLICATION_CREDENTIALS=${process.env.GOOGLE_APPLICATION_CREDENTIALS}`);
    global.FIREBASE_DISABLED = true;
    await initializeFirebaseWithRetry();
  } else {
    console.error(`${debugPrefix} Unhandled rejection: ${error.message}, stack: ${error.stack}`);
  }
});

async function safeFirestoreOperation(operation) {
  const debugPrefix = `[${new Date().toISOString()}] [SafeFirestoreOperation]`;
  console.log(`${debugPrefix} Initiating Firestore operation`);
  try {
    const result = await withFirebaseRetry(operation);
    console.log(`${debugPrefix} Firestore operation completed successfully`);
    return result;
  } catch (error) {
    console.error(`${debugPrefix} Firestore operation failed: ${error.message}, stack: ${error.stack}`);
    throw error;
  }
}

async function sendDailyDestinationNotifications() {
  const debugPrefix = `[${new Date().toISOString()}] [SendDailyDestinationNotifications]`;
  if (global.FIREBASE_DISABLED) {
    console.warn(`${debugPrefix} Daily notifications skipped - Firebase is disabled`);
    return;
  }
  const today = new Date().toISOString().split('T')[0];
  console.log(`${debugPrefix} Sending daily destination reminders for ${today}`);
  try {
    const destinations = await Destination.find({ date: today });
    if (!destinations.length) {
      console.log(`${debugPrefix} No destinations found for today`);
      return;
    }
    const userIds = [...new Set(destinations.map(d => d.userId))];
    console.log(`${debugPrefix} Found ${userIds.length} unique users with destinations`);
    for (const userId of userIds) {
      const dest = destinations.find(d => d.userId === userId);
      if (!dest) {
        console.warn(`${debugPrefix} No destination found for user ${userId}`);
        continue;
      }
      try {
        console.log(`${debugPrefix} Preparing notification for user_${userId}`);
        const messagingResult = await safeFirestoreOperation(async () => {
          const message = {
            notification: {
              title: 'Tracking Reminder',
              body: 'You have a destination assigned for today, please open the app and start tracking your journey.'
            },
            data: {
              action: 'destination_reminder',
              latitude: dest.latitude.toString(),
              longitude: dest.longitude.toString(),
              date: dest.date
            },
            topic: `user_${userId}`
          };
          console.log(`${debugPrefix} Sending notification to user_${userId}`);
          return await getMessaging().send(message);
        });
        if (messagingResult) {
          console.log(`${debugPrefix} Reminder sent successfully to user_${userId}: ${messagingResult}`);
        }
      } catch (err) {
        console.error(`${debugPrefix} Error sending reminder to user_${userId}: ${err.message}, stack: ${err.stack}`);
      }
    }
  } catch (err) {
    console.error(`${debugPrefix} Error in daily reminders: ${err.message}, stack: ${err.stack}`);
  }
}

mongoose.connect('mongodb+srv://covailabs1:dpBIwF4ZZcJQkgjA@cluster0.jr1ju8f.mongodb.net/trainer_track?retryWrites=true&w=majority&appName=Cluster0')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  number: { type: String, required: true, unique: true },
  isAdmin: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

const destinationSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  latitude: { type: Number, required: true },
  longitude: { type: Number, required: true },
  date: { type: String, required: true },
  assignedAt: { type: Date, default: Date.now }
});
destinationSchema.index({ userId: 1, date: 1 }, { unique: true });
const Destination = mongoose.model('Destination', destinationSchema);

const locationSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  latitude: { type: Number, required: true },
  longitude: { type: Number, required: true },
  speed: { type: Number, default: 0.0 },
  appStatus: { type: String, enum: ['foreground', 'background', 'offline'], default: 'offline' },
  timestamp: { type: Date, default: Date.now }
});
const Location = mongoose.model('Location', locationSchema);

const historySchema = new mongoose.Schema({
  userId: { type: String, required: true },
  date: { type: String, required: true },
  distance: { type: Number, required: true },
  timeTaken: { type: String, required: true },
  path: [{ latitude: Number, longitude: Number }],
  startLatitude: { type: Number },
  startLongitude: { type: Number }
});
const History = mongoose.model('History', historySchema);

const verifyToken = (req, res, next) => {
  const debugPrefix = `[${new Date().toISOString()}] [VerifyToken]`;
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    console.warn(`${debugPrefix} No token provided in request`);
    return res.status(401).json({ message: 'No token provided' });
  }
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      console.error(`${debugPrefix} Invalid token: ${err.message}, stack: ${err.stack}`);
      return res.status(401).json({ message: 'Invalid token' });
    }
    console.log(`${debugPrefix} Token verified successfully for userId: ${decoded.userId}`);
    req.userId = decoded.userId;
    req.isAdmin = decoded.isAdmin;
    next();
  });
};

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});
app.get('/ping', (req, res) => {
  console.log(`[${new Date().toISOString()}] Ping received`);
  res.status(200).send('Alive');
});

setInterval(async () => {
  const debugPrefix = `[${new Date().toISOString()}] [KeepAlive]`;
  try {
    console.log(`${debugPrefix} Sending keep-alive ping`);
    await axios.get(keepAliveUrl);
    console.log(`${debugPrefix} Keep-alive ping successful`);
  } catch (error) {
    console.error(`${debugPrefix} Keep-alive ping failed: ${error.message}, stack: ${error.stack}`);
  }
}, 14 * 60 * 1000);

app.post('/login', async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [Login]`;
  const { username, password } = req.body;
  try {
    console.log(`${debugPrefix} Attempting login for username: ${username}`);
    const user = await User.findOne({ username });
    if (!user) {
      console.warn(`${debugPrefix} User not found: ${username}`);
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      console.warn(`${debugPrefix} Invalid password for username: ${username}`);
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    console.log(`${debugPrefix} Generating JWT for userId: ${user._id}`);
    const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, secretKey, { expiresIn: '1h' });
    console.log(`${debugPrefix} Login successful for username: ${username}`);
    res.json({ userId: user._id, token, isAdmin: user.isAdmin });
  } catch (err) {
    console.error(`${debugPrefix} Login error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/tracking-started', async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [TrackingStarted]`;
  const { userId, timestamp } = req.body;
  try {
    console.log(`${debugPrefix} Processing tracking started for userId: ${userId}`);
    const user = await User.findById(userId, '-password');
    if (!user) {
      console.warn(`${debugPrefix} User not found: ${userId}`);
      return res.status(404).json({ message: 'User not found' });
    }
    const userName = user.name || user.username || 'Unknown User';
    console.log(`${debugPrefix} Sending tracking started notification for user: ${userName}`);
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
      console.log(`${debugPrefix} Sending Firebase message to admin_notifications`);
      return await getMessaging().send(adminMessage);
    });
    if (messagingResult) {
      console.log(`${debugPrefix} Notification sent successfully, messageId: ${messagingResult}`);
      res.status(200).json({
        success: true,
        message: 'Tracking started notification sent',
        user: userName,
        messageId: messagingResult
      });
    } else {
      console.warn(`${debugPrefix} Notification skipped - Firebase disabled`);
      res.status(200).json({
        success: true,
        message: 'Tracking started recorded, notification skipped (Firebase disabled)',
        user: userName
      });
    }
  } catch (err) {
    console.error(`${debugPrefix} Tracking started error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/api/notify-proximity', verifyToken, async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [NotifyProximity]`;
  const { userId, userName, distanceToDestination, timestamp } = req.body;
  if (!userId || !distanceToDestination || !timestamp) {
    console.warn(`${debugPrefix} Missing required fields: userId=${userId}, distanceToDestination=${distanceToDestination}, timestamp=${timestamp}`);
    return res.status(400).json({ message: 'userId, distanceToDestination, and timestamp are required' });
  }
  try {
    console.log(`${debugPrefix} Processing proximity notification for userId: ${userId}, distance: ${distanceToDestination}`);
    const messagingResult = await safeFirestoreOperation(async () => {
      const message = {
        notification: {
          title: 'User Approaching Destination',
          body: `${userName} is within ${distanceToDestination.toFixed(1)} meters of their destination.`
        },
        data: {
          userName: userName || userId,
          distanceToDestination: distanceToDestination.toString(),
          timestamp: timestamp.toString(),
          action: 'proximity_alert'
        },
        topic: 'admin_notifications'
      };
      console.log(`${debugPrefix} Sending proximity notification to admin_notifications`);
      return await getMessaging().send(message);
    });
    if (messagingResult) {
      console.log(`${debugPrefix} Proximity notification sent successfully, messageId: ${messagingResult}`);
      res.status(200).json({ message: 'Proximity notification sent successfully', messageId: messagingResult });
    } else {
      console.warn(`${debugPrefix} Proximity notification skipped - Firebase disabled`);
      res.status(200).json({ message: 'Proximity recorded, notification skipped (Firebase disabled)' });
    }
  } catch (err) {
    console.error(`${debugPrefix} Proximity notification error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/api/tracking-stopped', async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [TrackingStopped]`;
  const { userId, timestamp } = req.body;
  try {
    console.log(`${debugPrefix} Processing tracking stopped for userId: ${userId}`);
    const user = await User.findById(userId, '-password');
    if (!user) {
      console.warn(`${debugPrefix} User not found: ${userId}`);
      return res.status(404).json({ message: 'User not found' });
    }
    const userName = user.name || user.username || 'Unknown User';
    console.log(`${debugPrefix} Sending tracking stopped notification for user: ${userName}`);
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
      console.log(`${debugPrefix} Sending Firebase message to admin_notifications`);
      return await getMessaging().send(adminMessage);
    });
    if (messagingResult) {
      console.log(`${debugPrefix} Notification sent successfully, messageId: ${messagingResult}`);
      res.status(200).json({
        success: true,
        message: 'Tracking stopped notification sent',
        user: userName,
        messageId: messagingResult
      });
    } else {
      console.warn(`${debugPrefix} Notification skipped - Firebase disabled`);
      res.status(200).json({
        success: true,
        message: 'Tracking stopped recorded, notification skipped (Firebase disabled)',
        user: userName
      });
    }
  } catch (err) {
    console.error(`${debugPrefix} Tracking stopped error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/users', verifyToken, async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [GetUsers]`;
  if (!req.isAdmin) {
    console.warn(`${debugPrefix} Admin access required, userId: ${req.userId}`);
    return res.status(403).json({ message: 'Admin access required' });
  }
  try {
    console.log(`${debugPrefix} Fetching all users`);
    const users = await User.find({}, '-password');
    console.log(`${debugPrefix} Retrieved ${users.length} users`);
    res.json(users);
  } catch (err) {
    console.error(`${debugPrefix} Get users error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/users/status', verifyToken, async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [GetUserStatus]`;
  if (!req.isAdmin) {
    console.warn(`${debugPrefix} Admin access required, userId: ${req.userId}`);
    return res.status(403).json({ message: 'Admin access required' });
  }
  try {
    console.log(`${debugPrefix} Fetching user statuses`);
    const users = await User.find({}, '-password');
    const locations = await Location.aggregate([
      { $sort: { userId: 1, timestamp: -1 } },
      {
        $group: {
          _id: '$userId',
          userId: { $first: '$userId' },
          appStatus: { $first: '$appStatus' },
          timestamp: { $first: '$timestamp' }
        }
      }
    ]);
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    console.log(`${debugPrefix} Processing ${users.length} users with ${locations.length} location records`);
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
        isSendingLocation: !!location && location.timestamp >= fiveMinutesAgo
      };
    });
    console.log(`${debugPrefix} Returning ${userStatuses.length} user statuses`);
    res.json(userStatuses);
  } catch (err) {
    console.error(`${debugPrefix} Get user statuses error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/users', verifyToken, async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [CreateUser]`;
  if (!req.isAdmin) {
    console.warn(`${debugPrefix} Admin access required, userId: ${req.userId}`);
    return res.status(403).json({ message: 'Admin access required' });
  }
  try {
    const { username, password, name, email, number } = req.body;
    console.log(`${debugPrefix} Creating user with username: ${username}`);
    if (!username || !password || !name || !email || !number) {
      console.warn(`${debugPrefix} Missing required fields`);
      return res.status(400).json({ message: 'All fields are required' });
    }
    const existingUser = await User.findOne({ $or: [{ username }, { email }, { number }] });
    if (existingUser) {
      console.warn(`${debugPrefix} User already exists: username=${username}, email=${email}, number=${number}`);
      return res.status(400).json({ message: 'Username, email, or number already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword, name, email, number });
    await user.save();
    console.log(`${debugPrefix} User created successfully: ${username}`);
    res.status(201).json({ message: 'User created' });
  } catch (err) {
    console.error(`${debugPrefix} Add user error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/users/:userId', verifyToken, async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [UpdateUser]`;
  if (!req.isAdmin) {
    console.warn(`${debugPrefix} Admin access required, userId: ${req.userId}`);
    return res.status(403).json({ message: 'Admin access required' });
  }
  try {
    const { username, password, name, email, number } = req.body;
    console.log(`${debugPrefix} Updating user: ${req.params.userId}`);
    const updateData = { username, name, email, number };
    if (password) updateData.password = await bcrypt.hash(password, 10);
    const existingUser = await User.findOne({
      $or: [{ username }, { email }, { number }],
      _id: { $ne: req.params.userId }
    });
    if (existingUser) {
      console.warn(`${debugPrefix} Username, email, or number already exists: ${username}, ${email}, ${number}`);
      return res.status(400).json({ message: 'Username, email, or number already exists' });
    }
    const updatedUser = await User.findByIdAndUpdate(req.params.userId, updateData, { new: true });
    if (!updatedUser) {
      console.warn(`${debugPrefix} User not found: ${req.params.userId}`);
      return res.status(404).json({ message: 'User not found' });
    }
    console.log(`${debugPrefix} User updated successfully: ${req.params.userId}`);
    res.json({ message: 'User updated' });
  } catch (err) {
    console.error(`${debugPrefix} Update user error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/users/:userId', verifyToken, async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [DeleteUser]`;
  if (!req.isAdmin) {
    console.warn(`${debugPrefix} Admin access required, userId: ${req.userId}`);
    return res.status(403).json({ message: 'Admin access required' });
  }
  try {
    console.log(`${debugPrefix} Deleting user: ${req.params.userId}`);
    const user = await User.findByIdAndDelete(req.params.userId);
    if (!user) {
      console.warn(`${debugPrefix} User not found: ${req.params.userId}`);
      return res.status(404).json({ message: 'User not found' });
    }
    await Destination.deleteMany({ userId: req.params.userId });
    await Location.deleteMany({ userId: req.params.userId });
    await History.deleteMany({ userId: req.params.userId });
    console.log(`${debugPrefix} User and associated data deleted: ${req.params.userId}`);
    res.json({ message: 'User and associated data deleted' });
  } catch (err) {
    console.error(`${debugPrefix} Delete user error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/destination', verifyToken, async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [AssignDestination]`;
  if (!req.isAdmin) {
    console.warn(`${debugPrefix} Admin access required, userId: ${req.userId}`);
    return res.status(403).json({ message: 'Admin access required' });
  }
  try {
    const { userId, latitude, longitude, date } = req.body;
    console.log(`${debugPrefix} Assigning destination for userId: ${userId}`);
    if (!userId || !latitude || !longitude || !date) {
      console.warn(`${debugPrefix} Missing required fields: userId=${userId}, latitude=${latitude}, longitude=${longitude}, date=${date}`);
      return res.status(400).json({ message: 'userId, latitude, longitude, and date are required' });
    }
    const user = await User.findById(userId);
    if (!user) {
      console.warn(`${debugPrefix} User not found: ${userId}`);
      return res.status(404).json({ message: 'User not found' });
    }
    const formattedDate = new Date(date).toISOString().split('T')[0];
    if (!formattedDate) {
      console.warn(`${debugPrefix} Invalid date format: ${date}`);
      return res.status(400).json({ message: 'Invalid date format' });
    }
    console.log(`${debugPrefix} Updating/inserting destination for date: ${formattedDate}`);
    const destination = await Destination.findOneAndUpdate(
      { userId, date: formattedDate },
      { latitude, longitude, date: formattedDate },
      { new: true, upsert: true }
    );
    console.log(`${debugPrefix} Sending destination notification for userId: ${userId}`);
    const messagingResult = await safeFirestoreOperation(async () => {
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
      console.log(`${debugPrefix} Sending Firebase message to destination_${userId}`);
      return await getMessaging().send(adminMessage);
    });
    const message = destination.isNew ? 'Destination assigned' : 'Destination updated';
    console.log(`${debugPrefix} ${message} for userId: ${userId}, notificationSent: ${!!messagingResult}`);
    res.status(201).json({
      message,
      destination: { userId, latitude, longitude, date: formattedDate },
      notificationSent: !!messagingResult
    });
  } catch (err) {
    console.error(`${debugPrefix} Assign destination error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/destination/:userId', verifyToken, async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [GetDestination]`;
  try {
    console.log(`${debugPrefix} Fetching destination for userId: ${req.params.userId}`);
    const destination = await Destination.findOne({ userId: req.params.userId });
    if (!destination) {
      console.warn(`${debugPrefix} No destination found for userId: ${req.params.userId}`);
      return res.status(404).json({ message: 'No destination found' });
    }
    console.log(`${debugPrefix} Destination found for userId: ${req.params.userId}`);
    res.json({
      userId: destination.userId,
      latitude: destination.latitude,
      longitude: destination.longitude,
      date: destination.date
    });
  } catch (err) {
    console.error(`${debugPrefix} Get destination error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/destination/:userId', verifyToken, async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [DeleteDestination]`;
  if (!req.isAdmin) {
    console.warn(`${debugPrefix} Admin access required, userId: ${req.userId}`);
    return res.status(403).json({ message: 'Admin access required' });
  }
  try {
    console.log(`${debugPrefix} Deleting destination for userId: ${req.params.userId}`);
    const destination = await Destination.findOneAndDelete({ userId: req.params.userId });
    if (!destination) {
      console.warn(`${debugPrefix} No destination found for userId: ${req.params.userId}`);
      return res.status(404).json({ message: 'No destination found' });
    }
    console.log(`${debugPrefix} Destination deleted for userId: ${req.params.userId}`);
    res.json({ message: 'Destination deleted' });
  } catch (err) {
    console.error(`${debugPrefix} Delete destination error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/tracking/:userId', verifyToken, async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [GetTracking]`;
  try {
    console.log(`${debugPrefix} Fetching tracking data for userId: ${req.params.userId}`);
    const locations = await Location.find({ userId: req.params.userId }).sort({ timestamp: -1 }).limit(1);
    if (!locations.length) {
      console.warn(`${debugPrefix} No tracking data found for userId: ${req.params.userId}`);
      return res.status(404).json({ message: 'No tracking data found' });
    }
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    console.log(`${debugPrefix} Tracking data found for userId: ${req.params.userId}`);
    res.json({
      userId: locations[0].userId,
      latitude: locations[0].latitude,
      longitude: locations[0].longitude,
      speed: locations[0].speed ?? 0.0,
      appStatus: locations[0].timestamp >= fiveMinutesAgo ? locations[0].appStatus : 'offline',
      isSendingLocation: locations[0].timestamp >= fiveMinutesAgo,
      timestamp: locations[0].timestamp
    });
  } catch (err) {
    console.error(`${debugPrefix} Get tracking data error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/locations', verifyToken, async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [GetLocations]`;
  if (!req.isAdmin) {
    console.warn(`${debugPrefix} Admin access required, userId: ${req.userId}`);
    return res.status(403).json({ message: 'Admin access required' });
  }
  try {
    console.log(`${debugPrefix} Fetching all locations`);
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
          timestamp: { $first: '$timestamp' }
        }
      }
    ]);
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    console.log(`${debugPrefix} Retrieved ${locations.length} location records`);
    res.json(locations.map(loc => ({
      userId: loc.userId,
      latitude: loc.latitude,
      longitude: loc.longitude,
      speed: loc.speed ?? 0.0,
      appStatus: loc.timestamp >= fiveMinutesAgo ? loc.appStatus : 'offline',
      isSendingLocation: loc.timestamp >= fiveMinutesAgo,
      timestamp: loc.timestamp
    })));
  } catch (err) {
    console.error(`${debugPrefix} Get locations error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/history/:userId', verifyToken, async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [GetHistory]`;
  try {
    console.log(`${debugPrefix} Fetching history for userId: ${req.params.userId}`);
    const history = await History.find({ userId: req.params.userId }).sort({ date: -1 });
    console.log(`${debugPrefix} Retrieved ${history.length} history records for userId: ${req.params.userId}`);
    res.json(history);
  } catch (err) {
    console.error(`${debugPrefix} Get history error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/location', verifyToken, async (req, res) => {
  const debugPrefix = `[${new Date().toISOString()}] [SaveLocation]`;
  try {
    const { userId, latitude, longitude, speed, timestamp, startLatitude, startLongitude, isStartLocation, appStatus } = req.body;
    console.log(`${debugPrefix} Saving location for userId: ${userId}`);
    if (!userId || !latitude || !longitude) {
      console.warn(`${debugPrefix} Missing required fields: userId=${userId}, latitude=${latitude}, longitude=${longitude}`);
      return res.status(400).json({ message: 'userId, latitude, and longitude are required' });
    }
    const user = await User.findById(userId);
    if (!user) {
      console.warn(`${debugPrefix} User not found: ${userId}`);
      return res.status(404).json({ message: 'User not found' });
    }
    const locationData = {
      userId,
      latitude,
      longitude,
      speed: speed ?? 0.0,
      appStatus: appStatus,
      timestamp: timestamp ? new Date(timestamp) : Date.now()
    };
    console.log(`${debugPrefix} Updating/inserting location data`);
    await Location.findOneAndUpdate(
      { userId },
      locationData,
      { upsert: true, new: true }
    );
    const date = new Date(timestamp || Date.now()).toISOString().split('T')[0];
    console.log(`${debugPrefix} Fetching locations for date: ${date}`);
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
      path
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
    console.log(`${debugPrefix} Updating/inserting history data for date: ${date}`);
    await History.findOneAndUpdate(
      { userId, date },
      historyData,
      { upsert: true, new: true }
    );
    console.log(`${debugPrefix} Location saved successfully for userId: ${userId}`);
    res.status(201).json({ message: 'Location saved' });
  } catch (err) {
    console.error(`${debugPrefix} Send location error: ${err.message}, stack: ${err.stack}`);
    res.status(500).json({ message: 'Server error' });
  }
});

function calculateDistance(locations) {
  const debugPrefix = `[${new Date().toISOString()}] [CalculateDistance]`;
  console.log(`${debugPrefix} Calculating distance for ${locations.length} locations`);
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
  const result = Number(totalDistance.toFixed(2));
  console.log(`${debugPrefix} Calculated distance: ${result} km`);
  return result;
}

function calculateTimeTaken(locations) {
  const debugPrefix = `[${new Date().toISOString()}] [CalculateTimeTaken]`;
  if (locations.length < 2) {
    console.log(`${debugPrefix} Less than 2 locations, returning 0.00 minutes`);
    return '0.00 minutes';
  }
  const start = new Date(locations[0].timestamp);
  const end = new Date(locations[locations.length - 1].timestamp);
  const diff = (end - start) / 1000 / 60;
  const result = `${diff.toFixed(2)} minutes`;
  console.log(`${debugPrefix} Calculated time taken: ${result}`);
  return result;
}

async function startServer() {
  const debugPrefix = `[${new Date().toISOString()}] [StartServer]`;
  try {
    console.log(`${debugPrefix} Starting server initialization`);
    await startFirebase();
    console.log(`${debugPrefix} Scheduling daily destination reminders at 8 AM IST`);
    const dailyJob = new CronJob('0 0 8 * * *', async () => {
      console.log(`${debugPrefix} Running scheduled daily destination notifications`);
      await sendDailyDestinationNotifications();
    }, null, true, 'Asia/Kolkata');
    console.log(`${debugPrefix} Daily destination reminder scheduled`);
    app.listen(port, () => {
      console.log(`${debugPrefix} Server running on port ${port}`);
    });
  } catch (error) {
    console.error(`${debugPrefix} Failed to start server: ${error.message}, stack: ${error.stack}`);
    process.exit(1);
  }
}

startServer();

module.exports = {
  safeFirestoreOperation,
  withFirebaseRetry,
  ensureFreshFirebaseToken
};