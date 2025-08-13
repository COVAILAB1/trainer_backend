const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const admin = require('firebase-admin');
const { CronJob } = require('cron');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
const port = process.env.PORT || 3000;
const secretKey = process.env.JWT_SECRET || 'tamil';

const serviceAccount = {
  "type": "service_account",
  "project_id": "trainertrack-e6238",
  "private_key_id": "a0eb8e373357da5e8e350ec967f41798bcc3caf9",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDjiYuvHX9VDgBu\nlqCow+q2rdX8us/mC507MhEbsQh/B/6EHwtGYxnbyJVJ+z0zkDnOY2KrgRsyfvzq\n4M9BL2cCmWL+qLKxaJLNxHgGzZvCS+5R/sIIoQRNR+yeZwmEPM4ay4tpadxcHNG3\nJbE1H3F405OcZxJ2miSTCMkz3lddeavpDuk71Z428s7gVOdwXRs4vLtQOcXINoQz\nW6R0XhuBbO7XgBkyKvopcDo6eQPtIXCqA/sBME9xHVMHnOP7kaT61F5azsnUCyPb\nYNl5xTZNXDmYsGcwsKm6ptsg2HPzMzwSVtoKTZENRO3UzRilXw/G8n3F6AjgB17b\nHvftEzpbAgMBAAECggEANj+P3xNQTW4GKledPD9hkWZGs3eyo203cmqQa6K8nNTC\nGKvyGzj7bEwZU8cjo0yKi6tkVfF1E4f1MuagYzEzBQqe8Io1+FgvUAG8gBq7PQqv\najsr9bS1+trgDjAQs8dveDH5LgvALvHsChdhdYHmouEGu25Tl5VOjQO2PLiQ6cbq\nYNoUXArrkqpuKcYC3ufRH+gKkfr5eHNx5tHXV/nNSf6/8sEOjq7SxZ4yiaxroXBK\nErwS7fcmEdEX2invNAxOclQwx0H0o+f1mMGqyMOBnnb3dbzQX7FW7ibnS1vSZSSH\nCe9HuLygYQ9tq4GGO2750sPhIgPzxYCEOy4bq77K+QKBgQDyQxLGYxW/rjaSJJm2\nBur4VqEoN/ujeCaqPD5zfnERTekJo8lxlVuVpNrPxXwFIcCaTqFqj15TogQx4aPk\nnG8vhoeKS+Qwy1T7I7loyLKf01slo6uZb1xkTS+M1KqISKrkMUMDBp5f1dRUReZG\nqbFhufF2vh2hO6G20cyTRlXd5QKBgQDwcLaIjnnqd+zeJSjOzEd8+77246hT5m+H\nOMTYlp4ptgNdH+e4Px7EA1SuG8+S6HpBxSQt8X/dz3jqcB0eRapfU1M3YxoMKqpv\nrmBbiGtNBw+UO3cph7HpdMapolMVYWEZwohRw1azS1VKyPaeY/3w3nZBtAjEDo+J\ny+i4A/kzPwKBgHZdNwse1j10zMzSfRdmgd8b1FlmINhZl+qMzKZ5HJ0rx7QiBgYs\nxzZx+UaSYmnPd97slAkQSzHpcss8R2sm01wRCqATPEZq0fZyGeCMTlmwVlQph2nL\n8wQ+ggD41ukHOBeNygPsc+y2+KrEDCJyPmxVARjXAnsIO5arIpzCPKnRAoGAIiB9\naAiA+WyoLCeuERwhkXXR9wz9GVt9vP2rwuot7NGuzIr4wsgCv+ORI11DKyDgKXGn\n3vWGJp+KFAxxtZhBxGH5T8U7LzrnEg74EkXcpQQ5i9qc4UInWHGAuRcXH9PAin14\nB9Ln/W7V3lWD25tpscSBmHXLQLioWvCcSXIW7tUCgYEA3bFNKSXcxkrFz9nPSuPR\nnzwhFe5I2v0qkSr8EHd3K96nXfwzy1i/j5T1WmVZ3z2d2wkQjEmOEE7mq7GbJFIa\nH3kLp1sx/Wd112Y/MWPG+uDSyzcdEijyfFV/HL21FIbkqFieKloIQhMeXHOReGir\nd5fbuCrkwyMs7GgSdljSEo0=\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-fbsvc@trainertrack-e6238.iam.gserviceaccount.com",
  "client_id": "117021301682543078913",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40trainertrack-e6238.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
};

let initTime = Date.now();
global.FIREBASE_DISABLED = false;

async function syncSystemTime() {
  try {
    console.log('🕐 Attempting to sync system time...');
    const response = await fetch('http://worldtimeapi.org/api/timezone/Etc/UTC');
    const timeData = await response.json();
    const correctTime = new Date(timeData.datetime);
    const systemTime = new Date();
    const timeDiff = Math.abs(correctTime.getTime() - systemTime.getTime());
    console.log(`⏰ Time difference: ${timeDiff}ms`);
    if (timeDiff > 30000) {
      console.warn('⚠️ Significant time drift detected!');
    }
    return { timeDiff, correctTime, systemTime };
  } catch (error) {
    console.warn('⚠️ Time sync check failed:', error.message);
    return null;
  }
}

async function initializeFirebaseWithRetry(maxRetries = 3) {
  await syncSystemTime();
  for (let i = 0; i < maxRetries; i++) {
    try {
      admin.apps.forEach(app => app.delete());
      console.log(`🔥 Initializing Firebase (attempt ${i + 1}/${maxRetries})...`);
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
      });
      await Promise.race([
        admin.app().options.credential.getAccessToken(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Token fetch timeout')), 10000))
      ]);
      console.log(`✅ Firebase Admin initialized successfully`);
      initTime = Date.now();
      global.FIREBASE_DISABLED = false;
      return true;
    } catch (error) {
      console.error(`❌ Firebase init attempt ${i + 1} failed: ${error.message}`);
      if (i === maxRetries - 1) {
        console.warn('🚫 Disabling Firebase due to repeated failures');
        global.FIREBASE_DISABLED = true;
        return false;
      }
      await new Promise(resolve => setTimeout(resolve, 2000 * (i + 1)));
    }
  }
}

async function ensureFreshFirebaseToken() {
  if (global.FIREBASE_DISABLED) return false;
  try {
    await admin.app().options.credential.getAccessToken(true);
    return true;
  } catch (error) {
    console.warn('🔄 Token refresh failed:', error.message);
    global.FIREBASE_DISABLED = true;
    return false;
  }
}

async function withFirebaseRetry(operation, maxRetries = 3) {
  if (global.FIREBASE_DISABLED) {
    console.warn('⚠️ Firebase operation skipped - Firebase is disabled');
    return null;
  }
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await operation();
    } catch (error) {
      if ((error.message.includes('invalid_grant') || error.message.includes('Invalid JWT') || error.message.includes('credential')) && i < maxRetries - 1) {
        console.log(`🔄 Retry ${i + 1} after credential error`);
        await initializeFirebaseWithRetry();
        await new Promise(resolve => setTimeout(resolve, 1000));
        continue;
      }
      throw error;
    }
  }
}

function setupAutomaticTokenRefresh() {
  setInterval(async () => {
    if (!global.FIREBASE_DISABLED) {
      console.log('🔄 Refreshing Firebase token...');
      const success = await ensureFreshFirebaseToken();
      console.log(success ? '✅ Token refreshed successfully' : '❌ Token refresh skipped');
    }
  }, 20 * 60 * 1000);
}

async function startFirebase() {
  const success = await initializeFirebaseWithRetry();
  if (success) {
    setupAutomaticTokenRefresh();
    console.log('📊 Firebase initialized at:', new Date().toISOString());
  } else {
    console.warn('⚠️ Starting server without Firebase');
  }
}

process.on('unhandledRejection', async (error) => {
  if (error.message?.includes('invalid_grant')) {
    console.error('🚨 JWT signature error detected:', new Date().toISOString());
    global.FIREBASE_DISABLED = true;
    await initializeFirebaseWithRetry();
  }
});

async function safeFirestoreOperation(operation) {
  return withFirebaseRetry(operation);
}

async function sendDailyDestinationNotifications() {
  if (global.FIREBASE_DISABLED) {
    console.warn('⚠️ Daily notifications skipped - Firebase is disabled');
    return;
  }
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
      const dest = destinations.find(d => d.userId === userId);
      if (!dest) continue;
      try {
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
          return await admin.messaging().send(message);
        });
        if (messagingResult) {
          console.log(`✅ Reminder sent to user_${userId}:`, messagingResult);
        }
      } catch (err) {
        console.error(`❌ Error sending reminder to user ${userId}:`, err.message);
      }
    }
  } catch (err) {
    console.error('❌ Error in daily reminders:', err);
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
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    req.userId = decoded.userId;
    req.isAdmin = decoded.isAdmin;
    next();
  });
};

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
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

app.post('/api/tracking-started', async (req, res) => {
  const { userId, timestamp } = req.body;
  try {
    const user = await User.findById(userId, '-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    const userName = user.name || user.username || 'Unknown User';
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
    if (messagingResult) {
      res.status(200).json({
        success: true,
        message: 'Tracking started notification sent',
        user: userName,
        messageId: messagingResult
      });
    } else {
      res.status(200).json({
        success: true,
        message: 'Tracking started recorded, notification skipped (Firebase disabled)',
        user: userName
      });
    }
  } catch (err) {
    console.error('Tracking started error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/api/notify-proximity', verifyToken, async (req, res) => {
  const { userId, userName, distanceToDestination, timestamp } = req.body;
  if (!userId || !distanceToDestination || !timestamp) {
    return res.status(400).json({ message: 'userId, distanceToDestination, and timestamp are required' });
  }
  try {
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
      return await admin.messaging().send(message);
    });
    if (messagingResult) {
      res.status(200).json({ message: 'Proximity notification sent successfully', messageId: messagingResult });
    } else {
      res.status(200).json({ message: 'Proximity recorded, notification skipped (Firebase disabled)' });
    }
  } catch (err) {
    console.error('Proximity notification error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/api/tracking-stopped', async (req, res) => {
  const { userId, timestamp } = req.body;
  try {
    const user = await User.findById(userId, '-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    const userName = user.name || user.username || 'Unknown User';
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
    if (messagingResult) {
      res.status(200).json({
        success: true,
        message: 'Tracking stopped notification sent',
        user: userName,
        messageId: messagingResult
      });
    } else {
      res.status(200).json({
        success: true,
        message: 'Tracking stopped recorded, notification skipped (Firebase disabled)',
        user: userName
      });
    }
  } catch (err) {
    console.error('Tracking stopped error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

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
          timestamp: { $first: '$timestamp' }
        }
      }
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
        isSendingLocation: !!location && location.timestamp >= fiveMinutesAgo
      };
    });
    res.json(userStatuses);
  } catch (err) {
    console.error('Get user statuses error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/users', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  try {
    const { username, password, name, email, number } = req.body;
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

app.put('/users/:userId', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  try {
    const { username, password, name, email, number } = req.body;
    const updateData = { username, name, email, number };
    if (password) updateData.password = await bcrypt.hash(password, 10);
    const existingUser = await User.findOne({
      $or: [{ username }, { email }, { number }],
      _id: { $ne: req.params.userId }
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

app.post('/destination', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  try {
    const { userId, latitude, longitude, date } = req.body;
    if (!userId || !latitude || !longitude || !date) {
      return res.status(400).json({ message: 'userId, latitude, longitude, and date are required' });
    }
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    const formattedDate = new Date(date).toISOString().split('T')[0];
    if (!formattedDate) return res.status(400).json({ message: 'Invalid date format' });
    const destination = await Destination.findOneAndUpdate(
      { userId, date: formattedDate },
      { latitude, longitude, date: formattedDate },
      { new: true, upsert: true }
    );
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
      return await admin.messaging().send(adminMessage);
    });
    const message = destination.isNew ? 'Destination assigned' : 'Destination updated';
    res.status(201).json({
      message,
      destination: { userId, latitude, longitude, date: formattedDate },
      notificationSent: !!messagingResult
    });
  } catch (err) {
    console.error('Assign destination error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/destination/:userId', verifyToken, async (req, res) => {
  try {
    const destination = await Destination.findOne({ userId: req.params.userId });
    if (!destination) return res.status(404).json({ message: 'No destination found' });
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

app.delete('/destination/:userId', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  try {
    const destination = await Destination.findOneAndDelete({ userId: req.params.userId });
    if (!destination) return res.status(404).json({ message: 'No destination found' });
    res.json({ message: 'Destination deleted' });
  } catch (err) {
    console.error('Delete destination error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/tracking/:userId', verifyToken, async (req, res) => {
  try {
    const locations = await Location.find({ userId: req.params.userId }).sort({ timestamp: -1 }).limit(1);
    if (!locations.length) return res.status(404).json({ message: 'No tracking data found' });
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
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
    console.error('Get tracking data error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

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
          timestamp: { $first: '$timestamp' }
        }
      }
    ]);
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
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
    console.error('Get locations error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/history/:userId', verifyToken, async (req, res) => {
  try {
    const history = await History.find({ userId: req.params.userId }).sort({ date: -1 });
    res.json(history);
  } catch (err) {
    console.error('Get history error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/location', verifyToken, async (req, res) => {
  try {
    const { userId, latitude, longitude, speed, timestamp, startLatitude, startLongitude, isStartLocation, appStatus } = req.body;
    if (!userId || !latitude || !longitude) {
      return res.status(400).json({ message: 'userId, latitude, and longitude are required' });
    }
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    const locationData = {
      userId,
      latitude,
      longitude,
      speed: speed ?? 0.0,
      appStatus: appStatus,
      timestamp: timestamp ? new Date(timestamp) : Date.now()
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

function calculateTimeTaken(locations) {
  if (locations.length < 2) return '0.00 minutes';
  const start = new Date(locations[0].timestamp);
  const end = new Date(locations[locations.length - 1].timestamp);
  const diff = (end - start) / 1000 / 60;
  return `${diff.toFixed(2)} minutes`;
}

async function startServer() {
  try {
    await startFirebase();
    const dailyJob = new CronJob('0 0 8 * * *', async () => {
      await sendDailyDestinationNotifications();
    }, null, true, 'Asia/Kolkata');
    console.log('⏰ Daily destination reminder scheduled at 8 AM IST');
    app.listen(port, () => {
      console.log(`🚀 Server running on port ${port}`);
    });
  } catch (error) {
    console.error('💥 Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

module.exports = {
  safeFirestoreOperation,
  withFirebaseRetry,
  ensureFreshFirebaseToken
};