const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

const port = process.env.PORT || 3000;
const secretKey = process.env.JWT_SECRET || 'tamil';

app.use(cors());
app.use(express.json());

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

// Location Schema - for live tracking (one record per user)
const locationSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
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
  path: [{ latitude: Number, longitude: Number, timestamp: Date }],
  startLatitude: { type: Number },
  startLongitude: { type: Number },
});
historySchema.index({ userId: 1, date: 1 }, { unique: true });
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

// Socket.IO authentication middleware
const authenticateSocket = (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error'));
  }
  
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return next(new Error('Authentication error'));
    }
    socket.userId = decoded.userId;
    socket.isAdmin = decoded.isAdmin;
    next();
  });
};

io.use(authenticateSocket);

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log(`User connected: ${socket.userId}`);
  
  // Join user to their room for real-time updates
  socket.join(`user_${socket.userId}`);
  
  if (socket.isAdmin) {
    socket.join('admin_room');
  }

  // Handle location updates from mobile app
  socket.on('location', async (data) => {
    try {
      const { latitude, longitude, speed, timestamp, startLatitude, startLongitude, isStartLocation, appStatus } = data;
      const userId = socket.userId;
      
      console.log('Socket location request:', { userId, ...data });
      
      if (!latitude || !longitude) {
        socket.emit('locationError', { message: 'latitude and longitude are required' });
        return;
      }
      
      const user = await User.findById(userId);
      if (!user) {
        socket.emit('locationError', { message: 'User not found' });
        return;
      }

      const locationTimestamp = timestamp ? new Date(timestamp) : new Date();
      const date = locationTimestamp.toISOString().split('T')[0];

      // 1. Update current location for live tracking (upsert instead of delete)
      await Location.findOneAndUpdate(
        { userId },
        {
          userId,
          latitude,
          longitude,
          speed: speed ?? 0.0,
          appStatus: appStatus || 'foreground',
          timestamp: locationTimestamp,
        },
        { upsert: true, new: true }
      );

      // 2. Update history with all location points
      let historyRecord = await History.findOne({ userId, date });
      
      if (!historyRecord) {
        // Create new history record
        historyRecord = new History({
          userId,
          date,
          distance: 0,
          timeTaken: '0.00 minutes',
          path: [],
        });
        
        // Set start location if provided or use first location
        if (isStartLocation && startLatitude != null && startLongitude != null) {
          historyRecord.startLatitude = startLatitude;
          historyRecord.startLongitude = startLongitude;
        } else {
          historyRecord.startLatitude = latitude;
          historyRecord.startLongitude = longitude;
        }
      }

      // Add current point to path
      historyRecord.path.push({
        latitude,
        longitude,
        timestamp: locationTimestamp
      });

      // Update start location if explicitly marked as start
      if (isStartLocation && startLatitude != null && startLongitude != null) {
        historyRecord.startLatitude = startLatitude;
        historyRecord.startLongitude = startLongitude;
      }

      // Calculate distance and time
      if (historyRecord.path.length > 1) {
        historyRecord.distance = calculateDistance(historyRecord.path);
        historyRecord.timeTaken = calculateTimeTaken(historyRecord.path);
      }

      await historyRecord.save();

      // 3. Prepare location update data
      const locationUpdate = {
        userId,
        latitude,
        longitude,
        speed: speed ?? 0.0,
        appStatus: appStatus || 'foreground',
        timestamp: locationTimestamp,
        distance: historyRecord.distance,
        timeTaken: historyRecord.timeTaken,
        totalPoints: historyRecord.path.length
      };

      // 4. Emit confirmations and updates
      // Confirm to sender
      socket.emit('locationSaved', {
        message: 'Location saved',
        distance: historyRecord.distance,
        timeTaken: historyRecord.timeTaken,
        totalPoints: historyRecord.path.length
      });

      // Emit to admin dashboard
      socket.to('admin_room').emit('userLocationUpdate', locationUpdate);
      
      // Emit to all users in same room (if needed for group tracking)
      socket.to(`user_${userId}`).emit('locationUpdate', locationUpdate);

    } catch (err) {
      console.error('Socket location error:', err);
      socket.emit('locationError', { message: 'Server error processing location' });
    }
  });

  // Handle tracking start from mobile app
  socket.on('trackingStart', async (data) => {
    try {
      const { latitude, longitude } = data;
      const userId = socket.userId;
      const date = new Date().toISOString().split('T')[0];

      await History.findOneAndUpdate(
        { userId, date },
        {
          userId,
          date,
          startLatitude: latitude,
          startLongitude: longitude,
          distance: 0,
          timeTaken: '0.00 minutes',
          path: [{
            latitude,
            longitude,
            timestamp: new Date()
          }],
        },
        { upsert: true, new: true }
      );

      socket.emit('trackingStarted', { message: 'Tracking started', date });
      socket.to('admin_room').emit('userTrackingStarted', { userId, latitude, longitude, date });

    } catch (err) {
      console.error('Socket tracking start error:', err);
      socket.emit('trackingError', { message: 'Error starting tracking' });
    }
  });

  // Handle tracking end from mobile app
  socket.on('trackingEnd', async () => {
    try {
      const userId = socket.userId;
      
      socket.emit('trackingEnded', { message: 'Tracking ended' });
      socket.to('admin_room').emit('userTrackingEnded', { userId });

    } catch (err) {
      console.error('Socket tracking end error:', err);
      socket.emit('trackingError', { message: 'Error ending tracking' });
    }
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.userId}`);
  });
});

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

// Assign destination (admin only)
app.post('/destination', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  try {
    const { userId, latitude, longitude, date } = req.body;
    if (!userId || !latitude || !longitude || !date) {
      return res.status(400).json({ message: 'userId, latitude, longitude, and date are required' });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ message: 'Invalid date format. Use YYYY-MM-DD' });
    }
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    await Destination.findOneAndDelete({ userId, date });
    const destination = new Destination({ userId, latitude, longitude, date });
    await destination.save();
    res.status(201).json({ message: 'Destination assigned' });
  } catch (err) {
    console.error('Assign destination error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user destination
app.get('/destination/:userId', verifyToken, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const destination = await Destination.findOne({ userId: req.params.userId, date: today });
    if (!destination) return res.status(404).json({ message: 'No destination found for today' });
    res.json({ userId: destination.userId, latitude: destination.latitude, longitude: destination.longitude, date: destination.date });
  } catch (err) {
    console.error('Get destination error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete destination (admin only)
app.delete('/destination/:userId', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  try {
    const today = new Date().toISOString().split('T')[0];
    const destination = await Destination.findOneAndDelete({ userId: req.params.userId, date: today });
    if (!destination) {
      return res.status(404).json({ message: 'No destination found for today' });
    }
    res.json({ message: 'Destination deleted' });
  } catch (err) {
    console.error('Delete destination error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get today's destinations (admin only)
app.get('/destinations/today', verifyToken, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Admin access required' });
  try {
    const { date } = req.query;
    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ message: 'Valid date parameter (YYYY-MM-DD) is required' });
    }
    const destinations = await Destination.find({ date });
    res.json(destinations.map(dest => ({
      userId: dest.userId,
      latitude: dest.latitude,
      longitude: dest.longitude,
      date: dest.date,
    })));
  } catch (err) {
    console.error('Get today\'s destinations error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user tracking data
app.get('/tracking/:userId', verifyToken, async (req, res) => {
  try {
    const location = await Location.findOne({ userId: req.params.userId });
    if (!location) return res.status(404).json({ message: 'No tracking data found' });
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    console.log('Tracking data:', location)
    res.json({
      userId: location.userId,
      latitude: location.latitude,
      longitude: location.longitude,
      speed: location.speed ?? 0.0,
      appStatus: location.timestamp >= fiveMinutesAgo ? location.appStatus : 'offline',
      isSendingLocation: location.timestamp >= fiveMinutesAgo,
      timestamp: location.timestamp,
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
    const locations = await Location.find({});
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

server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});