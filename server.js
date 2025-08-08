const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;
const secretKey = process.env.JWT_SECRET || 'tamil'; // Use environment variable for security

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

// Location Schema
const locationSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  latitude: { type: Number, required: true },
  longitude: { type: Number, required: true },
  speed: { type: Number, default: 0.0 },
  appStatus: { type: String, enum: ['foreground', 'background','offline'], default: 'offline' }, // New field
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

// Get user statuses (admin only) - New endpoint
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
    const { userId, latitude, longitude } = req.body;
    
    if (!userId || !latitude || !longitude) {
      return res.status(400).json({ message: 'userId, latitude, and longitude are required' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Find existing destination and update, or create new one
    const destination = await Destination.findOneAndUpdate(
      { userId },
      { latitude, longitude },
      { new: true, upsert: true }
    );

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
    await Location.deleteMany({ userId });
    const location = new Location({
      userId,
      latitude,
      longitude,
      speed: speed ?? 0.0,
      appStatus: appStatus ,
      timestamp: timestamp ? new Date(timestamp) : Date.now(),
    });
    await location.save();
    const date = new Date(timestamp || Date.now()).toISOString().split('T')[0];
    const locations = await Location.find({ userId, timestamp: { $gte: new Date(date) } }).sort({ timestamp: 1 });
    let path = locations.map(loc => ({ latitude: loc.latitude, longitude: loc.longitude }));
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

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});