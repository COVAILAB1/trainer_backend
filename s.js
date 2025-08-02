const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const app = express();
const port = 3000;
const secretKey = 'tamil'; // Replace with a secure key in production

app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/trainer_track2', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('Connected to MongoDB')).catch(err => console.error('MongoDB connection error:', err));

// Updated User Schema to match Flutter app expectations
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phoneNumber: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Destination Schema
const destinationSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  latitude: { type: Number, required: true },
  longitude: { type: Number, required: true },
  address: { type: String },
  assignedAt: { type: Date, default: Date.now },
});
const Destination = mongoose.model('Destination', destinationSchema);

// Location Schema
const locationSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  latitude: { type: Number, required: true },
  longitude: { type: Number, required: true },
  speed: { type: Number, default: 0 },
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
  createdAt: { type: Date, default: Date.now }
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

// Admin middleware
const requireAdmin = (req, res, next) => {
  if (!req.isAdmin) {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('Login attempt:', { username });
  
  try {
    const user = await User.findOne({ username });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin }, 
      secretKey, 
      { expiresIn: '24h' }
    );
    
    res.json({ 
      userId: user._id, 
      token,
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        phoneNumber: user.phoneNumber,
        username: user.username,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all users (admin only)
app.get('/users', verifyToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password'); // Exclude password from response
    res.json(users);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add user (admin only)
app.post('/users', verifyToken, requireAdmin, async (req, res) => {
  try {
    const { fullName, email, phoneNumber, username, password, isAdmin } = req.body;
    
    // Validate required fields
    if (!fullName || !email || !phoneNumber || !username || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ username }, { email }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        message: 'User with this username or email already exists' 
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ 
      fullName,
      email,
      phoneNumber,
      username, 
      password: hashedPassword,
      isAdmin: isAdmin || false
    });
    
    await user.save();
    
    // Return user without password
    const userResponse = user.toObject();
    delete userResponse.password;
    
    res.status(201).json({ 
      message: 'User created successfully',
      user: userResponse
    });
  } catch (err) {
    console.error('Add user error:', err);
    if (err.code === 11000) {
      res.status(400).json({ message: 'Username or email already exists' });
    } else {
      res.status(500).json({ message: 'Server error' });
    }
  }
});

// Update user (admin only)
app.put('/users/:userId', verifyToken, requireAdmin, async (req, res) => {
  try {
    const { fullName, email, phoneNumber, username, password, isAdmin } = req.body;
    
    const updateData = { 
      fullName,
      email,
      phoneNumber,
      username,
      isAdmin,
      updatedAt: new Date()
    };
    
    // Only update password if provided
    if (password && password.trim() !== '') {
      updateData.password = await bcrypt.hash(password, 10);
    }
    
    // Remove undefined fields
    Object.keys(updateData).forEach(key => {
      if (updateData[key] === undefined) {
        delete updateData[key];
      }
    });
    
    const updatedUser = await User.findByIdAndUpdate(
      req.params.userId, 
      updateData,
      { new: true, runValidators: true }
    ).select('-password');
    
    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({ 
      message: 'User updated successfully',
      user: updatedUser
    });
  } catch (err) {
    console.error('Update user error:', err);
    if (err.code === 11000) {
      res.status(400).json({ message: 'Username or email already exists' });
    } else {
      res.status(500).json({ message: 'Server error' });
    }
  }
});

// Delete user (admin only)
app.delete('/users/:userId', verifyToken, requireAdmin, async (req, res) => {
  try {
    const deletedUser = await User.findByIdAndDelete(req.params.userId);
    
    if (!deletedUser) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Also clean up related data
    await Destination.deleteMany({ userId: req.params.userId });
    await Location.deleteMany({ userId: req.params.userId });
    await History.deleteMany({ userId: req.params.userId });
    
    res.json({ message: 'User and related data deleted successfully' });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Assign destination (admin only)
app.post('/destination', verifyToken, requireAdmin, async (req, res) => {
  try {
    const { userId, latitude, longitude, address } = req.body;
    
    if (!userId || !latitude || !longitude) {
      return res.status(400).json({ message: 'UserId, latitude, and longitude are required' });
    }
    
    // Remove existing destination for this user
    await Destination.findOneAndDelete({ userId });
    
    const destination = new Destination({ 
      userId, 
      latitude, 
      longitude,
      address: address || ''
    });
    
    await destination.save();
    res.status(201).json({ 
      message: 'Destination assigned successfully',
      destination
    });
  } catch (err) {
    console.error('Assign destination error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user destination
app.get('/destination/:userId', verifyToken, async (req, res) => {
  try {
    const destination = await Destination.findOne({ userId: req.params.userId });
    if (!destination) {
      return res.status(404).json({ message: 'No destination found' });
    }
    res.json(destination);
  } catch (err) {
    console.error('Get destination error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user tracking data (enhanced to match Flutter expectations)
app.get('/tracking/:userId', verifyToken, async (req, res) => {
  try {
    // Get current location
    const currentLocation = await Location.findOne({ userId: req.params.userId })
      .sort({ timestamp: -1 })
      .limit(1);
    
    // Get destination
    const destination = await Destination.findOne({ userId: req.params.userId });
    
    // Get path (recent locations for route)
    const path = await Location.find({ userId: req.params.userId })
      .sort({ timestamp: -1 })
      .limit(50); // Last 50 locations
    
    let eta = 'N/A';
    let distance = 'N/A';
    
    // Calculate distance and ETA if both current location and destination exist
    if (currentLocation && destination) {
      const distanceKm = calculateDistanceBetweenPoints(
        currentLocation.latitude,
        currentLocation.longitude,
        destination.latitude,
        destination.longitude
      );
      distance = distanceKm.toFixed(2);
      
      // Simple ETA calculation (assuming average speed of 50 km/h)
      const avgSpeed = 50; // km/h
      const etaHours = distanceKm / avgSpeed;
      const etaMinutes = Math.round(etaHours * 60);
      eta = `${etaMinutes} minutes`;
    }
    
    res.json({
      currentLocation: currentLocation || {},
      destination: destination || null,
      path: path.reverse(), // Reverse to get chronological order
      eta,
      distance
    });
  } catch (err) {
    console.error('Get tracking error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user history
app.get('/history/:userId', verifyToken, async (req, res) => {
  try {
    const history = await History.find({ userId: req.params.userId })
      .sort({ createdAt: -1 });
    res.json(history);
  } catch (err) {
    console.error('Get history error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Send location data
app.post('/location', verifyToken, async (req, res) => {
  try {
    const { latitude, longitude, speed } = req.body;
    
    if (!latitude || !longitude) {
      return res.status(400).json({ message: 'Latitude and longitude are required' });
    }
    
    const location = new Location({ 
      userId: req.userId, // From JWT token
      latitude, 
      longitude, 
      speed: speed || 0
    });
    
    await location.save();
    
    // Optional: Create history entry for completed trips
    // This is a simplified version - you might want more sophisticated trip detection
    const recentLocations = await Location.find({ userId: req.userId })
      .sort({ timestamp: -1 })
      .limit(100);
    
    if (recentLocations.length >= 10) { // Minimum points for a trip
      const existingHistoryToday = await History.findOne({
        userId: req.userId,
        date: new Date().toISOString().split('T')[0]
      });
      
      if (!existingHistoryToday) {
        const distance = calculateDistance(recentLocations.reverse());
        const timeTaken = calculateTimeTaken(recentLocations);
        
        const history = new History({
          userId: req.userId,
          date: new Date().toISOString().split('T')[0],
          distance: parseFloat(distance),
          timeTaken,
          path: recentLocations.map(loc => ({ 
            latitude: loc.latitude, 
            longitude: loc.longitude,
            timestamp: loc.timestamp
          })),
        });
        
        await history.save();
      }
    }
    
    res.status(201).json({ message: 'Location saved successfully' });
  } catch (err) {
    console.error('Save location error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Helper function to calculate distance between two points
function calculateDistanceBetweenPoints(lat1, lon1, lat2, lon2) {
  const R = 6371; // Earth radius in kilometers
  const φ1 = lat1 * Math.PI / 180;
  const φ2 = lat2 * Math.PI / 180;
  const Δφ = (lat2 - lat1) * Math.PI / 180;
  const Δλ = (lon2 - lon1) * Math.PI / 180;

  const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
            Math.cos(φ1) * Math.cos(φ2) *
            Math.sin(Δλ/2) * Math.sin(Δλ/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  
  return R * c;
}

// Helper function to calculate distance along a path (Haversine formula)
function calculateDistance(locations) {
  let totalDistance = 0;
  for (let i = 1; i < locations.length; i++) {
    const distance = calculateDistanceBetweenPoints(
      locations[i-1].latitude,
      locations[i-1].longitude,
      locations[i].latitude,
      locations[i].longitude
    );
    totalDistance += distance;
  }
  return totalDistance.toFixed(2);
}

// Helper function to calculate time taken
function calculateTimeTaken(locations) {
  if (locations.length < 2) return '0 minutes';
  
  const start = new Date(locations[0].timestamp);
  const end = new Date(locations[locations.length - 1].timestamp);
  const diff = (end - start) / 1000 / 60; // Convert to minutes
  
  if (diff < 60) {
    return `${Math.round(diff)} minutes`;
  } else {
    const hours = Math.floor(diff / 60);
    const minutes = Math.round(diff % 60);
    return `${hours}h ${minutes}m`;
  }
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

// Handle 404 - Use a proper catch-all route
app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`Health check available at http://localhost:${port}/health`);
});