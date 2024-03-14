const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt=require('bcryptjs')
const jwt=require('jsonwebtoken')
const User=require('./Model/userSchema')
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cookieParser());
const corsOptions = {
  origin: 'https://authfront-six.vercel.app',
  credentials: true
};

app.use(cors(corsOptions));


mongoose.connect('mongodb+srv://vikram:vikramnaik@cluster0.dt8oe9s.mongodb.net/auth-sysytem?retryWrites=true&w=majority&appName=Cluster0');

// Define MongoDB Schema and Models for Users

// Add User Registration Route

// Add User Login Route

// Add Private Route
app.post('/register', async (req, res) => {
    // Extract username and password from the request body
    const { username, password } = req.body;
  
    try {
      // Check if the user already exists
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
      }
  
      // Hash the password using bcrypt
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Create a new user in the database
      const newUser = new User({ username, password: hashedPassword });
      await newUser.save();
  
      return res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });
  

  app.post('/login', async (req, res) => {
    // Extract username and password from the request body
    const { username, password } = req.body;
  
    try {
      // Check if the user exists
      const user = await User.findOne({ username });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      // Verify the password using bcrypt
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Invalid password' });
      }
  
      // Generate a JWT token for authentication
      const token = jwt.sign({ userId: user._id ,username:username}, 'secret-key', { expiresIn: '1h' });
  
      res.cookie("token",token)

      res.json({ message: 'Login successful',token:token });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });
 
  app.post('/logout', (req, res) => {
    // Clear the token from cookies
    res.clearCookie('token')
    res.json({ message: 'Logged out successfully' });
  });
  
  const verifyToken = (req, res, next) => {
    // Extract the token from the request header
    let token = req.cookies.token
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized - No token provided' });
    }
  
    try {
      // Verify the token
      const decodedToken = jwt.verify(token, 'secret-key');
      req.userId = decodedToken.userId;
      req.username = decodedToken.username;
      next();
    } catch (error) {
      console.error(error);
      res.status(401).json({ message: 'Unauthorized - Invalid token' });
    }
  };
  
  app.get('/private', verifyToken,(req, res) => {
    // Private route logic
      res.json(req.username);
  });
  

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
