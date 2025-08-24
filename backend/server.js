const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Auth routes
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await prisma.user.findUnique({
      where: { email }
    });
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    if (user.isBlocked) {
      return res.status(403).json({ message: 'Account is blocked' });
    }
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Profile routes
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id }
    });
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      isBlocked: user.isBlocked,
      forcedPasswordReset: user.forcedPasswordReset
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/profile', authenticateToken, async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const updateData = {};
    if (username) updateData.username = username;
    if (email) updateData.email = email;
    if (password) updateData.password = bcrypt.hashSync(password, 8);
    
    const user = await prisma.user.update({
      where: { id: req.user.id },
      data: updateData
    });
    
    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin routes
app.get('/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin access required' });
  
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        isBlocked: true,
        forcedPasswordReset: true
      }
    });
    
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/admin/users/:userId', authenticateToken, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin access required' });
  
  const { role, isBlocked, forcedPasswordReset } = req.body;
  try {
    const updateData = {};
    if (role) updateData.role = role;
    if (typeof isBlocked === 'boolean') updateData.isBlocked = isBlocked;
    if (typeof forcedPasswordReset === 'boolean') updateData.forcedPasswordReset = forcedPasswordReset;
    
    const user = await prisma.user.update({
      where: { id: req.params.userId },
      data: updateData
    });
    
    res.json({ message: 'User updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Socket.io for messaging
io.on('connection', (socket) => {
  console.log('New client connected');
  
  socket.on('join', (userId) => {
    socket.join(userId);
  });
  
  socket.on('sendMessage', async ({ senderId, receiverId, content }) => {
    try {
      const message = await prisma.message.create({
        data: {
          senderId,
          receiverId,
          content
        }
      });
      
      io.to(receiverId).emit('newMessage', message);
    } catch (error) {
      console.error('Error saving message:', error);
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});
// ...existing code...

// Registration route
// ...existing code...
app.post('/auth/register', async (req, res) => {
  console.log('Registration request body:', req.body); // Console log added
  const { username, email, password } = req.body;
  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(409).json({ message: 'Email already exists' });
    }
    const hashedPassword = bcrypt.hashSync(password, 8);
    const user = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
        role: 'USER',
        isBlocked: false,
        forcedPasswordReset: false
      }
    });
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error); // Console log added
    res.status(500).json({ message: 'Server error' });
  }
});
// ...existing

// ...existing code...
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));

