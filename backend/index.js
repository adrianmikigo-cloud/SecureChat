import express from 'express';
import http from 'http';
import socketIo from 'socket.io';
import cors from 'cors';
import { Sequelize, DataTypes } from 'sequelize';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

app.use(cors());
app.use(express.json());

const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key-change-this';

// Database connection
const sequelize = new Sequelize('secure_chat', 'admin', 'secret123', {
  host: process.env.DB_HOST || 'localhost',
  dialect: 'postgres',
  logging: false
});

// User Model
const User = sequelize.define('User', {
  id: { type: DataTypes.UUID, primaryKey: true, defaultValue: DataTypes.UUIDV4 },
  username: { type: DataTypes.STRING, unique: true, allowNull: false },
  passwordHash: { type: DataTypes.STRING, allowNull: false },
  role: { type: DataTypes.ENUM('admin', 'user'), defaultValue: 'user' },
  publicKey: { type: DataTypes.TEXT }
});

// Message Model
const Message = sequelize.define('Message', {
  id: { type: DataTypes.UUID, primaryKey: true, defaultValue: DataTypes.UUIDV4 },
  senderId: { type: DataTypes.UUID, allowNull: false },
  receiverId: { type: DataTypes.UUID, allowNull: false },
  encryptedContent: { type: DataTypes.TEXT, allowNull: false },
  nonce: { type: DataTypes.STRING },
  timestamp: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
});

// Permission Model
const Permission = sequelize.define('Permission', {
  id: { type: DataTypes.UUID, primaryKey: true, defaultValue: DataTypes.UUIDV4 },
  userId: { type: DataTypes.UUID, allowNull: false },
  allowedUserId: { type: DataTypes.UUID, allowNull: false },
  granted: { type: DataTypes.BOOLEAN, defaultValue: false }
});

// Register endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      username,
      passwordHash: hashedPassword,
      publicKey: crypto.randomBytes(32).toString('hex')
    });

    res.json({ id: user.id, username: user.username });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ where: { username } });

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id, role: user.role }, SECRET_KEY, {
      expiresIn: '24h'
    });

    res.json({ token, userId: user.id, role: user.role });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.userId = decoded.userId;
    req.role = decoded.role;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Get all users (admin only)
app.get('/users', verifyToken, async (req, res) => {
  if (req.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  
  const users = await User.findAll({ attributes: ['id', 'username', 'role'] });
  res.json(users);
});

// Grant permission (admin only)
app.post('/permission', verifyToken, async (req, res) => {
  if (req.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  
  const { userId, allowedUserId } = req.body;
  
  const permission = await Permission.findOrCreate({
    where: { userId, allowedUserId },
    defaults: { granted: true }
  });

  res.json(permission);
});

// Get user permissions
app.get('/my-permissions', verifyToken, async (req, res) => {
  const permissions = await Permission.findAll({
    where: { userId: req.userId, granted: true },
    attributes: ['allowedUserId']
  });
  res.json(permissions.map(p => p.allowedUserId));
});

// Get chat history
app.get('/messages/:userId', verifyToken, async (req, res) => {
  const { userId } = req.params;
  
  const messages = await Message.findAll({
    where: {
      [Sequelize.Op.or]: [
        { senderId: req.userId, receiverId: userId },
        { senderId: userId, receiverId: req.userId }
      ]
    },
    order: [['timestamp', 'ASC']],
    limit: 100
  });

  res.json(messages);
});

// WebSocket events
io.on('connection', (socket) => {
  console.log(`User connected: ${socket.id}`);

  socket.on('send-message', async (data) => {
    try {
      const { receiverId, encryptedContent, nonce } = data;
      const senderId = socket.handshake.query.userId;

      const permission = await Permission.findOne({
        where: { userId: senderId, allowedUserId: receiverId, granted: true }
      });

      if (!permission) {
        socket.emit('error', 'Permission denied');
        return;
      }

      const message = await Message.create({
        senderId,
        receiverId,
        encryptedContent,
        nonce
      });

      io.to(receiverId).emit('receive-message', {
        id: message.id,
        senderId,
        encryptedContent,
        nonce,
        timestamp: message.timestamp
      });
    } catch (error) {
      socket.emit('error', error.message);
    }
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.id}`);
  });
});

// Start server
sequelize.sync().then(() => {
  server.listen(3000, () => {
    console.log('🚀 SecureChat server running on port 3000');
  });
}).catch(err => {
  console.error('Database sync failed:', err);
});