// backend/index.js
const express = require('express');
const cors = require('cors');
const http = require('http');
const SocketIO = require('socket.io');
const { Sequelize, DataTypes } = require('sequelize');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = SocketIO(server);
app.use(cors());
app.use(express.json());

// Sequelize database connection
const sequelize = new Sequelize('SecureChatDB', 'user', 'password', {
    host: 'localhost',
    dialect: 'mysql',
});

// Sequelize models
const User = sequelize.define('User', {
    username: {
        type: DataTypes.STRING,
        unique: true,
    },
    password: {
        type: DataTypes.STRING,
    },
});

const Message = sequelize.define('Message', {
    content: {
        type: DataTypes.TEXT,
    },
    senderId: {
        type: DataTypes.INTEGER,
    },
});

const Permission = sequelize.define('Permission', {
    userId: {
        type: DataTypes.INTEGER,
    },
    canSendMessages: {
        type: DataTypes.BOOLEAN,
    },
});

// Authentication function
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, 'your_jwt_secret', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Password hashing
app.post('/register', async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = await User.create({ username: req.body.username, password: hashedPassword });
    res.status(201).json(user);
});

app.post('/login', async (req, res) => {
    const user = await User.findOne({ where: { username: req.body.username } });
    if (!user) return res.sendStatus(404);

    const isValidPassword = await bcrypt.compare(req.body.password, user.password);
    if (!isValidPassword) return res.sendStatus(403);

    const accessToken = jwt.sign({ username: user.username }, 'your_jwt_secret', { expiresIn: '1h' });
    res.json({ accessToken });
});

// E2E Encryption support
const encryptMessage = (message) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from('your_encryption_key'), iv);
    let encrypted = cipher.update(message);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
};

// Socket.io for real-time messaging
io.on('connection', (socket) => {
    console.log('New client connected');
    socket.on('sendMessage', (msg) => {
        const encryptedMsg = encryptMessage(msg.content);
        // Store encrypted message in the database
        Message.create({ content: encryptedMsg, senderId: msg.senderId });
        socket.broadcast.emit('message', msg);
    });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Sync models
sequelize.sync();
