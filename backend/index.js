'use strict';

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const crypto = require('crypto');

// Create Express app
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const PORT = process.env.PORT || 3000;

// Encrypt messages
const encrypt = (text) => {
    const cipher = crypto.createCipher('aes-256-cbc', 'a_password');
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
};

// Decrypt messages
const decrypt = (encryptedText) => {
    const decipher = crypto.createDecipher('aes-256-cbc', 'a_password');
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};

// Socket.io connection
io.on('connection', (socket) => {
    console.log('New client connected');
    
    socket.on('sendMessage', (message) => {
        const encryptedMessage = encrypt(message);
        io.emit('receiveMessage', encryptedMessage);
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});

// Start the server
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
