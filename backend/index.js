const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const PORT = process.env.PORT || 3000;

// Store connected users
let users = {};

// Generate a random key
function generateKey() {
    return crypto.randomBytes(32).toString('hex');
}

app.get('/', (req, res) => {
    res.send('E2E Encrypted Chat Server is running.')
});

io.on('connection', (socket) => {
    console.log('A user connected');

    socket.on('register', (username) => {
        users[socket.id] = username;
        socket.emit('key', generateKey());
        console.log(`${username} has connected`);
    });

    socket.on('sendMessage', (data) => {
        console.log(`Message from ${data.username}: ${data.message}`);
        socket.broadcast.emit('receiveMessage', data);
    });

    socket.on('disconnect', () => {
        console.log(`User ${users[socket.id]} disconnected`);
        delete users[socket.id];
    });
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
