const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const iconv = require('iconv-lite');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Èñïîëüçóåì ïîðò èç ïåðåìåííîé îêðóæåíèÿ èëè 6532
const PORT = process.env.PORT || 6532;
const USERS_FILE = path.join(__dirname, 'users.json');

// Çàãðóçêà ïîëüçîâàòåëåé èç ôàéëà
let users = {};
try {
    if (fs.existsSync(USERS_FILE)) {
        users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    }
} catch (err) {
    console.error('Error loading user data:', err);
}

// Ñîõðàíåíèå ïîëüçîâàòåëåé â ôàéë
function saveUsers() {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

// Middleware äëÿ ïðàâèëüíîé êîäèðîâêè
app.use((req, res, next) => {
  res.header('Content-Type', 'text/html; charset=utf-8');
  next();
});

app.use(express.json({ type: ['application/json', 'text/plain'] }));
app.use(express.urlencoded({ extended: true }));

const connectedUsers = {};
const activeTokens = {};
const guestUsers = {};
const groups = {};
const userGroups = {}; // Òåêóùèå ãðóïïû ïîëüçîâàòåëåé

// Ãåíåðàöèÿ òîêåíà
function generateToken(username) {
    const token = crypto.randomBytes(16).toString('hex');
    activeTokens[token] = {
        username,
        expires: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 äíåé
    };
    return token;
}

// Ïðîâåðêà òîêåíà
function verifyToken(token, username) {
    const tokenData = activeTokens[token];
    if (!tokenData) return false;
    if (tokenData.username !== username) return false;
    if (username.startsWith('guest') && !guestUsers[username]) {
        delete activeTokens[token];
        return false;
    }
    if (tokenData.expires < Date.now()) {
        delete activeTokens[token];
        return false;
    }
    return true;
}

function decodeText(text) {
  return text ? iconv.decode(Buffer.from(text), 'utf8') : 'guest';
}

io.on('connection', (socket) => {
    console.log('New connection:', socket.id);
    
    // Îáðàáîòêà ðåãèñòðàöèè
    socket.on('register', ({ username, password }, callback) => {
        const decodedUsername = decodeText(username);
        const decodedPassword = decodeText(password);
        
        if (users[decodedUsername]) {
            return callback({ success: false, message: 'Username already exists' });
        }
        
        users[decodedUsername] = {
            password: decodedPassword,
            createdAt: new Date().toISOString()
        };
        
        saveUsers();
        callback({ success: true });
    });
    
    // Îáðàáîòêà âõîäà
    socket.on('login', ({ username, password }, callback) => {
        const decodedUsername = decodeText(username);
        const decodedPassword = decodeText(password);
        
        const user = users[decodedUsername];
        if (!user) {
            return callback({ success: false, message: 'User not found' });
        }
        
        if (user.password !== decodedPassword) {
            return callback({ success: false, message: 'Invalid password' });
        }
        
        const token = generateToken(decodedUsername);
        callback({ success: true, token });
    });
    
    // Ñîçäàíèå ãîñòåâîãî ïîëüçîâàòåëÿ
    socket.on('createGuest', ({ username }, callback) => {
        const decodedUsername = decodeText(username);
        const token = generateToken(decodedUsername);
        guestUsers[decodedUsername] = { token };
        callback({ success: true, token });
    });
    
    // Ïðîâåðêà òîêåíà
    socket.on('verifyToken', ({ token, username }, callback) => {
        const isValid = verifyToken(token, username);
        callback({ success: isValid });
    });
    
    // Óñòàíîâêà èìåíè
    socket.on('setName', (name) => {
        const userName = decodeText(name);
        connectedUsers[socket.id] = userName;
        userGroups[userName] = null; // Ïî óìîë÷àíèþ íåò ãðóïïû
        
        io.emit('newMessage', {
            name: 'Server',
            message: `${userName} connected`
        });
        sendUserCount();
    });

    // Ñîçäàíèå ãðóïïû
    socket.on('create_group', ({ groupName }, callback) => {
        const username = connectedUsers[socket.id];
        if (!username) return callback({ success: false, message: 'Not authorized' });

        const decodedGroupName = decodeText(groupName);
        
        if (groups[decodedGroupName]) {
            return callback({ success: false, message: 'Group already exists' });
        }

        groups[decodedGroupName] = {
            users: [username],
            creator: username,
            admins: [username],
            banned: [],
            sockets: [socket.id]
        };

        userGroups[username] = decodedGroupName;
        
        callback({ success: true, groupName: decodedGroupName });
        io.to(socket.id).emit('system_message', `Group "${decodedGroupName}" created!`);
        io.to(socket.id).emit('update_group', decodedGroupName);
    });

    // Ïðèãëàøåíèå â ãðóïïó (áåç óêàçàíèÿ ãðóïïû - â òåêóùóþ)
    socket.on('invite', ({ user }, callback) => {
        const username = connectedUsers[socket.id];
        if (!username) return callback({ success: false, message: 'Not authorized' });
        
        const groupName = userGroups[username];
        if (!groupName) return callback({ success: false, message: 'You are not in a group' });

        const decodedUser = decodeText(user);
        
        if (!groups[groupName]) return callback({ success: false, message: 'Group not found' });
        if (!groups[groupName].admins.includes(username)) 
            return callback({ success: false, message: 'No permissions' });
        
        const recipientSocket = Object.entries(connectedUsers).find(([_, u]) => u === decodedUser);
        if (recipientSocket) {
            io.to(recipientSocket[0]).emit('group_invite', {
                groupName: groupName,
                from: username
            });
        }
        
        callback({ success: true });
    });

    // Âõîä â ãðóïïó
    socket.on('join_group', ({ groupName }, callback) => {
        const username = connectedUsers[socket.id];
        if (!username) return callback({ success: false, message: 'Not authorized' });

        const decodedGroupName = decodeText(groupName);
        
        if (!groups[decodedGroupName]) {
            return callback({ success: false, message: 'Group not found' });
        }

        // Âûõîäèì èç òåêóùåé ãðóïïû åñëè åñòü
        if (userGroups[username]) {
            const currentGroup = userGroups[username];
            groups[currentGroup].sockets = groups[currentGroup].sockets.filter(s => s !== socket.id);
            groups[currentGroup].users = groups[currentGroup].users.filter(u => u !== username);
        }

        // Âõîäèì â íîâóþ ãðóïïó
        groups[decodedGroupName].users.push(username);
        groups[decodedGroupName].sockets.push(socket.id);
        userGroups[username] = decodedGroupName;
        
        io.to(socket.id).emit('system_message', `You joined group "${decodedGroupName}"`);
        io.to(socket.id).emit('update_group', decodedGroupName);
        socket.broadcast.to(groups[decodedGroupName].sockets).emit('system_message',
            `User ${username} joined the group`);
            
        callback({ success: true });
    });

    // Âûõîä èç ãðóïïû
    socket.on('leave_group', (_, callback) => {
        const username = connectedUsers[socket.id];
        if (!username) return callback({ success: false, message: 'Not authorized' });

        const groupName = userGroups[username];
        if (!groupName) return callback({ success: false, message: 'You are not in a group' });

        groups[groupName].sockets = groups[groupName].sockets.filter(s => s !== socket.id);
        groups[groupName].users = groups[groupName].users.filter(u => u !== username);
        userGroups[username] = null;
        
        io.to(socket.id).emit('system_message', `You left group "${groupName}"`);
        io.to(socket.id).emit('update_group', null);
        socket.broadcast.to(groups[groupName].sockets).emit('system_message',
            `User ${username} left the group`);
            
        callback({ success: true });
    });

    // Êèê ïîëüçîâàòåëÿ
    socket.on('kick_user', ({ user }, callback) => {
        const username = connectedUsers[socket.id];
        if (!username) return callback({ success: false, message: 'Not authorized' });

        const groupName = userGroups[username];
        if (!groupName) return callback({ success: false, message: 'You are not in a group' });

        const decodedUser = decodeText(user);
        
        if (!groups[groupName].admins.includes(username))
            return callback({ success: false, message: 'No permissions' });
        
        groups[groupName].users = groups[groupName].users.filter(u => u !== decodedUser);
        userGroups[decodedUser] = null;
        
        const userSocket = Object.entries(connectedUsers).find(([_, u]) => u === decodedUser);
        if (userSocket && groups[groupName].sockets.includes(userSocket[0])) {
            io.to(userSocket[0]).emit('system_message', `You were kicked from group "${groupName}"`);
            io.to(userSocket[0]).emit('update_group', null);
            groups[groupName].sockets = groups[groupName].sockets.filter(s => s !== userSocket[0]);
        }
        
        callback({ success: true });
    });

    // Îòïðàâêà ñîîáùåíèé
    socket.on('sendMessage', (data) => {
        if (data && data.name && data.message) {
            const username = decodeText(data.name);
            const message = decodeText(data.message);

            const groupName = userGroups[username];
            
            if (groupName && groups[groupName]) {
                // Îòïðàâëÿåì â ãðóïïó
                io.to(groups[groupName].sockets).emit('newMessage', {
                    name: username,
                    message,
                    group: groupName
                });
            } else {
                // Îòïðàâëÿåì â îáùèé ÷àò
                io.emit('newMessage', {
                    name: username,
                    message,
                    group: null
                });
            }
        }
    });

    // Ëè÷íûå ñîîáùåíèÿ
    socket.on('privateMessage', ({ from, to, message }, callback) => {
        const decodedFrom = decodeText(from);
        const decodedTo = decodeText(to);
        const decodedMessage = decodeText(message);

        const recipientSocket = Object.entries(connectedUsers).find(
            ([_, username]) => username === decodedTo
        );

        if (!recipientSocket) {
            return callback({ success: false, message: 'User not online' });
        }

        io.to(recipientSocket[0]).emit('privateMessage', {
            from: decodedFrom,
            message: decodedMessage
        });

        callback({ success: true });
    });

    // Îòêëþ÷åíèå
    socket.on('disconnect', () => {
        const userName = connectedUsers[socket.id] ? decodeText(connectedUsers[socket.id]) : 'guest';
        
        // Âûõîäèì èç ãðóïïû ïðè îòêëþ÷åíèè
        if (userGroups[userName]) {
            const groupName = userGroups[userName];
            if (groups[groupName]) {
                groups[groupName].sockets = groups[groupName].sockets.filter(s => s !== socket.id);
                groups[groupName].users = groups[groupName].users.filter(u => u !== userName);
                socket.broadcast.to(groups[groupName].sockets).emit('system_message',
                    `User ${userName} disconnected`);
            }
            delete userGroups[userName];
        }
        
        delete connectedUsers[socket.id];
        io.emit('newMessage', {
            name: 'Server',
            message: `${userName} disconnected`
        });
        sendUserCount();
    });
});

function sendUserCount() {
    const users = Object.values(connectedUsers).map(user => decodeText(user));
    io.emit('userCountUpdate', {
        count: users.length,
        users
    });
}

app.use(express.static('public'));

app.get('/', (req, res) => {
    res.redirect('/auth.html');
});

server.listen(PORT, () => {
    console.log(`CNT Messenger started on port ${PORT}`);
});
