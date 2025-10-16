const express = require('express');
const WebSocket = require('ws');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();

// CORS configuration
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

app.use(express.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 10000;

// Store active connections and tokens
const clients = new Map(); // clientId -> { ws, userData, isAuthenticated }
const userRooms = new Map(); // clientId -> roomId
const chatTokens = new Map(); // chatToken -> userData
const clientTokens = new Map(); // clientId -> chatToken
const salesforceUsers = new Map(); // userId -> userData

// Token expiration time (24 hours)
const TOKEN_EXPIRY = 24 * 60 * 60 * 1000;

console.log('🚀 Starting Chat Server...');
console.log('📍 Port:', PORT);

// ============================================
// UTILITY FUNCTIONS
// ============================================

function cleanExpiredTokens() {
    const now = Date.now();
    let cleaned = 0;
    
    chatTokens.forEach((data, token) => {
        if (data.expiresAt < now) {
            chatTokens.delete(token);
            cleaned++;
        }
    });
    
    if (cleaned > 0) {
        console.log(`🧹 Cleaned ${cleaned} expired tokens`);
    }
}

setInterval(cleanExpiredTokens, 60 * 60 * 1000);

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function isValidTokenFormat(token) {
    return typeof token === 'string' && token.length === 64 && /^[a-f0-9]+$/.test(token);
}

// ============================================
// HTTP ENDPOINTS
// ============================================

app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'OK', 
        service: 'Chat Server',
        timestamp: new Date().toISOString(),
        activeConnections: clients.size,
        activeTokens: chatTokens.size,
        activeRooms: new Set(userRooms.values()).size
    });
});

app.get('/oauth/authorize', (req, res) => {
    console.log('🔐 OAuth authorize request');
    const { redirect_uri, state, client_id } = req.query;
    
    const code = generateToken();
    console.log('✅ Authorization code generated');
    
    res.redirect(`${redirect_uri}?code=${code}&state=${state}`);
});

app.post('/oauth/token', (req, res) => {
    console.log('🔐 OAuth token request');
    const { grant_type, code, refresh_token } = req.body;
    
    const accessToken = generateToken();
    const newRefreshToken = generateToken();
    
    console.log('✅ Access token generated');
    
    res.json({
        access_token: accessToken,
        refresh_token: newRefreshToken,
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'api'
    });
});

app.post('/api/auth/salesforce-token', (req, res) => {
    try {
        console.log('🔐 Chat token request received');
        console.log('📥 Request body:', JSON.stringify(req.body, null, 2));
        
        const { userId, name, email, username, profile, instanceUrl } = req.body;
        
        if (!userId || !name || !email) {
            console.log('❌ Missing required fields');
            return res.status(400).json({ 
                error: 'Missing required fields',
                required: ['userId', 'name', 'email']
            });
        }
        
        const chatToken = generateToken();
        
        const userData = {
            userId,
            name,
            email,
            username: username || email,
            profile: profile || 'Standard User',
            instanceUrl: instanceUrl || 'Unknown',
            chatToken,
            createdAt: Date.now(),
            expiresAt: Date.now() + TOKEN_EXPIRY,
            lastActivity: Date.now()
        };
        
        chatTokens.set(chatToken, userData);
        salesforceUsers.set(userId, userData);
        
        console.log(`✅ Chat token generated for: ${name} (${userId})`);
        console.log(`📊 Active tokens: ${chatTokens.size}`);
        
        res.status(200).json({
            success: true,
            chatToken,
            expiresIn: TOKEN_EXPIRY / 1000,
            expiresAt: userData.expiresAt,
            message: 'Token generated successfully'
        });
        
    } catch (error) {
        console.error('❌ Error generating token:', error);
        res.status(500).json({ 
            error: 'Failed to generate token',
            message: error.message 
        });
    }
});

app.post('/api/auth/validate', (req, res) => {
    try {
        console.log('🔍 Token validation request');
        const { chatToken } = req.body;
        
        if (!chatToken) {
            return res.status(400).json({ 
                valid: false,
                error: 'Token required' 
            });
        }
        
        if (!isValidTokenFormat(chatToken)) {
            console.log('❌ Invalid token format');
            return res.status(400).json({ 
                valid: false,
                error: 'Invalid token format' 
            });
        }
        
        const tokenData = chatTokens.get(chatToken);
        
        if (!tokenData) {
            console.log('❌ Token not found');
            return res.status(401).json({ 
                valid: false,
                error: 'Invalid token' 
            });
        }
        
        if (tokenData.expiresAt < Date.now()) {
            console.log('❌ Token expired');
            chatTokens.delete(chatToken);
            return res.status(401).json({ 
                valid: false,
                error: 'Token expired' 
            });
        }
        
        tokenData.lastActivity = Date.now();
        
        console.log(`✅ Token valid for: ${tokenData.name}`);
        
        res.status(200).json({
            valid: true,
            userId: tokenData.userId,
            name: tokenData.name,
            email: tokenData.email,
            expiresAt: tokenData.expiresAt
        });
        
    } catch (error) {
        console.error('❌ Validation error:', error);
        res.status(500).json({ 
            valid: false,
            error: 'Validation failed' 
        });
    }
});

app.post('/api/auth/revoke', (req, res) => {
    try {
        const { chatToken } = req.body;
        
        if (!chatToken) {
            return res.status(400).json({ error: 'Token required' });
        }
        
        const tokenData = chatTokens.get(chatToken);
        
        if (tokenData) {
            chatTokens.delete(chatToken);
            console.log(`🔓 Token revoked for: ${tokenData.name}`);
            
            res.status(200).json({ 
                success: true,
                message: 'Token revoked successfully' 
            });
        } else {
            res.status(404).json({ 
                success: false,
                error: 'Token not found' 
            });
        }
        
    } catch (error) {
        console.error('❌ Revoke error:', error);
        res.status(500).json({ error: 'Failed to revoke token' });
    }
});

app.get('/api/auth/userinfo', (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Authorization header required' });
        }
        
        const chatToken = authHeader.substring(7);
        const tokenData = chatTokens.get(chatToken);
        
        if (!tokenData || tokenData.expiresAt < Date.now()) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }
        
        res.status(200).json({
            userId: tokenData.userId,
            name: tokenData.name,
            email: tokenData.email,
            username: tokenData.username,
            profile: tokenData.profile,
            instanceUrl: tokenData.instanceUrl
        });
        
    } catch (error) {
        console.error('❌ User info error:', error);
        res.status(500).json({ error: 'Failed to get user info' });
    }
});

app.post('/api/test/message', (req, res) => {
    console.log('🧪 Test message received:', req.body);
    res.status(200).json({ 
        success: true,
        received: req.body,
        timestamp: new Date().toISOString()
    });
});

// ============================================
// WEBSOCKET SERVER - FIXED VERSION
// ============================================

const server = app.listen(PORT, () => {
    console.log(`🚀 Chat server running on port ${PORT}`);
    console.log(`📍 HTTP: http://localhost:${PORT}`);
    console.log(`📍 WebSocket: ws://localhost:${PORT}`);
});

const wss = new WebSocket.Server({ 
    server,
    perMessageDeflate: false,
    clientTracking: true
});

console.log('🔌 WebSocket server initialized');

wss.on('connection', (ws, req) => {
    const clientId = uuidv4();
    console.log(`✅ New WebSocket connection: ${clientId}`);
    console.log(`📊 Total connections: ${clients.size + 1}`);
    
    // Store connection with state - FIXED
    const clientState = {
        ws: ws,
        isAuthenticated: false,
        userData: null,
        connectedAt: Date.now()
    };
    
    clients.set(clientId, clientState);
    
    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data);
            console.log(`📨 Message from ${clientId}:`, message.type);
            
            handleWebSocketMessage(clientId, message);
            
        } catch (error) {
            console.error('❌ Error parsing message:', error);
            sendError(clientId, 'Invalid message format');
        }
    });
    
    ws.on('close', () => {
        console.log(`❌ WebSocket disconnected: ${clientId}`);
        console.log(`📊 Total connections: ${clients.size - 1}`);
        
        // Remove from tracking
        clients.delete(clientId);
        userRooms.delete(clientId);
        clientTokens.delete(clientId);
    });
    
    ws.on('error', (error) => {
        console.error(`❌ WebSocket error for client ${clientId}:`, error);
    });
    
    // Send welcome message
    ws.send(JSON.stringify({
        type: 'connection',
        clientId: clientId,
        message: 'Connected to chat server',
        timestamp: new Date().toISOString()
    }));
});

/**
 * Handle WebSocket messages
 */
function handleWebSocketMessage(clientId, message) {
    const clientState = clients.get(clientId);
    if (!clientState) return;
    
    switch (message.type) {
        case 'authenticate':
            authenticateClient(clientId, message);
            break;
            
        case 'join':
            joinRoom(clientId, message);
            break;
            
        case 'chat':
            sendMessage(clientId, message);
            break;
            
        case 'leave':
            leaveRoom(clientId);
            break;
            
        default:
            sendError(clientId, 'Unknown message type');
    }
}

/**
 * Authenticate client with chat token
 */
function authenticateClient(clientId, message) {
    const clientState = clients.get(clientId);
    if (!clientState) return;
    
    const { chatToken } = message;
    
    if (!chatToken) {
        sendError(clientId, 'Authentication token required');
        return;
    }
    
    const tokenData = chatTokens.get(chatToken);
    
    if (!tokenData || tokenData.expiresAt < Date.now()) {
        sendError(clientId, 'Invalid or expired authentication token');
        return;
    }
    
    // Store authentication
    clientTokens.set(clientId, chatToken);
    clientState.userData = tokenData;
    clientState.isAuthenticated = true;
    
    // Send success response
    clientState.ws.send(JSON.stringify({
        type: 'authenticated',
        message: 'Successfully authenticated',
        userId: tokenData.userId,
        name: tokenData.name,
        timestamp: new Date().toISOString()
    }));
    
    console.log(`✅ Client authenticated: ${tokenData.name} (${clientId})`);
}

/**
 * Join a chat room
 */
function joinRoom(clientId, message) {
    const clientState = clients.get(clientId);
    if (!clientState || !clientState.isAuthenticated) {
        sendError(clientId, 'Authentication required');
        return;
    }
    
    const { room } = message;
    
    if (!room) {
        sendError(clientId, 'Room name required');
        return;
    }
    
    userRooms.set(clientId, room);
    
    clientState.ws.send(JSON.stringify({
        type: 'joined',
        room: room,
        message: `Joined room: ${room}`,
        timestamp: new Date().toISOString()
    }));
    
    console.log(`📍 Client ${clientId} joined room: ${room}`);
}

/**
 * Send chat message
 */
function sendMessage(clientId, message) {
    const clientState = clients.get(clientId);
    if (!clientState || !clientState.isAuthenticated) {
        sendError(clientId, 'Authentication required');
        return;
    }
    
    const room = userRooms.get(clientId);
    
    if (!room) {
        sendError(clientId, 'Join a room first');
        return;
    }
    
    const chatMessage = {
        type: 'chat',
        messageId: uuidv4(),
        sender: clientState.userData.name,
        content: message.content,
        timestamp: new Date().toISOString(),
        room: room,
        source: 'external'
    };
    
    broadcastToRoom(room, chatMessage, clientId);
    console.log(`📨 Message in room ${room}: ${message.content}`);
}

/**
 * Leave current room
 */
function leaveRoom(clientId) {
    const clientState = clients.get(clientId);
    if (!clientState) return;
    
    const room = userRooms.get(clientId);
    
    if (room) {
        userRooms.delete(clientId);
        clientState.ws.send(JSON.stringify({
            type: 'left',
            room: room,
            message: `Left room: ${room}`,
            timestamp: new Date().toISOString()
        }));
        console.log(`🚪 Client ${clientId} left room: ${room}`);
    }
}

/**
 * Broadcast message to room members
 */
function broadcastToRoom(room, message, excludeClientId = null) {
    let delivered = 0;
    clients.forEach((clientState, clientId) => {
        if (clientId !== excludeClientId && userRooms.get(clientId) === room) {
            if (clientState.ws.readyState === WebSocket.OPEN) {
                clientState.ws.send(JSON.stringify(message));
                delivered++;
            }
        }
    });
    console.log(`📤 Message delivered to ${delivered} clients in room ${room}`);
}

/**
 * Send error message to client
 */
function sendError(clientId, errorMessage) {
    const clientState = clients.get(clientId);
    if (clientState && clientState.ws.readyState === WebSocket.OPEN) {
        clientState.ws.send(JSON.stringify({
            type: 'error',
            message: errorMessage,
            timestamp: new Date().toISOString()
        }));
    }
}

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM received, shutting down gracefully');
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

module.exports = app;