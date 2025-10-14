const WebSocket = require('ws');
const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 10000;

// Store active connections
const clients = new Map();
const userRooms = new Map();

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    service: 'Chat Server',
    timestamp: new Date().toISOString()
  });
});

// WebSocket server
const server = app.listen(PORT, () => {
  console.log(`🚀 Chat server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ 
  server,
  perMessageDeflate: false
});

wss.on('connection', (ws, req) => {
  const clientId = uuidv4();
  console.log(`✅ New client connected: ${clientId}`);
  
  clients.set(clientId, ws);
  
  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data);
      handleMessage(clientId, message);
    } catch (error) {
      console.error('❌ Error parsing message:', error);
      sendError(ws, 'Invalid message format');
    }
  });
  
  ws.on('close', () => {
    console.log(`❌ Client disconnected: ${clientId}`);
    const userRoom = userRooms.get(clientId);
    if (userRoom) {
      userRooms.delete(clientId);
    }
    clients.delete(clientId);
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

function handleMessage(clientId, message) {
  const ws = clients.get(clientId);
  
  switch (message.type) {
    case 'join':
      userRooms.set(clientId, message.room);
      console.log(`📍 Client ${clientId} joined room: ${message.room}`);
      ws.send(JSON.stringify({
        type: 'system',
        message: `Joined room: ${message.room}`,
        timestamp: new Date().toISOString()
      }));
      break;
      
    case 'chat':
      const room = userRooms.get(clientId);
      if (!room) {
        sendError(ws, 'Join a room first');
        return;
      }
      
      const chatMessage = {
        type: 'chat',
        messageId: uuidv4(),
        sender: message.sender || 'Unknown',
        content: message.content,
        timestamp: new Date().toISOString(),
        room: room,
        source: message.source || 'external'
      };
      
      broadcastToRoom(room, chatMessage, clientId);
      console.log(`📨 Message in room ${room}: ${message.content}`);
      break;
      
    default:
      sendError(ws, 'Unknown message type');
  }
}

function broadcastToRoom(room, message, excludeClientId = null) {
  let delivered = 0;
  clients.forEach((ws, clientId) => {
    if (clientId !== excludeClientId && userRooms.get(clientId) === room) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));
        delivered++;
      }
    }
  });
  console.log(`📤 Message delivered to ${delivered} clients in room ${room}`);
}

function sendError(ws, errorMessage) {
  ws.send(JSON.stringify({
    type: 'error',
    message: errorMessage,
    timestamp: new Date().toISOString()
  }));
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