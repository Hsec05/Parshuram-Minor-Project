// 
// SOC/index.js
require('dotenv').config();

const express = require('express');
const path = require('path');
const cors = require('cors');
const app = express();
const session = require('express-session');
const authRoutes = require('./routes/auth-router');
const ticketRoutes = require('./routes/ticket-router');
const logRoutes = require('./routes/log-router');
const dashboardRoutes = require('./routes/dashboard-router');
const agentRoutes = require('./routes/agent-router');
const authUser = require('./middlewares/auth-middleware');
const {authLimiter} = require('./middlewares/rate-limiter');
const redisClient = require('./util/redisConnect');
const redisBrokerClient = require('./util/redisBroker'); 
const mongoConnect = require('./util/mongoConnect');
const fs = require('fs');

const port = process.env.PORT;

app.use(session({
    resave: false,
    saveUninitialized: true,
    secret: process.env.SESSION_SECRET
}));

app.use(express.json());

// redisBrokerClient.subscribe('threat_alerts', (message) => {
//   try {
//       const alert = JSON.parse(message);
//       console.log('Received alert from ingestion:', alert);
//       // io.emit('new_alert', alert); // Uncomment if using Socket.IO
//     } catch (err) {
//       console.error('Failed to parse alert:', err);
//     }
// });

// redisClient.subscribe('threat_alerts', (message) => {
//   try {
//       const alert = JSON.parse(message);
//       console.log('Received alert from ingestion:', alert);
//       // io.emit('new_alert', alert); // Uncomment if using Socket.IO
//     } catch (err) {
//       console.error('Failed to parse alert:', err);
//     }
// });

const allowedOrigins = [
    'https://6hz6c9fr-5501.inc1.devtunnels.ms',
    'http://127.0.0.1:5500',
    'https://4ldd3q1q-5500.inc1.devtunnels.ms',
    'http://localhost:5173'
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));
const adminRoutes = require('./routes/admin-router');
app.use('/api/admin', adminRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/tickets', ticketRoutes);
app.use('/api/logs', logRoutes);
app.use('/api/threats', dashboardRoutes);
app.use('/api/agents', agentRoutes);

const UPLOADS_DIR = path.join(__dirname, 'uploads', 'tickets');
app.get('/uploads/tickets/:fileName', authUser, authLimiter, (req, res) => {
    const fileName = req.params.fileName;
    const filePath = path.join(UPLOADS_DIR, fileName);
    const normalizedPath = path.normalize(filePath);
    if (!normalizedPath.startsWith(UPLOADS_DIR)) {
        return res.status(400).send('Invalid file path');
    }
    fs.access(normalizedPath, fs.constants.F_OK, (err) => {
        if (err) {
            return res.status(404).send('File not found');
        }
        res.sendFile(normalizedPath, (err) => {
            if (err) {
                console.error('Error sending file:', err);
                return res.status(500).send('Server error');
            }
        });
    });
});

async function start() {
  try {
    await mongoConnect();
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  } catch (e) {
    console.error('Start failed', e);
    process.exit(1);
  }
}

start();