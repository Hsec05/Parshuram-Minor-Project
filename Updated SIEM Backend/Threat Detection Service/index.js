require('dotenv').config();

const express = require('express');
const http = require('http');
const bodyParser = require('body-parser');
const { connectDB } = require('./util/db');
const windowsRoutes = require('./routes/windows');
const agentRoutes = require('./routes/agent-auth-routes');
const policyRoutes = require('./routes/policy-route'); // <-- new

const app = express();

const session = require('express-session');
app.use(session({
    resave: false,
    saveUninitialized: true,
    secret: process.env.SESSION_SECRET
}));

app.use(bodyParser.json({ limit: '2mb' }));

// Routes
app.use('/api/auth', agentRoutes);
app.use('/api/windows', windowsRoutes);
app.use('/api/policies', policyRoutes); // <-- new

// Optional: test endpoint for log analysis
const { analyzeWindowsLog } = require('./utils/ruleEngine');
app.post('/api/logs/analyze', async (req, res) => {
  const log = req.body;
  try {
    const matches = await analyzeWindowsLog(log);
    res.json({ matches });
  } catch (err) {
    console.error('Log analysis error', err);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3001;

async function start() {
  try {
    await connectDB();
    app.listen(PORT, () => {
      console.log(`SIEM server listening on port ${PORT}`);
    });
  } catch (e) {
    console.error('Start failed', e);
    process.exit(1);
  }
}

start();
