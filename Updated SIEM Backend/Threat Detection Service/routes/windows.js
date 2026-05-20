const express = require('express');
const router = express.Router();
const authAgent = require('../middlewares/auth-middleware');
const { decodeWindowsLog } = require('../decoders/windowsDecoder');
const { analyzeWindowsLog } = require('../utils/ruleEngine');
const redisClient = require('../util/redisConnect');
const WindowsLog = require('../models/windows_logs');
const WindowsThreat = require('../models/windows_threats');

// Generic handler for a channel (system/security/application)
async function handleChannel(req, res, channel) {
  const logs = Array.isArray(req.body.logs) ? req.body.logs : [req.body];
  const alerts = [];
  const agentId = req.agent; // From auth middleware
  const ip = req.headers['x-agent-ip'] || req.ip; // Optional

  for (const raw of logs) {
    try {
      const decoded = decodeWindowsLog(raw);
      const matched = await analyzeWindowsLog(decoded);
      console.log(matched);
      

      const logData = {
        agent_id: agentId,
        ip,
        os: 'windows',
        channel,
        severity: matched.length > 0
          ? (matched.some(m => m.severity === 'high') ? 'high' : 'medium')
          : 'low',
        level: decoded.level,
        eventId: decoded.eventId,
        timeCreated: decoded.timeCreated ? new Date(decoded.timeCreated) : new Date(),
        source: decoded.source,
        task: decoded.task,
        computer: decoded.computer,
        description: decoded.description
      }

      const threatData = {
        agent_id: agentId,
        ip,
        os: 'windows',
        channel,
        severity: matched.some(m => m.severity === 'high') ? 'high' : 'medium',
        ruleMatched: matched.map(m => m.id),
        message: matched.map(m => m.description).join(' | ')
      }

      if (decoded.accountName) {logData.accountName = decoded.accountName};
      if (decoded.logonType != null && decoded.logonType !== '') {logData.logonType = decoded.logonType};
      if (matched.length > 0) {logData.threat = true}
      // Store the full log with flat fields
      const logDoc = await WindowsLog.create(logData);

      // If threats matched, create threat record
      if (matched.length > 0) {
        threatData.log_ref = logDoc._id;
        await WindowsThreat.create(threatData);

        alerts.push({
          log_id: logDoc._id,
          severity: matched.some(m => m.severity === 'high') ? 'high' : 'medium',
          matched
        });
      }
    } catch (err) {
      console.error('Processing error', err);
    }
  }

  res.json({ status: 'ok' });
  redisClient.publish('threat_alerts', JSON.stringify(alerts));
}

router.post('/system', authAgent, (req, res) => handleChannel(req, res, 'system'));
router.post('/security', authAgent, (req, res) => handleChannel(req, res, 'security'));
router.post('/application', authAgent, (req, res) => handleChannel(req, res, 'application'));

module.exports = router;