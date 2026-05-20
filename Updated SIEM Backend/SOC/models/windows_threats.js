// models/windows_threats.js
const mongoose = require('mongoose');

const WindowsThreatSchema = new mongoose.Schema({
  log_ref: { type: mongoose.Schema.Types.ObjectId, ref: 'WindowsLog', required: true },
  agent_id: { type: String, required: true, index: true },
  ip: { type: String, index: true },
  os: { type: String, default: 'windows' },
  channel: { type: String, enum: ['system', 'security', 'application'], index: true },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], index: true },
  ruleMatched: { type: [String], required: true, index: true }, // Array of rule IDs
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now, index: true }
});

// Indexes for fast queries
WindowsThreatSchema.index({ agent_id: 1, timestamp: -1 });
WindowsThreatSchema.index({ severity: 1, timestamp: -1 });
WindowsThreatSchema.index({ ip: 1, timestamp: -1 });

module.exports = mongoose.model('windows_threats', WindowsThreatSchema, 'windows_threats');
