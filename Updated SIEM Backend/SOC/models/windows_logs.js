// models/windows_logs.js
const mongoose = require('mongoose');

const WindowsLogSchema = new mongoose.Schema({
  agent_id: { type: String, required: true, index: true }, // Unique agent/machine ID
  ip: { type: String, index: true }, // Optional - populated from request headers
  os: { type: String, default: 'windows' },
  channel: { type: String, enum: ['system', 'security', 'application'], index: true },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], index: true },
  level: { type: Number },
  eventId: { type: Number, index: true },
  timeCreated: { type: Date, index: true }, // From log source
  source: { type: String },
  task: { type: String },
  computer: { type: String },
  description: { type: String },
  accountName: { type: String, index: true },
  logonType: { type: Number, index: true },
  threat: { type: Boolean }
});

// Compound indexes for query performance
WindowsLogSchema.index({ agent_id: 1, timeCreated: -1 });
WindowsLogSchema.index({ severity: 1, timeCreated: -1 });
WindowsLogSchema.index({ ip: 1, timeCreated: -1 });

module.exports = mongoose.model('windows_logs', WindowsLogSchema, 'windows_logs');
