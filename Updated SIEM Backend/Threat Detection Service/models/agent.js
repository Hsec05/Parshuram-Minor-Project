const mongoose = require('mongoose');


const agentSchema = new mongoose.Schema({
  agentId: { type: String, required: true, unique: true, index: true }, // UUID or custom ID
  fingerprint: { type: String, required: true, unique: true },
  cpuId: { type: String, required: true },
  motherboardId: { type: String, required: true },
  diskId: { type: String, required: true },
  lastLoginAt: { type: Date, required: false },
  active: { type: Boolean, default: false }
}, { timestamps: true });

module.exports = mongoose.model('agent', agentSchema, 'agent');
