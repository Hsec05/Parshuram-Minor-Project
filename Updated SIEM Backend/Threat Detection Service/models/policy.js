const mongoose = require("mongoose");

const policySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: { type: String },
  conditions: {
    eventType: String,         // e.g., "login_failed"
    threshold: Number,         // e.g., 5
    timeWindow: String,        // e.g., "10m"
    source: String             // e.g., "WindowsLogs"
  },
  actions: {
    alert: { type: Boolean, default: false },
    ticket: { type: Boolean, default: false },
    notifyEmail: { type: String }
  },
  createdBy: { type: String, default: "admin" },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Policy", policySchema);
