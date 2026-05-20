const mongoose = require('mongoose');

const updateSchema = new mongoose.Schema({
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'under_review', 'closed'], required: true },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical', 'urgent'], required: true },
  attachments: [{ type: String }], // file paths or URLs
  employee_id: { type: String, required: true }, // from MySQL users table
  updated_at: { type: Date, default: Date.now }
});

const ticketSchema = new mongoose.Schema({
  ticketID: { type: Number, unique: true, index: true }, // auto-increment ticket number
  title: { type: String, required: true },
  description: { type: String, required: true },
  
  files: [{ type: String }], 
  createdBy: { type: String, required: true, index: true },
  // references to logs (Windows or Linux)
  log_refs: [
    {
      type: mongoose.Schema.Types.ObjectId,
      refPath: 'logModel' // dynamically refers to windows_logs, linux_logs etc.
    }
  ],
  logModel: { type: String, required: true, enum: ['windows_logs', 'linux_logs'] }, // which collection logs belong to

  status: { type: String, enum: ['open', 'working', 'closed'], default: 'open', index: true },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical', 'urgent'], required: true, index: true },
  updates: [updateSchema],
  levels: [{ type: String, enum: ['L1', 'L2', 'L3', 'L4'], index: true}],
  contributors: [{ type: String, index: true }],
  created_at: { type: Date, default: Date.now, index: true },
  updated_at: { type: Date, default: Date.now }
});
ticketSchema.index({ title: 'text' });

// Pre-save hook to auto-increment ticketNumber
ticketSchema.pre('save', async function (next) {
  if (this.isNew) {
    const Counter = mongoose.model('TicketCounter');
    const counter = await Counter.findOneAndUpdate(
      { name: 'ticketNumber' },
      { $inc: { value: 1 } },
      { new: true, upsert: true }
    );
    this.ticketNumber = counter.value;
  }
  next();
});

// Counter model for auto increment
const counterSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  value: { type: Number, default: 0 }
});
mongoose.model('TicketCounter', counterSchema);

module.exports = mongoose.model('tickets', ticketSchema, 'tickets');
