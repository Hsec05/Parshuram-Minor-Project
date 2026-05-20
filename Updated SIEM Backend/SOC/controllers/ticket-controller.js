const path = require('path');
const fs = require('fs');
const multer = require('multer'); //install
const redisClient = require('../util/redisConnect');
const Ticket = require('../models/ticket-model');
const WindowsLog = require('../models/windows_logs');
const WindowsThreat = require('../models/windows_threats');

// Auto increment counter
let ticketCounter = 1000; // can also persist in DB if you want consistency

const raiseTicket = async (req, res) => {
  try {
    const { role, email } = req.user;
    const files = [];

    const allowedRoles = ['L1', 'L2', 'L3', 'L4'];
    if (!allowedRoles.includes(role)) {
      return res.status(403).json({ message: 'Not authorized to raise tickets' });
    }
    console.log(1);
    

    const { title, description, log_refs, severity, attachments, level } = req.body;

    if (!title || !description || !log_refs || !Array.isArray(log_refs) || log_refs.length === 0) {
      return res.status(400).json({ message: 'Missing required fields: title, description, log_refs' });
    }
    console.log(2);

    const allowedSeverities = ['low', 'medium', 'high', 'critical', 'urgent'];
    if (!allowedSeverities.includes(severity)) {
      return res.status(400).json({ message: 'Invalid severity level' });
    }
    console.log(3);
    console.log(log_refs);

    // Validate that referenced logs exist
    const windowsLogs = await WindowsLog.find({ _id: { $in: log_refs } });
    const totalRefs = [...windowsLogs];
    console.log(totalRefs);
    
    

    if (totalRefs.length === 0) {
      return res.status(400).json({ message: 'No valid log references found' });
    }
    console.log(4);

    // Auto increment ticket ID
    ticketCounter++;
    const ticketID = ticketCounter;

    if (!Array.isArray(attachments)) {
      return res.status(400).json({ message: 'Invalid attachments type' });
    }
    console.log(5);

    if (attachments.length > 0) {
      files = attachments;

      for (const file of attachments) {
        const filename = path.basename(file);
        const redisKey = `tempUpload:${filename}`;
        await redisClient.del(redisKey); // remove from auto-delete queue
      }
    }
    console.log(6);
    

    // Create ticket
    const ticket = await Ticket.create({
      ticketID,
      title,
      description,
      log_refs,
      status: 'open',
      severity,
      createdBy: email,
      files,
      updates: [],
      contributors: [email],
      logModel: 'windows_logs',
      levels: [role, ...(level === 'L2' ? ['L2'] : [])]
    });
    console.log(7);   

    res.status(201).json({
      message: 'Ticket raised successfully',
      ticketID
    });

  } catch (err) {
    console.error('Error raising ticket:', err);
    res.status(500).json({ message: 'Server error' });
  }
};

// Multer storage config
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../uploads/tickets');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Unique name: timestamp + random + original filename
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}_${file.originalname}`;
    cb(null, uniqueName);
  }
});

const upload = multer({ storage }).single('file');

// Upload API
const uploadFile = async (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      console.error('Upload error:', err);
      return res.status(500).json({ message: 'File upload failed' });
    }

    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    try {
      const filePath = `/uploads/tickets/${req.file.filename}`;
      const redisKey = `tempUpload:${req.file.filename}`;

      // Add file to cleanup queue (auto delete after 1h)
      await redisClient.set(redisKey, filePath, { EX: 3600 });

      setTimeout(async () => {
        const stillExists = await redisClient.get(redisKey);
        if (stillExists) {
          const fullPath = path.join(__dirname, '..', stillExists);
          if (fs.existsSync(fullPath)) {
            fs.unlinkSync(fullPath);
            console.log(`Auto-deleted unused file: ${fullPath}`);
          }
          await redisClient.del(redisKey);
        }
      }, 3600 * 1000); // 1h
      
      res.status(200).json({
        message: 'File uploaded successfully',
        url: filePath,
        filename: req.file.filename
      });
    } catch (error) {
      console.error('Upload handling error:', error);
      res.status(500).json({ message: 'Error processing uploaded file' });
    }
  });
};

const updateTicket = async (req, res) => {
  try {
    const { role, email } = req.user;

    const { ticketID, message, status, severity, attachments } = req.body;

    if (!ticketID || !message || !status || !severity) {
      return res.status(400).json({
        message: 'Missing required fields: ticketID, message, status, severity'
      });
    }

    // Validate status
    const allowedStatuses = ['open', 'working', 'closed'];
    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status value' });
    }    

    const allowedSeverities = ['low', 'medium', 'high', 'critical', 'urgent'];
    if (!allowedSeverities.includes(severity)) {
      return res.status(400).json({ message: 'Invalid severity level' });
    }

    // Find ticket
    const ticket = await Ticket.findOne({ ticketID });
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    // Check role permission
    if (!ticket.levels.includes(role)) {
      return res.status(403).json({
        message: 'You are not authorized to update this ticket'
      });
    }

    if (!Array.isArray(attachments)) {
      return res.status(400).json({ message: 'Invalid attachments type' });
    }

    if (attachments.length > 0) {
      files = attachments;

      for (const file of attachments) {
        const filename = path.basename(file);
        const redisKey = `tempUpload:${filename}`;
        await redisClient.del(redisKey); // remove from auto-delete queue
      }
    }

    const updateEntry = {
      message,
      status,
      severity,
      attachments: attachments || [],
      employee_id: email,
    };

    ticket.updates.push(updateEntry);

    if (!ticket.contributors.includes(email)) {
      ticket.contributors.push(email);
    }

    // Update main fields
    ticket.status = status;
    ticket.severity = severity;
    ticket.updated_at = new Date();

    await ticket.save();

    res.status(200).json({ message: 'Ticket updated successfully' });

  } catch (err) {
    console.error('Error in updating ticket:', err);
    res.status(500).json({ message: 'Server error' });
  }
}

const addLevel = async (req, res) => {
  try {    
    const { role, email } = req.user;
    const { ticketID, message } = req.body;

    if (!ticketID) {
      return res.status(400).json({ message: 'ticketID is required' });
    }

    // Find the ticket
    const ticket = await Ticket.findOne({ ticketID });
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    // Ensure user role is in ticket.levels
    if (!ticket.levels.includes(role)) {
      return res.status(403).json({ message: 'Not authorized to modify this ticket' });
    }

    // Role mapping for level assignment
    const roleMap = {
      L1: 'L2',
      L2: 'L3',
      L3: 'L4'
    };

    const newLevel = roleMap[role];
    if (!newLevel) {
      return res.status(400).json({ message: `${role} cannot assign a new level` });
    }

    // If the new level already exists, prevent duplicates
    if (ticket.levels.includes(newLevel)) {
      return res.status(400).json({ message: `Ticket already assigned to ${newLevel}` });
    }

    // Add new level
    ticket.levels.push(newLevel);

    // Build message
    let updateMessage = `Assigned ticket to ${newLevel}`;
    if (message && message.trim()) {
      updateMessage += `\n${message.trim()}`;
    }

    // Create update entry
    const updateEntry = {
      message: updateMessage,
      employee_id: email,
      updated_at: new Date(),
      status: ticket.status,        
      severity: ticket.severity,
    };

    ticket.updates.push(updateEntry);

    // Ensure contributor is tracked
    if (!ticket.contributors.includes(email)) {
      ticket.contributors.push(email);
    }

    ticket.updated_at = new Date();

    await ticket.save();

    res.status(200).json({
      message: `Level ${newLevel} added successfully`
    });
  } catch (error) {
    console.error('Error in adding level on ticket:', error);
    res.status(500).json({ message: 'Server error' });    
  }
}

const showList = async (req, res) => {
  try {    
    const { role } = req.user;
    const filters = { levels: role }; // always filter by user's role

    // Optional query filters
    const { createdBy, log_refs, status, severity, contributors, startDate, endDate, title } = req.body;

    if (createdBy) filters.createdBy = createdBy;
    if (log_refs && log_refs.length > 0) filters.log_refs = { $in: Array.isArray(log_refs) ? log_refs : [log_refs] };
    if (status && status.length > 0) filters.status = { $in: Array.isArray(status) ? status : [status] };
    if (severity && severity.length > 0) filters.severity = { $in: Array.isArray(severity) ? severity : [severity] };
    if (contributors) filters.contributors = { $in: Array.isArray(contributors) ? contributors : [contributors] };
    if (startDate || endDate) {
      filters.created_at = {};
      if (startDate) filters.created_at.$gte = new Date(startDate);
      if (endDate) filters.created_at.$lte = new Date(endDate);
    }
    if (title) filters.$text = { $search: title }; // 'i' = case-insensitive

    // Fetch tickets with only required fields
    const tickets = await Ticket.find(filters)
      .select('ticketID title created_at status severity createdBy updates')
      .sort({ created_at: -1 }); // newest first
      // .limit(limit) // for pagination
      // .skip(skip);
      console.log(filters);
      

    const response = tickets.map(t => ({
      ticketID: t.ticketID,
      title: t.title,
      created_at: t.created_at,
      no_of_comments: t.updates.length,
      status: t.status,
      severity: t.severity,
      createdBy: t.createdBy
    }));

    res.status(200).json({ tickets: response });
  } catch (error) {
    console.error('Error in list of ticket:', error);
    res.status(500).json({ message: 'Server error' });    
  }
}

const viewTicket = async (req, res) => {
  try {    
    const { role } = req.user;
    const { ticketID } = req.params;
    
    if (!ticketID) {
      return res.status(400).json({ message: 'ticketID is required' });
    }

    const ticket = await Ticket.findOne({ ticketID }).select('-_id -__v'); // exclude MongoDB _id and __v
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    // Check if user's role is in ticket levels
    if (!ticket.levels.includes(role)) {
      return res.status(403).json({ message: 'Not authorized to view this ticket' });
    }

    res.status(200).json({
      id: ticket.ticketID,
      title: ticket.title,
      description: ticket.description,
      files: ticket.files,
      reporter: ticket.createdBy,
      log_refs: ticket.log_refs,
      status: ticket.status,
      severity: ticket.severity,
      updates: ticket.updates,
      levels: ticket.levels,
      contributors: ticket.contributors,
      createdAt: ticket.created_at      
    });
  } catch (error) {
    console.error('Error in showing ticket:', error);
    res.status(500).json({ message: 'Server error' });    
  }
}

module.exports = {raiseTicket, uploadFile, updateTicket, addLevel, showList, viewTicket}