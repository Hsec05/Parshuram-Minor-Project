const UserModel = require('../models/user-model');
const AgentModel = require('../../Threat Detection Service/models/agent'); // Assuming this path based on file structure
const WindowsThreat = require('../models/windows_threats');
const Policy = require('../../Threat Detection Service/models/policy'); 
const Ticket = require('../models/ticket-model');

// Fetches all users for the User Management table
const getAllUsers = async (req, res) => {
    try {
        // Fetch all users, selecting only necessary fields for the Admin table
        const users = await UserModel.find({}, 'name email role lastLogin createdAt').lean(); 

        // Map data to expected frontend structure
        const formattedUsers = users.map(user => ({
            id: user._id,
            email: user.email,
            role: user.role, // Assuming role mapping: superadmin/admin -> admin, L1/L2/L3/L4 -> analyst/viewer
            employeeId: user.name.toUpperCase().substring(0, 3) + user._id.toString().slice(-4), // Simple mock employee ID based on name/ID
            status: 'active', // Placeholder: Actual status logic would check lastLogin or session
            lastLogin: user.updatedAt || user.createdAt,
            createdAt: user.createdAt
        }));

        res.status(200).json(formattedUsers);
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).json({ message: 'Error fetching user list.' });
    }
};

// Fetches system-wide statistics for the overview cards
const getSystemStats = async (req, res) => {
  try {
    // Ensure connection is ready
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ message: 'Database not connected yet' });
    }

    console.log('Fetching totalUsers...');
    const totalUsers = await UserModel.countDocuments() || 0;

    console.log('Fetching activeUsers...');
    const activeUsers = await UserModel.countDocuments({ lastLoginAt: { $gte: new Date(Date.now() - 24*60*60*1000) } }) || 0;

    console.log('Fetching totalAgents...');
    const totalAgents = await AgentModel.countDocuments() || 0;

    console.log('Fetching activeAgents...');
    const activeAgents = await AgentModel.countDocuments({ active: true }) || 0;

    console.log('Fetching totalPolicies...');
    const totalRules = await PolicyModel.countDocuments() || 0;

    console.log('Fetching totalTickets...');
    const totalTickets = await TicketModel.countDocuments() || 0;

    // Storage usage placeholder
    const storageUsed = '2.4 TB';
    const storageTotal = '5.0 TB';

    res.status(200).json({
      totalUsers,
      activeUsers,
      totalAgents,
      activeAgents,
      totalRules,
      activeRules: totalRules, // simplification
      totalTickets,
      storageUsed,
      storageTotal
    });
  } catch (err) {
    console.error('Error fetching system stats:', err);
    res.status(500).json({ message: 'Error fetching system statistics.' });
  }
};
// Fetches recent system and security activity logs
const getRecentActivity = async (req, res) => {
    try {
        // Fetch recent updates from Tickets
        const ticketUpdates = await Ticket.aggregate([
            {$unwind: "$updates"},
            {$sort: {"updates.updated_at": -1}},
            {$limit: 5},
            {
                $project: {
                    _id: 0,
                    message: "$updates.message",
                    timestamp: "$updates.updated_at",
                    type: "Ticket Update",
                    severity: "$updates.severity",
                    email: "$updates.employee_id"
                }
            }
        ]).limit(5).exec();

        // Fetch recent threats (highest severity first)
        const recentThreats = await WindowsThreat.find({}, 'message timestamp severity agent_id')
            .sort({ timestamp: -1 })
            .limit(5)
            .lean();

        // Combine and sort
        let combinedActivity = [
            ...ticketUpdates,
            ...recentThreats.map(t => ({
                message: t.message,
                timestamp: t.timestamp,
                type: "Threat Detected",
                severity: t.severity,
                email: t.agent_id // Using agent ID as identifier for now
            }))
        ];

        combinedActivity.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

        res.status(200).json(combinedActivity.slice(0, 10)); // Top 10 activities

    } catch (err) {
        console.error('Error fetching recent activity:', err);
        res.status(500).json({ message: 'Error fetching recent activity.' });
    }
};

module.exports = {
    getAllUsers,
    getSystemStats,
    getRecentActivity
};
