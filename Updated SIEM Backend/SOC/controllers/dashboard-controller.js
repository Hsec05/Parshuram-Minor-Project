const Ticket = require('../models/ticket-model');
const WindowsThreat = require('../models/windows_threats');

const getCounts = async (req, res) => {
  try {
    const totalThreats = await WindowsThreat.countDocuments();
    // Correctly query the Ticket model for ticket statuses
    const processingTickets = await Ticket.countDocuments({
      status: { $in: ['open', 'under_review'] } // Changed from 'under_review' to 'working' based on ticket-model.js enums
    });
    const resolvedTickets = await Ticket.countDocuments({ status: 'closed' });
    const criticalThreats = await WindowsThreat.countDocuments({ severity: 'critical' });

    res.status(200).json({
      totalThreats,
      processingTickets,
      resolvedTickets,
      criticalThreats
    });
  } catch (error) {
    console.error("Error fetching counts:", error);
    res.status(500).json({ message: "Server error" });
  }
};

const getThreatsGraph = async (req, res) => {
  try {
    let { startDate, endDate, interval } = req.query;

    if (!startDate || !endDate) {
      return res.status(400).json({ message: "startDate and endDate are required" });
    }
    startDate = new Date(startDate);
    endDate = new Date(endDate);

    let dateFormat;
    switch (interval) {
        case "5m": case "30m": case "hour":
            dateFormat = "%Y-%m-%dT%H";
            break;
        case "day":
            dateFormat = "%Y-%m-%d";
            break;
        case "month":
            dateFormat = "%Y-%m";
            break;
        case "year":
            dateFormat = "%Y";
            break;
        default:
            dateFormat = "%Y-%m-%dT%H"; // Fallback to hourly
    }
    
    // Aggregate threats and resolved threats to show on a graph
    const data = await WindowsThreat.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate, $lte: endDate }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: dateFormat, date: "$timestamp" } },
          threats: { $sum: 1 },
          resolved: {
              $sum: { $cond: [{ $eq: ["$status", "resolved"] }, 1, 0] }
          }
        }
      },
      { $sort: { _id: 1 } },
      {
          $project: {
              _id: 0,
              name: "$_id",
              threats: "$threats",
              resolved: "$resolved"
          }
      }
    ]);
    res.status(200).json(data);
  } catch (error) {
    console.error("Error in threats graph:", error);
    res.status(500).json({ message: "Server error" });
  }
};

const threatsByOS = async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const match = {};

    if (startDate && endDate) {
      // Corrected the field name from `time` to `timestamp`
      match.timestamp = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }

    const result = await WindowsThreat.aggregate([
      { $match: match },
      {
        $group: {
          _id: "$os",
          value: { $sum: 1 }
        }
      },
      { $sort: { value: -1 } }
    ]);

    // Format for pie chart
    const formattedResult = result.map(item => ({
      name: item._id,
      value: item.value,
      // You can add colors here if you wish
      color: item._id === 'windows' ? '#3B82F6' : '#10B981'
    }));

    res.status(200).json(formattedResult);
  } catch (error) {
    console.error('Error in threatsByOS:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// New function to get recent threats from the database
const getRecentThreats = async (req, res) => {
  try {
      const recentThreats = await WindowsThreat.find({})
          .sort({ timestamp: -1 })
          .limit(10);
      res.status(200).json(recentThreats);
  } catch (err) {
      console.error('Error fetching recent threats:', err);
      res.status(500).json({ error: 'Failed to fetch recent threats' });
  }
};

// New function to get recent notifications (from threats or logs)
const getNotifications = async (req, res) => {
  try {
      const notifications = await WindowsThreat.find({})
          .sort({ timestamp: -1 })
          .limit(15);
      res.status(200).json(notifications);
  } catch (err) {
      console.error('Error fetching notifications:', err);
      res.status(500).json({ error: 'Failed to fetch notifications' });
  }
};

module.exports = { getCounts, getThreatsGraph, threatsByOS, getRecentThreats, getNotifications };