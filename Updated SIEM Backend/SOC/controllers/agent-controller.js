const Agent = require('../models/agent');
const WindowsLog = require('../models/windows_logs');
const WindowsThreat = require('../models/windows_threats');

const listAgents = async (req, res) => {
  try {
    const filters = {};

    if (req.query.active) {
      filters.active = req.query.active === 'true';
    }

    const agents = await Agent.find(filters).lean();

    const agentsWithLogs = await Promise.all(
      agents.map(async (a) => {
        // ✅ Fetch latest log for this agent
        const latestLog = await WindowsLog.findOne(
          { agent_id: a.agentId },
          { _id: 0, __v: 0 }
        )
          .sort({ timeCreated: -1 })
          .lean();

        const threatCount = await WindowsThreat.countDocuments({ agent_id: a.agentId });

        return {
          id: a.agentId,
          name: latestLog?.computer,
          ...a,
          ip: latestLog?.ip || null,
          os: latestLog?.os || null,
          status: a.active? "active": "disconnected",
          computerName: latestLog?.computer || null,
          lastSeen: latestLog?.timeCreated || null,
          threatsCount: threatCount || 0,
          location: "Vadodara",

          // remove unwanted fields
          _id: undefined,
          timestamp: undefined
        };
      })
    );

    return res.status(200).json({
      success: true,
      count: agents.length,
      agents: agentsWithLogs
    });

  } catch (error) {
    console.error("Error fetching agents:", error);
    return res.status(500).json({
      success: false,
      message: "Server error while fetching agents"
    });
  }
};

module.exports = {
  listAgents
};
