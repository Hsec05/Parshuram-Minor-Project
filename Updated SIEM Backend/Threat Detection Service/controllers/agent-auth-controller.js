const { v4: uuidv4 } = require('uuid');
const agentModel = require('../models/agent');
const crypto = require('crypto');
const redisClient = require('../util/redisConnect');

const agentRegisterRequest = async (req, res) => {
  
  try {
    const { cpuId, motherboardId, diskId } = req.body;
    if(!cpuId || !motherboardId || !diskId){
      return res.status(401).json({ message: 'Provide CPU Id, Motherboard Id and Disk Id first.' });
    }

    const fingerprint = crypto.createHash('sha256').update(`${cpuId}-${motherboardId}-${diskId}`).digest('hex');

    // Check if already approved
    const existingAgent = await agentModel.findOne({ fingerprint });
    if (existingAgent) {
      const agentId = existingAgent.agentId;

      return res.json({ message: 'Registration successful', agentId: agentId });
    }

    // Create agent record
    const agentId = uuidv4();
    const newAgent = new agentModel({
      agentId,
      fingerprint,
      cpuId: cpuId,
      motherboardId: motherboardId,
      diskId: diskId,
      active: true
    });
    await newAgent.save();

    return res.json({ message: 'Registration successful', agentId: agentId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const agentLogin = async (req, res) => {
  try {
    const { agentId, cpuId, motherboardId, diskId } = req.body;
    
    if (!agentId || !cpuId || !motherboardId || !diskId) {
      return res.status(400).json({ message: 'Missing required fields.' });
    }

    const fingerprint = crypto.createHash('sha256').update(`${cpuId}-${motherboardId}-${diskId}`).digest('hex');

    const agent = await agentModel.findOne({ agentId, fingerprint });
    if (!agent) {
      return res.status(401).json({ message: 'Unauthorized: Agent not found or fingerprint mismatch' });
    }

    // Clean up existing sessions for this agent
    const sessionIndexKey = `sessionByAgentId:${agentId}`;
    const oldSessionId = await redisClient.get(sessionIndexKey);

    if (oldSessionId) {
      // Delete the old session data
      await redisClient.del(`agent_session:${oldSessionId}`);
      await redisClient.del(sessionIndexKey);
    }

    const session = uuidv4();

    // Store session data in Redis hash for fast access
    const sessionKey = `agent_session:${session}`;
    await redisClient.hSet(sessionKey, {
      agentId: agent.agentId
    });
    await redisClient.set(sessionIndexKey, session);

    agent.lastLoginAt = new Date();
    agent.active = true;
    agent.save();

    res.json({ message: 'Login successful', session: session });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = {agentRegisterRequest, agentLogin}