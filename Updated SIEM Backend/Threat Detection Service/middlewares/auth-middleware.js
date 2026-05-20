const redisClient = require('../util/redisConnect');

const authAgent = async (req, res, next) => {
  try {
    const agentToken = req.header('x-session');
    if (!agentToken) {
      return res.status(401).json({ message: 'Provide auth token first' });
    }

    // Expected format: "Bearer <sessionId>"
    // const sessionId = agentToken.replace('Bearer', '').trim();
    // if (!sessionId) {
    //   return res.status(401).json({ message: 'Invalid session token' });
    // }

    // Check Redis for session
    const sessionKey = `agent_session:${agentToken}`;
    const sessionData = await redisClient.hGetAll(sessionKey);
    console.log(sessionData);
    

    if (!sessionData || Object.keys(sessionData).length === 0) {
      return res.status(401).json({ message: 'Session expired or invalid' });
    }

    // Attach user data to request
    req.agent = sessionData.agentId;

    next();
  } catch (err) {
    console.error('Error in auth middleware:', err);
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = authAgent;