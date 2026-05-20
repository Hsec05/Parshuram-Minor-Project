// const redisClient = require('../util/redisConnect');

// const authUser = async (req, res, next) => {
//   try {
//     const userToken = req.header('Authorization');
//     if (!userToken) {
//       return res.status(401).json({ message: 'Please login first' });
//     }

//     // Expected format: "Bearer <sessionId>"
//     const sessionId = userToken.replace('Bearer', '').trim();
//     if (!sessionId) {
//       return res.status(401).json({ message: 'Invalid session token' });
//     }

//     // Check Redis for session
//     const sessionKey = `session:${sessionId}`;
//     const sessionData = await redisClient.hGetAll(sessionKey);

//     if (!sessionData || Object.keys(sessionData).length === 0) {
//       return res.status(401).json({ message: 'Session expired or invalid' });
//     }

//     // Attach user data to request
//     req.user = {
//       email: sessionData.emailId,
//       role: sessionData.level,
//       sessionId
//     };

//     next();
//   } catch (err) {
//     console.error('Error in auth middleware:', err);
//     res.status(500).json({ message: 'Server error' });
//   }
// };

// module.exports = authUser;
const redisClient = require('../util/redisConnect');

const authUser = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    console.log(authHeader);
    
    if (!authHeader) {
      return res.status(401).json({ message: 'Authorization header missing' });
    }

    // Expected format: "Bearer <sessionId>"
    const parts = authHeader.split(' ');
    
    // Check if the format is "Bearer <token>"
    if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
        return res.status(401).json({ message: 'Invalid token format. Must be Bearer <token>' });
    }

    const sessionId = parts[1].trim();

    // Check Redis for session
    const sessionKey = `session:${sessionId}`;
    const sessionData = await redisClient.hGetAll(sessionKey);

    if (!sessionData || Object.keys(sessionData).length === 0) {
      return res.status(401).json({ message: 'Session expired or invalid' });
    }

    // Attach user data to request
    req.user = {
      email: sessionData.emailId,
      role: sessionData.level,
      sessionId
    };

    next();
  } catch (err) {
    console.error('Error in auth middleware:', err);
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = authUser;
