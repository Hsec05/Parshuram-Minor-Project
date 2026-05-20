// const { v4: uuidv4 } = require('uuid');
// const UserModel = require('../models/user-model');
// const redisClient = require('../util/redisConnect');

// const SESSION_EXPIRY = 60 * 60 * 6; // 6 hours

// const addAdmin = async (req, res) => {
//   try {
//     const { name, email, role } = req.body;
//     if (role !== 'admin' && role !== 'superadmin') {
//       return res.status(400).json({ message: 'Role must be admin or superadmin' });
//     }

//     const existing = await UserModel.findOne({ email });
//     if (existing) {
//       return res.status(400).json({ message: 'User already exists' });
//     }

//     const password_hash = await UserModel.hashPass('admin');
//     const newUser = await UserModel.create({ name, email, password_hash, role });
//     res.json({ message: 'Admin created successfully', userId: newUser._id });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: 'Server error' });
//   }
// };

// const login = async (req, res) => {
//   try {
//     const { email, password } = req.body;
//     const user = await UserModel.findOne({ email });

//     if (!user) {
//       return res.status(401).json({ message: 'Unauthorized' });
//     }

//     const match = await UserModel.verifyPass(password, user.password_hash); 
//     if (!match) return res.status(401).json({ message: 'Invalid password' });

//     // Delete existing sessions for this email
//     const key = `sessionsByEmail:${user.email}`;
//     const oldSessionIds = await redisClient.sMembers(key);

//     if (oldSessionIds && oldSessionIds.length > 0) {
//       // Delete each session hash
//       const pipeline = redisClient.multi();
//       oldSessionIds.forEach(sid => pipeline.del(`session:${sid}`));
//       // Delete the set itself
//       pipeline.del(key);
//       await pipeline.exec();
//     }

//     const sessionId = uuidv4();

//     // Store session data in Redis hash for fast access
//     const sessionKey = `session:${sessionId}`;
//     await redisClient.hSet(sessionKey, {
//       emailId: user.email,
//       level: user.role
//     });
//     await redisClient.expire(sessionKey, SESSION_EXPIRY);

//     // Maintain an index of sessions for each email
//     const emailKey = `sessionsByEmail:${user.email}`;
//     await redisClient.sAdd(emailKey, sessionId);
//     await redisClient.expire(emailKey, SESSION_EXPIRY);

//     // Set the session ID in a cookie
//     res.cookie('sessionId', sessionId, {
//         httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
//         secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
//         maxAge: SESSION_EXPIRY * 1000 // Cookie expiry in milliseconds
//     });

//     res.json({ message: 'Login successful', sessionId });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: 'Server error' });
//   }
// };

// const logout = async (req, res) => {
//   try {
//     const { sessionId, email } = req.user;

//     // Keys in Redis
//     const sessionKey = `session:${sessionId}`;
//     const emailKey = `sessionsByEmail:${email}`;

//     // Remove session hash
//     await redisClient.del(sessionKey);

//     // Remove this session from the email's set
//     await redisClient.sRem(emailKey, sessionId);

//     // If no sessions left for this email, remove the email key completely
//     const remainingSessions = await redisClient.sCard(emailKey);
//     if (remainingSessions === 0) {
//       await redisClient.del(emailKey);
//     }

//     res.json({ message: 'Logout successful' });
//   } catch (err) {
//     console.error('Error logging out:', err);
//     res.status(500).json({ message: 'Server error' });
//   }
// };
// const addMember = async (req, res) => {
//   try {
//     if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
//       return res.status(403).json({ message: 'Access denied' });
//     }

//     const { name, email, password, role } = req.body;
//     if (!name || !email || !password || !role) {
//       return res.status(400).json({ message: 'All fields are required' });
//     }

//     const allowedRoles = ['L1', 'L2', 'L3', 'L4'];
//     if (!allowedRoles.includes(role)) {
//       return res.status(400).json({ message: 'Invalid role' });
//     }

//     const hashedPassword = await UserModel.hashPass(password);
//     const newUserId = await UserModel.create({ name, email, password_hash: hashedPassword, role });
//     res.status(201).json({ message: 'User added successfully', userId: newUserId._id });
//   } catch (err) {
//     console.error('Error adding member:', err);
//     if (err.code === 11000) {
//       return res.status(400).json({ message: 'Email already exists' });
//     }
//     res.status(500).json({ message: 'Server error' });
//   }
// };

// module.exports = {addAdmin, login, addMember, logout}
const { v4: uuidv4 } = require('uuid');
const UserModel = require('../models/user-model');
const redisClient = require('../util/redisConnect');


const SESSION_EXPIRY = 60 * 60 * 6; // 6 hours

// --- NEW FUNCTION: Fetch user details for frontend initialization ---
const getUserDetails = async (req, res) => {
  try {
    // The auth middleware already populated req.user with email and role from Redis.
    const userEmail = req.user.email;
    
    // Fetch remaining details from MongoDB
    const user = await UserModel.findOne({ email: userEmail }, 'name email role').lean();

    if (!user) {
      // Log the issue and invalidate session if user doesn't exist in MongoDB
      console.error(`User ${userEmail} found in Redis but not MongoDB.`);
      return res.status(401).json({ message: 'User profile not found. Please re-login.' });
    }

    // Send the data back to the frontend
    res.json({
        email: user.email,
        role: user.role,
        name: user.name,
        // Ensure standard fields are always returned, even if mocked/defaulted
        employeeId: user.name.toUpperCase().substring(0, 3) + user._id.toString().slice(-4), // Simple mock ID
        department: 'Security Operations',
    });
  } catch (err) {
    console.error('Error fetching user details:', err);
    res.status(500).json({ message: 'Failed to retrieve user data.' });
  }
};
// --- END NEW FUNCTION ---

const addAdmin = async (req, res) => {
  try {
    const { name, email, role } = req.body;
    if (role !== 'admin' && role !== 'superadmin') {
      return res.status(400).json({ message: 'Role must be admin or superadmin' });
    }

    const existing = await UserModel.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const password_hash = await UserModel.hashPass('admin');
    const newUser = await UserModel.create({ name, email, password_hash, role });
    res.json({ message: 'Admin created successfully', userId: newUser._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await UserModel.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const match = await UserModel.verifyPass(password, user.password_hash);
    if (!match) return res.status(401).json({ message: 'Invalid password' });

    // Delete existing sessions for this email
    const key = `sessionsByEmail:${user.email}`;
    const oldSessionIds = await redisClient.sMembers(key);

    if (oldSessionIds && oldSessionIds.length > 0) {
      // Delete each session hash
      const pipeline = redisClient.multi();
      oldSessionIds.forEach(sid => pipeline.del(`session:${sid}`));
      // Delete the set itself
      pipeline.del(key);
      await pipeline.exec();
    }

    const sessionId = uuidv4();

    // Store session data in Redis hash for fast access
    const sessionKey = `session:${sessionId}`;
    await redisClient.hSet(sessionKey, {
      emailId: user.email,
      level: user.role
    });
    await redisClient.expire(sessionKey, SESSION_EXPIRY);

    // Maintain an index of sessions for each email
    const emailKey = `sessionsByEmail:${user.email}`;
    await redisClient.sAdd(emailKey, sessionId);
    await redisClient.expire(emailKey, SESSION_EXPIRY);
    
    res.json({ message: 'Login successful', sessionId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

const logout = async (req, res) => {
  try {
    const { sessionId, email } = req.user;

    // Keys in Redis
    const sessionKey = `session:${sessionId}`;
    const emailKey = `sessionsByEmail:${email}`;

    // Remove session hash
    await redisClient.del(sessionKey);

    // Remove this session from the email's set
    await redisClient.sRem(emailKey, sessionId);

    // If no sessions left for this email, remove the email key completely
    const remainingSessions = await redisClient.sCard(emailKey);
    if (remainingSessions === 0) {
      await redisClient.del(emailKey);
    }

    res.json({ message: 'Logout successful' });
  } catch (err) {
    console.error('Error logging out:', err);
    res.status(500).json({ message: 'Server error' });
  }
};

const addMember = async (req, res) => {
  try {
    // Only admin or superadmin can add new members
    if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const allowedRoles = ['L1', 'L2', 'L3', 'L4'];
    if (!allowedRoles.includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }

    // Hash password with salt rounds = 15
    const hashedPassword = await UserModel.hashPass(password);

    // Save to DB
    const newUserId = await UserModel.create({ name, email, password_hash: hashedPassword, role });

    res.status(201).json({ message: 'User added successfully', userId: newUserId._id });
  } catch (err) {
    console.error('Error adding member:', err);
    if (err.code === 11000) {
      return res.status(400).json({ message: 'Email already exists' });
    }
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = {addAdmin, login, addMember, logout, getUserDetails} // <-- EXPORT NEW FUNCTION HERE
