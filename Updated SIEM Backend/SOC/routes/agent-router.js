const express = require('express');
const router = express.Router();
const authUser = require('../middlewares/auth-middleware');
const { authLimiter } = require('../middlewares/rate-limiter');
const agentController = require('../controllers/agent-controller');

// All admin routes should be protected and rate limited
// Authentication ensures only logged-in users can access this page data.

router.get('/list', authUser, authLimiter, agentController.listAgents);

module.exports = router;
