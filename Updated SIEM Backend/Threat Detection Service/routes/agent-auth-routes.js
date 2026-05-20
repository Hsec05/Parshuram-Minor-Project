const express = require('express');
const router = express.Router();
const {agentRegisterRequest, agentLogin, allowAgent, otp} = require('../controllers/agent-auth-controller');

router.post('/register', agentRegisterRequest);
router.post('/login', agentLogin);

module.exports = router;