const express = require('express');
const router = express.Router();
const authUser = require('../middlewares/auth-middleware');
const { authLimiter } = require('../middlewares/rate-limiter');
const adminController = require('../controllers/admin-controller');

// All admin routes should be protected and rate limited
// Authentication ensures only logged-in users can access this page data.

router.get('/users', authUser, /*authLimiter,*/ adminController.getAllUsers);
router.get('/stats', authUser, /*authLimiter,*/ adminController.getSystemStats);
router.get('/activity', authUser, /*authLimiter,*/ adminController.getRecentActivity);

module.exports = router;
