// const express = require('express');
// const router = express.Router();
// const authUser = require('../middlewares/auth-middleware');
// const {authLimiter} = require('../middlewares/rate-limiter');
// const dashboardController = require('../controllers/dashboard-controller');

// // Counts (dashboard stats)
// router.get('/stats', authUser, authLimiter, dashboardController.getCounts);

// // Graph (time-based threats aggregation)
// // router.get('/trends', authUser, authLimiter, dashboardController.getThreatsGraph); // Correctly renamed to `trends`
// // router.get('/by-device', authUser, authLimiter, dashboardController.threatsByOS) // Correctly renamed to `by-device`
// // router.get('/recent', authUser, authLimiter, dashboardController.getRecentThreats); // New endpoint
// // router.get('/notifications', authUser, authLimiter, dashboardController.getNotifications); // New endpoint
// router.get('/stats', authUser, authLimiter, dashboardController.getCounts);
// router.get('/trends', authUser, authLimiter, dashboardController.getThreatsGraph);
// router.get('/by-device', authUser, authLimiter, dashboardController.threatsByOS);
// router.get('/recent', authUser, authLimiter, dashboardController.getRecentThreats);
// router.get('/notifications', authUser, authLimiter, dashboardController.getNotifications);
// module.exports = router
const express = require('express');
const router = express.Router();
const authUser = require('../middlewares/auth-middleware');
const {authLimiter} = require('../middlewares/rate-limiter');
const dashboardController = require('../controllers/dashboard-controller');

// Analyst Dashboard APIs (Protected)
router.get('/stats', authUser, authLimiter, dashboardController.getCounts);
router.get('/trends', authUser, authLimiter, dashboardController.getThreatsGraph);
router.get('/by-device', authUser, authLimiter, dashboardController.threatsByOS);
router.get('/recent', authUser, authLimiter, dashboardController.getRecentThreats);
router.get('/notifications', authUser, authLimiter, dashboardController.getNotifications);

module.exports = router;