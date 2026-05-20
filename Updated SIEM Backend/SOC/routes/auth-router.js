const express = require('express');
const router = express.Router();

const authController = require('../controllers/auth-controller');
const authUser = require('../middlewares/auth-middleware');
const {authLimiter, addMemberLimiter} = require('../middlewares/rate-limiter');

router.get('/user', authUser, authController.getUserDetails);
router.post('/add-admin', authLimiter, authController.addAdmin);
router.post('/login', authLimiter, authController.login);
router.post('/logout', authUser, authLimiter, authController.logout);

// router.route('/pass/reset').post();

router.post('/add-member', authUser, addMemberLimiter, authController.addMember);
module.exports = router
// const express = require('express');
// const router = express.Router();

// const authController = require('../controllers/auth-controller');
// const authUser = require('../middlewares/auth-middleware');
// const {authLimiter, addMemberLimiter} = require('../middlewares/rate-limiter');

// router.post('/add-admin', authLimiter, authController.addAdmin);
// router.post('/login', authLimiter, authController.login);
// router.post('/logout', authUser, authLimiter, authController.logout);

// // Route for the frontend to retrieve user details (role) after logging in
// router.get('/user', authUser, authController.getUserDetails);

// router.post('/add-member', authUser, addMemberLimiter, authController.addMember);
// module.exports = router