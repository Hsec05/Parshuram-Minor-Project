const express = require('express');
const router = express.Router();
const authUser = require('../middlewares/auth-middleware');
const {authLimiter} = require('../middlewares/rate-limiter');
const ticketController = require('../controllers/ticket-controller');

router.post('/raise', authUser, authLimiter, ticketController.raiseTicket);
router.post('/update', authUser, authLimiter, ticketController.updateTicket);
router.post('/upload', authUser, authLimiter, ticketController.uploadFile);
router.post('/addLevel', authUser, authLimiter, ticketController.addLevel);
router.get('/view/:ticketID', authUser, authLimiter, ticketController.viewTicket);
router.post('/list', authUser, ticketController.showList);  

module.exports = router