const express = require('express');
const router = express.Router();
const authUser = require('../middlewares/auth-middleware');
const {authLimiter} = require('../middlewares/rate-limiter');
const logController = require('../controllers/log-controller');

router.post('/listLogs',  logController.listLogs);
router.post('/listThreats',  logController.listThreats);
router.get('/viewLog/:logID',  logController.viewLog);
router.get('/viewThreat/:threatID',  logController.viewThreat);
router.post('/markFalsePositive', logController.markFalsePositive);

module.exports = router