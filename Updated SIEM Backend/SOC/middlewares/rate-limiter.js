const rateLimit = require('express-rate-limit');

const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 50, // 5 attempts per IP
  message: { error: "Too many login attempts. Try again in 1 minute." },
  standardHeaders: true, // Return rate limit info in the RateLimit-* headers
  legacyHeaders: false, // Disable the X-RateLimit-* headers
});

const addMemberLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 15,
  message: { error: "Rate limit exceeded. Please slow down." },
  standardHeaders: true, 
  legacyHeaders: false, 
});

module.exports = {authLimiter, addMemberLimiter};