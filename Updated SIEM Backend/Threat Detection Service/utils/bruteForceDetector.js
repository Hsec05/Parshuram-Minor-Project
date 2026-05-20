// Simple in-memory brute force detector using sliding window
// For production use Redis or another shared store to keep state across instances.

const WINDOW_MS = Number(process.env.BRUTE_FORCE_WINDOW_MS || 5 * 60 * 1000);
const THRESHOLD = Number(process.env.BRUTE_FORCE_THRESHOLD || 5);

// Map keyed by IP or username: { key: [ timestamps ] }
const attempts = new Map();

// record an attempt, return true if threshold exceeded -> alert
function registerAttempt(key, timestamp = Date.now()) {
  if (!key) return false;
  const arr = attempts.get(key) || [];
  // remove old
  const cutoff = timestamp - WINDOW_MS;
  const newArr = [...arr.filter(ts => ts > cutoff), timestamp];
  attempts.set(key, newArr);
  return newArr.length >= THRESHOLD;
}

// optional: clear state for a key (cooldown)
function clearAttempts(key) {
  attempts.delete(key);
}

module.exports = { registerAttempt, clearAttempts };
