// ruleEngine.js
const windowsRules = require('../rules/windowsRules');
const statefulRules = require('../rules/windowsStatefulRules');
const Policy = require('../models/policy');
const { registerAttempt } = require('./bruteForceDetector');

// ---------- In-memory state store (replace with Redis for production) ----------
const stateStore = new Map();

function getState(key) {
  const entry = stateStore.get(key);
  if (!entry) return null;
  if (entry.expiresAt && Date.now() > entry.expiresAt) {
    stateStore.delete(key);
    return null;
  }
  return entry.value;
}

function setState(key, value, ttlSeconds = null) {
  const expiresAt = ttlSeconds ? Date.now() + ttlSeconds * 1000 : null;
  stateStore.set(key, { value, expiresAt });
}

function incState(key, amount = 1, ttlSeconds = null) {
  const cur = getState(key) || 0;
  const newVal = cur + amount;
  setState(key, newVal, ttlSeconds);
  return newVal;
}

// Cleanup expired states every minute
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of stateStore.entries()) {
    if (v.expiresAt && v.expiresAt <= now) stateStore.delete(k);
  }
}, 60 * 1000);

// Context object for stateful rules and DB policies
const stateContext = {
  get: (key) => getState(key),
  set: (key, val, ttlSeconds = null) => setState(key, val, ttlSeconds),
  inc: (key, amount = 1, ttlSeconds = null) => incState(key, amount, ttlSeconds),
};

// Convert string like "10m" -> seconds
function parseTimeWindow(str) {
  if (!str) return null;
  const match = str.match(/(\d+)([smh])/);
  if (!match) return null;
  const val = parseInt(match[1], 10);
  switch (match[2]) {
    case 's': return val;
    case 'm': return val * 60;
    case 'h': return val * 3600;
    default: return null;
  }
}

/**
 * analyzeWindowsLog
 * - decoded: parsed Windows event log
 * Returns: array of matched rules { id, description, severity, meta? }
 */
async function analyzeWindowsLog(decoded) {
  const matches = [];

  // ---------- 1) Stateless rules ----------
  for (const rule of windowsRules) {
    try {
      const matched = await Promise.resolve(rule.match(decoded));
      if (matched) {
        matches.push({
          id: rule.id,
          description: rule.description,
          severity: rule.severity || 'medium',
          meta: rule.meta || undefined
        });
      }
    } catch (e) {
      console.error('Rule error (stateless)', rule.id, e);
    }
  }

  // ---------- 2) Stateful rules ----------
  for (const rule of statefulRules) {
    try {
      const res = await Promise.resolve(rule.match(decoded, stateContext));
      if (res) {
        if (typeof res === 'object') {
          matches.push({
            id: res.id || rule.id,
            description: res.description || rule.description,
            severity: res.severity || rule.severity || 'medium',
            meta: res.meta || rule.meta || undefined
          });
        } else {
          matches.push({
            id: rule.id,
            description: rule.description,
            severity: rule.severity || 'medium',
            meta: rule.meta || undefined
          });
        }
      }
    } catch (e) {
      console.error('Rule error (stateful)', rule.id, e);
    }
  }

  // ---------- 3) DB Policies (user-defined) ----------
  let dbPolicies = [];
  try {
    dbPolicies = await Policy.find();
  } catch (e) {
    console.error("Error fetching DB policies", e);
  }

  for (const rule of dbPolicies) {
    try {
      const cond = rule.conditions;
      if (!cond || !decoded.eventType) continue;

      if (decoded.eventType === cond.eventType) {
        // Track state per user/IP/global
        const key = `${decoded.eventId}:${decoded.user || decoded.ip || 'global'}`;
        const count = stateContext.inc(key, 1, parseTimeWindow(cond.timeWindow));

        if (count >= (cond.threshold || 1)) {
          matches.push({
            id: rule._id,
            description: rule.name,
            severity: 'high',
            meta: { source: 'db-policy', actions: rule.actions }
          });
          // Reset counter after triggering
          stateContext.set(key, 0, parseTimeWindow(cond.timeWindow));
        }
      }
    } catch (e) {
      console.error('DB policy error', rule._id, e);
    }
  }

  // ---------- 4) Brute force detection ----------
  if (decoded.eventId === 4625) {
    const ipMatch = (decoded.description || '').match(/(\d{1,3}\.){3}\d{1,3}/);
    const usernameMatch = (decoded.description || '').match(/Account Name:\s*([\w$\\.-]+)/i)
      || (decoded.description || '').match(/User Name:\s*([\w$\\.-]+)/i);

    const ip = ipMatch ? ipMatch[0] : null;
    const user = usernameMatch ? usernameMatch[1] : null;

    try {
      if (ip && registerAttempt(`ip:${ip}`)) {
        matches.push({
          id: 'bruteforce-ip-threshold',
          description: `Brute force suspected from IP ${ip}`,
          severity: 'high'
        });
      }
      if (user && registerAttempt(`user:${user}`)) {
        matches.push({
          id: 'bruteforce-user-threshold',
          description: `Brute force suspected for user ${user}`,
          severity: 'high'
        });
      }
    } catch (e) {
      console.error('Bruteforce detection error', e);
    }
  }

  return matches;
}

module.exports = { analyzeWindowsLog, stateContext };
