// Simple stateful detection module
// Each rule keeps its own memory (using a Map or counters with timestamps)

const statefulRules = [

  // 1. Brute force detection (5 failed logons in 5 minutes)
  {
    id: 'st-bruteforce-failed-logons',
    description: 'Multiple failed logons within 5 minutes (possible brute force)',
    severity: 'high',
    state: new Map(),
    match: function(decoded) {
      if (decoded.eventId !== 4625) return false; // failed logon
      const user = decoded.accountName || 'unknown';
      const now = Date.now();

      if (!this.state.has(user)) this.state.set(user, []);
      const attempts = this.state.get(user);

      // keep last 5 minutes only
      const windowStart = now - 5 * 60 * 1000;
      const recent = attempts.filter(ts => ts > windowStart);
      recent.push(now);
      this.state.set(user, recent);

      return recent.length >= 5; // 5+ failures in window
    }
  },

  // 2. Success after failures (password spray / guessing)
  {
    id: 'st-success-after-failures',
    description: 'Successful logon after multiple failures',
    severity: 'medium',
    state: new Map(),
    match: function(decoded) {
      const user = decoded.accountName || 'unknown';

      if (decoded.eventId === 4625) { // failed
        const now = Date.now();
        if (!this.state.has(user)) this.state.set(user, []);
        this.state.get(user).push(now);
        return false;
      }

      if (decoded.eventId === 4624) { // success
        const now = Date.now();
        const failures = (this.state.get(user) || []).filter(ts => ts > now - 10*60*1000);
        if (failures.length >= 3) {
          this.state.delete(user); // reset
          return true;
        }
      }

      return false;
    }
  },

  // 3. Multiple accounts failing from same IP (password spray)
  {
    id: 'st-password-spray',
    description: 'Same IP failed against multiple accounts',
    severity: 'high',
    state: new Map(),
    match: function(decoded) {
      if (decoded.eventId !== 4625) return false;
      const ip = decoded.sourceIp || 'unknown';
      const user = decoded.accountName || 'unknown';
      const now = Date.now();

      if (!this.state.has(ip)) this.state.set(ip, new Set());
      const users = this.state.get(ip);
      users.add(user);

      // reset window after 15 min
      setTimeout(() => { this.state.delete(ip); }, 15*60*1000);

      return users.size >= 5; // 5+ distinct accounts failed
    }
  },

  // 4. Lateral movement detection (same account logs in to 3+ different hosts in 10 mins)
  {
    id: 'st-lateral-movement',
    description: 'Account logged in to multiple hosts in short time',
    severity: 'high',
    state: new Map(),
    match: function(decoded) {
      if (decoded.eventId !== 4624) return false;
      const user = decoded.accountName || 'unknown';
      const host = decoded.targetHost || decoded.computerName || 'unknown';
      const now = Date.now();

      if (!this.state.has(user)) this.state.set(user, []);
      const entries = this.state.get(user);
      entries.push({host, time: now});

      // keep only last 10 minutes
      const recent = entries.filter(e => e.time > now - 10*60*1000);
      this.state.set(user, recent);

      const uniqueHosts = new Set(recent.map(e => e.host));
      return uniqueHosts.size >= 3;
    }
  },

  // 5. Privilege escalation chain (user added to group + special privileges)
  {
    id: 'st-privilege-escalation',
    description: 'User added to privileged group followed by privilege assignment',
    severity: 'critical',
    state: new Map(),
    match: function(decoded) {
      const user = decoded.accountName || 'unknown';

      if (decoded.eventId === 4728) { // added to group
        this.state.set(user, { addedAt: Date.now() });
        return false;
      }

      if (decoded.eventId === 4672) { // privilege assigned
        const info = this.state.get(user);
        if (info && Date.now() - info.addedAt < 10*60*1000) {
          this.state.delete(user);
          return true;
        }
      }

      return false;
    }
  },

  // 6. Suspicious log clearing followed by login
  {
    id: 'st-log-clear-then-login',
    description: 'Security log cleared followed by successful logon',
    severity: 'high',
    state: { clearedAt: null },
    match: function(decoded) {
      if (decoded.eventId === 1102) { // log cleared
        this.state.clearedAt = Date.now();
        return false;
      }

      if (decoded.eventId === 4624 && this.state.clearedAt) {
        if (Date.now() - this.state.clearedAt < 5*60*1000) {
          this.state.clearedAt = null;
          return true;
        }
      }

      return false;
    }
  },

  // 7. Service creation followed by privilege assignment
  {
    id: 'st-service-creation-escalation',
    description: 'Service created and privileges escalated',
    severity: 'high',
    state: new Map(),
    match: function(decoded) {
      if (decoded.eventId === 4697) { // service installed
        this.state.set(decoded.accountName, Date.now());
        return false;
      }

      if (decoded.eventId === 4672) { // privileges assigned
        const ts = this.state.get(decoded.accountName);
        if (ts && Date.now() - ts < 5*60*1000) {
          this.state.delete(decoded.accountName);
          return true;
        }
      }

      return false;
    }
  },

  // 8. Multiple logons from same account across geolocations (impossible travel)
  {
    id: 'st-impossible-travel',
    description: 'Same account logged in from distant locations in short time',
    severity: 'critical',
    state: new Map(),
    match: function(decoded) {
      if (decoded.eventId !== 4624) return false;
      const user = decoded.accountName || 'unknown';
      const loc = decoded.geoLocation || 'unknown';
      const now = Date.now();

      if (!this.state.has(user)) this.state.set(user, []);
      const entries = this.state.get(user);
      entries.push({ loc, time: now });
      const recent = entries.filter(e => e.time > now - 30*60*1000);
      this.state.set(user, recent);

      // if we detect >1 distinct location in <30 mins
      const uniqueLocs = new Set(recent.map(e => e.loc));
      return uniqueLocs.size > 1;
    }
  },

  // 9. Account creation + admin group membership
  {
    id: 'st-account-created-then-admin',
    description: 'New account quickly added to admin group',
    severity: 'critical',
    state: new Map(),
    match: function(decoded) {
      if (decoded.eventId === 4720) { // user created
        this.state.set(decoded.accountName, Date.now());
        return false;
      }

      if (decoded.eventId === 4728) { // added to group
        const ts = this.state.get(decoded.accountName);
        if (ts && Date.now() - ts < 5*60*1000) {
          this.state.delete(decoded.accountName);
          return true;
        }
      }

      return false;
    }
  },

  // 10. Repeated service crashes (persistence evasion or malware attempt)
  {
    id: 'st-service-crash-loop',
    description: 'Same service crashed repeatedly (7031)',
    severity: 'medium',
    state: new Map(),
    match: function(decoded) {
      if (decoded.eventId !== 7031) return false;
      const service = decoded.serviceName || 'unknown';
      const now = Date.now();

      if (!this.state.has(service)) this.state.set(service, []);
      const crashes = this.state.get(service).filter(ts => ts > now - 10*60*1000);
      crashes.push(now);
      this.state.set(service, crashes);

      return crashes.length >= 3; // crashed 3+ times in 10 min
    }
  },

  // 11. Multiple processes spawned by same parent (possible malware)
  {
    id: 'st-suspicious-process-spawn',
    description: 'Same parent spawned multiple processes rapidly',
    severity: 'high',
    state: new Map(),
    match: function(decoded) {
      if (decoded.eventId !== 4688) return false; // process creation
      const parent = decoded.parentProcess || 'unknown';
      const now = Date.now();

      if (!this.state.has(parent)) this.state.set(parent, []);
      const children = this.state.get(parent).filter(ts => ts > now - 1*60*1000);
      children.push(now);
      this.state.set(parent, children);

      return children.length >= 10; // 10+ processes in 1 minute
    }
  },

  // 12. Malware persistence attempt (scheduled task + process start)
  {
    id: 'st-scheduled-task-persistence',
    description: 'Scheduled task created followed by suspicious process start',
    severity: 'critical',
    state: new Map(),
    match: function(decoded) {
      if (decoded.eventId === 4698) { // task created
        this.state.set(decoded.accountName, Date.now());
        return false;
      }

      if (decoded.eventId === 4688) { // process start
        const ts = this.state.get(decoded.accountName);
        if (ts && Date.now() - ts < 5*60*1000) {
          this.state.delete(decoded.accountName);
          return true;
        }
      }

      return false;
    }
  }

];

module.exports = statefulRules;
