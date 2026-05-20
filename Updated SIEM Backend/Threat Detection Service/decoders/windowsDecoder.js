// Normalize windows log and extract simple fields (expand as needed)
function decodeWindowsLog(raw) {
  const decoded = {
    eventId: raw.EventID ?? raw.eventId ?? null,
    source: raw.Source ?? raw.source ?? '',
    task: raw.Task ?? raw.task ?? null,
    level: raw.Level ?? raw.level ?? null,
    timeCreated: raw.TimeCreated ?? raw.timeCreated ?? new Date().toISOString(),
    computer: raw.Computer ?? raw.computer ?? '',
    description: raw.Description ?? raw.description ?? '',
  };

  // Try to extract common Windows fields from Description using regex
  // Example: extract "Logon Type: 5" or privileges like SeDebugPrivilege
  const logonTypeMatch = decoded.description.match(/Logon Type:\s*(\d+)/i);
  if (logonTypeMatch) decoded.logonType = Number(logonTypeMatch[1]);

  const userMatch = decoded.description.match(/Account Name:\s*([\w$\\.-]+)/i)
    || decoded.description.match(/User Name:\s*([\w$\\.-]+)/i)
    || decoded.description.match(/^\s*([\w$\\.-]+)\s+/); // fallback
  if (userMatch) decoded.accountName = userMatch[1];
  
  return decoded;
}

module.exports = { decodeWindowsLog };
