// export interface User {
//   id: string;
//   email: string;
//   role: 'admin' | 'soc-l1' | 'soc-l2' | 'soc-l3' | 'soc-l4';
//   employeeId: string;
//   department: string;
//   credentials?: {
//     username: string;
//     password: string;
//   };
// }

// export interface Device {
//   id: string;
//   ip: string;
//   location: string;
//   os: string;
//   version: string;
//   hardwareInfo: string[];
//   requestTime: string;
//   status: 'pending' | 'approved' | 'rejected';
//   geolocation?: {
//     lat: number;
//     lng: number;
//     city: string;
//     country: string;
//   };
// }

// export interface Agent {
//   id: string;
//   name: string;
//   ip: string;
//   location: string;
//   os: string;
//   version: string;
//   status: 'active' | 'disconnected' | 'maintenance';
//   lastSeen: string;
//   uptime: string;
//   geolocation: {
//     lat: number;
//     lng: number;
//     city: string;
//     country: string;
//   };
//   alertsCount: number;
//   threatsCount: number;
// }

// export interface ThreatLog {
//   id: string;
//   agentId: string;
//   ip: string;
//   os: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   message: string;
//   ruleMatched: string;
//   channel: string;
//   timeCreated: string;
//   level: string;
//   eventId: string;
//   source: string;
//   task: string;
//   computer: string;
//   description: string;
//   isProcessed: boolean;
//   isFixed: boolean;
//   isFalsePositive?: boolean; // Add this new optional property
//   elevatedBy?: string;
//   elevatedTo?: 'soc-l2' | 'soc-l3' | 'soc-l4';
//   elevatedAt?: string;
//   elevationReason?: string;
// }

// export interface Log {
//   id: string;
//   agentId: string;
//   ip: string;
//   os: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   timeCreated: string;
//   description: string;
//   level: string;
//   eventId: string;
//   source: string;
//   task: string;
//   computer: string;
//   channel: string;
//   isThreat?: boolean;
//   ruleMatched?: string;
//   message?: string;
//   elevatedBy?: string;
//   elevatedTo?: 'soc-l2' | 'soc-l3' | 'soc-l4';
//   elevatedAt?: string;
//   elevationReason?: string;
// }

// export interface Ticket {
//   id: string;
//   title: string;
//   description: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   status: 'open' | 'in-progress' | 'resolved' | 'closed';
//   assignee: string;
//   reporter: string;
//   createdAt: string;
//   updatedAt: string;
//   relatedLogId?: string;
//   elevatedBy?: string;
//   elevatedTo?: 'soc-l2' | 'soc-l3' | 'soc-l4';
//   elevatedAt?: string;
//   elevationReason?: string;
//   escalationLevel?: number;
// }

// export interface Notification {
//   id: string;
//   message: string;
//   timestamp: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   read: boolean;
// }

// export interface Alert {
//   id: string;
//   agentId: string;
//   agentName: string;
//   type: 'agent-down' | 'maintenance' | 'security' | 'performance';
//   message: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   timestamp: string;
//   acknowledged: boolean;
//   acknowledgedBy?: string;
//   acknowledgedAt?: string;
// }

// export interface Policy {
//   id: string;
//   name: string;
//   description: string;
//   rules: Rule[];
//   isActive: boolean;
//   createdBy: string;
//   createdAt: string;
//   updatedAt: string;
// }

// export interface Rule {
//   id: string;
//   name: string;
//   description: string;
//   condition: string;
//   action: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   isActive: boolean;
//   createdBy: string;
//   createdAt: string;
// }

// export interface User {
//   id: string;
//   email: string;
//   role: 'admin' | 'soc-l1' | 'soc-l2' | 'soc-l3' | 'soc-l4';
//   employeeId: string;
//   department: string;
// }

// export interface Device {
//   id: string;
//   ip: string;
//   location: string;
//   os: string;
//   version: string;
//   hardwareInfo: string[];
//   requestTime: string;
//   status: 'pending' | 'approved' | 'rejected';
// }

// export interface Agent {
//   id: string;
//   name: string;
//   ip: string;
//   location: string;
//   os: string;
//   version: string;
//   status: 'active' | 'disconnected' | 'maintenance';
//   lastSeen: string;
//   uptime: string;
//   geolocation: { lat: number; lng: number; city: string; country: string; };
//   alertsCount: number;
//   threatsCount: number;
// }

// export interface ThreatLog {
//   id: string;
//   agentId: string;
//   ip: string;
//   os: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   message: string;
//   ruleMatched: string;
//   channel: string;
//   timeCreated: string;
//   level: string;
//   eventId: string;
//   source: string;
//   task: string;
//   computer: string;
//   description: string;
//   isProcessed: boolean;
//   isFixed: boolean;
//   isFalsePositive?: boolean;
// }

// export interface Log {
//   id: string;
//   agentId: string;
//   ip: string;
//   os: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   timeCreated: string;
//   description: string;
//   level: string;
//   eventId: string;
//   source: string;
//   task: string;
//   computer: string;
//   channel: string;
// }

// // NEW TYPE FOR ATTACHMENTS
// export interface Attachment {
//     id: string;
//     fileName: string;
//     fileType: string;
//     fileSize: string;
// }

// export interface Ticket {
//   id: string;
//   title: string;
//   description: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   status: 'open' | 'triaged' | 'in-progress' | 'resolved' | 'closed';
//   assignee: string;
//   reporter: string;
//   createdAt: string;
//   updatedAt: string;
//   relatedLogId?: string;
//   relatedAlertId?: string;
//   elevatedBy?: string;
//   elevatedTo?: 'soc-l2' | 'soc-l3' | 'soc-l4';
//   elevatedAt?: string;
//   escalationLevel?: number;
//   comments?: TicketComment[];
//   attachments?: Attachment[]; // Add attachments to the ticket itself
//   contributors?: string[]; // New field for contributors
// }

// export interface TicketComment {
//     id: string;
//     author: string;
//     timestamp: string;
//     comment: string;
//     attachments?: Attachment[]; // Add attachments to comments
// }

// export interface Notification {
//   id: string;
//   message: string;
//   timestamp: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   read: boolean;
// }

// export interface Alert {
//   id: string;
//   agentId: string;
//   agentName: string;
//   type: 'agent-down' | 'maintenance' | 'security' | 'performance';
//   message: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   timestamp: string;
//   acknowledged: boolean;
//   acknowledgedBy?: string;
//   acknowledgedAt?: string;
// }

// export interface Policy {
//   id: string;
//   name: string;
//   description: string;
//   rules: Rule[];
//   isActive: boolean;
//   createdBy: string;
//   createdAt: string;
//   updatedAt: string;
// }

// export interface Rule {
//   id: string;
//   name: string;
//   description: string;
//   condition: string;
//   action: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   isActive: boolean;
//   createdBy: string;
//   createdAt: string;
// }





export interface User {
  id: string;
  email: string;
  role: 'admin' | 'soc-l1' | 'soc-l2' | 'soc-l3' | 'L4';
  employeeId: string;
  department: string;
}

export interface Device {
  id: string;
  ip: string;
  location: string;
  os: string;
  version: string;
  hardwareInfo: string[];
  requestTime: string;
  status: 'pending' | 'approved' | 'rejected';
}

export interface Agent {
  id: string;
  name: string;
  ip: string;
  location: string;
  os: string;
  version: string;
  status: 'active' | 'disconnected' | 'maintenance';
  lastSeen: string;
  uptime: string;
  geolocation: { lat: number; lng: number; city: string; country: string; };
  alertsCount: number;
  threatsCount: number;
}

export interface ThreatLog {
  id: string;
  agent_id: string;
  log_ref: string;
  ip: string;
  os: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  ruleMatched: string[];
  channel: string;
  timestamp: string;
  level: string;
  eventId: string;
  source: string;
  task: string;
  computer: string;
  description: string;
  isProcessed: boolean;
  isFixed: boolean;
  isFalsePositive?: boolean;
}

export interface Log {
  id: string;
  agentId: string;
  ip: string;
  os: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timeCreated: string;
  description: string;
  level: string;
  eventId: string;
  source: string;
  task: string;
  computer: string;
  channel: string;
}

export interface Attachment {
    id: string;
    fileName: string;
    fileType: string;
    fileSize: string;
}

export interface TicketComment {
    id: string;
    employee_id: string;
    updated_at: string;
    message: string;
    status?: Ticket['status'];
    severity?: Ticket['severity'];
    attachments?: string[];
}

export interface Ticket {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical' | 'urgent';
  status: 'open' | 'under_review' | 'closed';
  assignee: string;
  reporter: string;
  createdAt: string;
  updatedAt: string;
  log_refs?: string[];
  files?: Attachment[]; // Added 'files' property to resolve the error
  updates?: TicketComment[];
  levels?: string[];
  contributors?: string[];
  relatedLogId?: string;
  relatedAlertId?: string;
}

export interface Notification {
  id: string;
  message: string;
  timestamp: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  read?: boolean;
}

export interface Alert {
  id: string;
  agentId: string;
  agentName: string;
  type: 'agent-down' | 'maintenance' | 'security' | 'performance';
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: string;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: string;
}

export interface Policy {
  id: string;
  name: string;
  description?: string;
  conditions: {
    eventType: string;
    threshold: number;
    timeWindow: string;
    source?: string;
  };
  actions: {
    alert: boolean;
    raiseTicket: boolean;
    notifyEmail?: string;
  };
  isActive: boolean;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

