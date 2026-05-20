// import React from 'react';
// import { ThreatLog, Log } from '../../types';
// import { X, AlertTriangle, Shield, Server, Clock, Calendar, User, MessageSquare } from 'lucide-react';

// interface LogViewModalProps {
//   log: ThreatLog | Log;
//   onClose: () => void;
//   onCreateTicket: (log: ThreatLog | Log) => void;
//   onMarkFalsePositive: (logId: string) => void;
//   log: ThreatLog & { isFalsePositive?: boolean };
// }

// const LogViewModal: React.FC<LogViewModalProps> = ({ 
//   log, 
//   onClose, 
//   onCreateTicket, 
//   onMarkFalsePositive 
// }) => {
//   const isThreatLog = (log: ThreatLog | Log): log is ThreatLog => {
//     return 'ruleMatched' in log && 'message' in log;
//   };

//   const getSeverityColor = (severity: string) => {
//     switch (severity) {
//       case 'critical': return 'border-red-500 bg-red-900/20';
//       case 'high': return 'border-orange-500 bg-orange-900/20';
//       case 'medium': return 'border-yellow-500 bg-yellow-900/20';
//       case 'low': return 'border-blue-500 bg-blue-900/20';
//       default: return 'border-gray-500 bg-gray-900/20';
//     }
//   };

//   const getSeverityIcon = (severity: string) => {
//     switch (severity) {
//       case 'critical': return <AlertTriangle className="h-5 w-5 text-red-500" />;
//       case 'high': return <AlertTriangle className="h-5 w-5 text-orange-500" />;
//       case 'medium': return <Shield className="h-5 w-5 text-yellow-500" />;
//       case 'low': return <Shield className="h-5 w-5 text-blue-500" />;
//       default: return <Shield className="h-5 w-5 text-gray-500" />;
//     }
//   };

//   const formatTimestamp = (timestamp: string) => {
//     return new Date(timestamp).toLocaleString();
//   };

//   const handleCreateTicket = () => {
//     onCreateTicket(log);
//   };

//   const handleMarkFalsePositive = () => {
//     onMarkFalsePositive(log.id);
//   };

//   return (
//     <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
//       <div className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full max-h-[85vh] overflow-y-auto">
//         <div className="flex items-center justify-between p-6 border-b border-gray-700">
//           <h2 className="text-xl font-bold text-white flex items-center space-x-2">
//             <Server className="h-6 w-6 text-blue-500" />
//             <span>Log Details - {log.id}</span>
//           </h2>
//           <button
//             onClick={onClose}
//             className="text-gray-400 hover:text-white transition-colors"
//           >
//             <X className="h-6 w-6" />
//           </button>
//         </div>

//         <div className="p-6 space-y-6">
//           {/* Severity and Basic Info */}
//           <div className={`border-l-4 rounded-r-lg p-4 ${getSeverityColor(log.severity)}`}>
//             <div className="flex items-center space-x-3 mb-3">
//               {getSeverityIcon(log.severity)}
//               <span className={`px-2 py-1 rounded-full text-xs font-medium border capitalize ${
//                 log.severity === 'critical' ? 'bg-red-900 text-red-300 border-red-500' :
//                 log.severity === 'high' ? 'bg-orange-900 text-orange-300 border-orange-500' :
//                 log.severity === 'medium' ? 'bg-yellow-900 text-yellow-300 border-yellow-500' :
//                 'bg-blue-900 text-blue-300 border-blue-500'
//               }`}>
//                 {log.severity} Priority
//               </span>
//               {isThreatLog(log) && (
//                 <span className="px-2 py-1 rounded-full text-xs font-medium bg-red-900 text-red-300 border border-red-500">
//                   THREAT
//                 </span>
//               )}
//             </div>
//             <p className="text-white font-medium">{log.description}</p>
//           </div>

//           {/* Threat-specific Information */}
//           {isThreatLog(log) && (
//             <div className="bg-red-900/20 border border-red-500 rounded-lg p-4">
//               <h4 className="text-red-300 font-medium mb-3 flex items-center space-x-2">
//                 <AlertTriangle className="h-5 w-5" />
//                 <span>Threat Information</span>
//               </h4>
//               <div className="space-y-2 text-sm">
//                 <div className="flex justify-between">
//                   <span className="text-gray-400">Rule Matched:</span>
//                   <span className="text-red-300 font-mono">{log.ruleMatched}</span>
//                 </div>
//                 <div className="flex justify-between">
//                   <span className="text-gray-400">Threat Message:</span>
//                   <span className="text-red-300">{log.message}</span>
//                 </div>
//                 <div className="flex justify-between">
//                   <span className="text-gray-400">Processing Status:</span>
//                   <span className={log.isProcessed ? 'text-green-400' : 'text-yellow-400'}>
//                     {log.isProcessed ? 'Processed' : 'Pending'}
//                   </span>
//                 </div>
//                 <div className="flex justify-between">
//                   <span className="text-gray-400">Fixed Status:</span>
//                   <span className={log.isFixed ? 'text-green-400' : 'text-red-400'}>
//                     {log.isFixed ? 'Fixed' : 'Not Fixed'}
//                   </span>
//                 </div>
//               </div>
//             </div>
//           )}

//           {/* System Information */}
//           <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
//             <h4 className="text-white font-medium mb-3">System Information</h4>
//             <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
//               <div>
//                 <p className="text-gray-400">Agent ID:</p>
//                 <p className="text-white">{log.agentId}</p>
//               </div>
//               <div>
//                 <p className="text-gray-400">IP Address:</p>
//                 <p className="text-white">{log.ip}</p>
//               </div>
//               <div>
//                 <p className="text-gray-400">Operating System:</p>
//                 <p className="text-white">{log.os}</p>
//               </div>
//               <div>
//                 <p className="text-gray-400">Computer:</p>
//                 <p className="text-white">{log.computer}</p>
//               </div>
//             </div>
//           </div>

//           {/* Event Details */}
//           <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
//             <h4 className="text-white font-medium mb-3">Event Details</h4>
//             <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
//               <div>
//                 <p className="text-gray-400">Event ID:</p>
//                 <p className="text-white">{log.eventId}</p>
//               </div>
//               <div>
//                 <p className="text-gray-400">Level:</p>
//                 <p className="text-white">{log.level}</p>
//               </div>
//               <div>
//                 <p className="text-gray-400">Source:</p>
//                 <p className="text-white">{log.source}</p>
//               </div>
//               <div>
//                 <p className="text-gray-400">Task:</p>
//                 <p className="text-white">{log.task}</p>
//               </div>
//               {isThreatLog(log) && (
//                 <div>
//                   <p className="text-gray-400">Channel:</p>
//                   <p className="text-white">{log.channel}</p>
//                 </div>
//               )}
//             </div>
//           </div>

//           {/* Timing Information */}
//           <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
//             <h4 className="text-white font-medium mb-3">Timing Information</h4>
//             <div className="space-y-2 text-sm">
//               <div className="flex justify-between">
//                 <span className="text-gray-400">Time Created:</span>
//                 <span className="text-gray-300">{formatTimestamp(log.timeCreated)}</span>
//               </div>
//             </div>
//           </div>

//           {/* Actions */}
//           <div className="flex justify-end space-x-3 pt-4 border-t border-gray-700">
//             <button
//               onClick={onClose}
//               className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors"
//             >
//               Close
//             </button>
//             {!log.isFalsePositive ? (
//                 <button
//                   onClick={() => onMarkFalsePositive(log.id)}
//                   className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors flex items-center space-x-2"
//                 >
//                   <Shield className="h-4 w-4" />
//                   <span>Mark as False Positive</span>
//                 </button>
//             ) : (<p className="text-yellow-400">Marked as false positive</p>
//             )}
//             <button
//               onClick={handleCreateTicket}
//               className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
//             >
//               <MessageSquare className="h-4 w-4" />
//               <span>Create Ticket</span>
//             </button>
//           </div>
//         </div>
//       </div>
//     </div>
//   );
// };

// export default LogViewModal;




// import React from 'react';
// import { ThreatLog, Log } from '../../types';
// import { X, AlertTriangle, Shield, Server, MessageSquare } from 'lucide-react';

// interface LogViewModalProps {
//   onClose: () => void;
//   onCreateTicket: (log: ThreatLog | Log) => void;
//   onMarkFalsePositive: (logId: string) => void;
//   // This is the corrected line - the duplicate 'log' prop has been removed.
//   log: (ThreatLog | Log) & { isFalsePositive?: boolean };
// }

// const LogViewModal: React.FC<LogViewModalProps> = ({ 
//   log, 
//   onClose, 
//   onCreateTicket, 
//   onMarkFalsePositive 
// }) => {
//   const isThreatLog = (log: ThreatLog | Log): log is ThreatLog => {
//     return 'ruleMatched' in log && 'message' in log;
//   };

//   const getSeverityColor = (severity: string) => {
//     switch (severity) {
//       case 'critical': return 'border-red-500 bg-red-900/20';
//       case 'high': return 'border-orange-500 bg-orange-900/20';
//       case 'medium': return 'border-yellow-500 bg-yellow-900/20';
//       case 'low': return 'border-blue-500 bg-blue-900/20';
//       default: return 'border-gray-500 bg-gray-900/20';
//     }
//   };

//   const getSeverityIcon = (severity: string) => {
//     switch (severity) {
//       case 'critical': return <AlertTriangle className="h-5 w-5 text-red-500" />;
//       case 'high': return <AlertTriangle className="h-5 w-5 text-orange-500" />;
//       case 'medium': return <Shield className="h-5 w-5 text-yellow-500" />;
//       case 'low': return <Shield className="h-5 w-5 text-blue-500" />;
//       default: return <Shield className="h-5 w-5 text-gray-500" />;
//     }
//   };

//   const formatTimestamp = (timestamp: string) => {
//     return new Date(timestamp).toLocaleString();
//   };

//   const handleCreateTicket = () => {
//     onCreateTicket(log);
//   };

//   return (
//     <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
//       <div className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full max-h-[85vh] overflow-y-auto">
//         <div className="flex items-center justify-between p-6 border-b border-gray-700">
//           <h2 className="text-xl font-bold text-white flex items-center space-x-2">
//             <Server className="h-6 w-6 text-blue-500" />
//             <span>Log Details - {log.id}</span>
//           </h2>
//           <button
//             onClick={onClose}
//             className="text-gray-400 hover:text-white transition-colors"
//           >
//             <X className="h-6 w-6" />
//           </button>
//         </div>

//         <div className="p-6 space-y-6">
//           {/* Severity and Basic Info */}
//           <div className={`border-l-4 rounded-r-lg p-4 ${getSeverityColor(log.severity)}`}>
//             <div className="flex items-center space-x-3 mb-3">
//               {getSeverityIcon(log.severity)}
//               <span className={`px-2 py-1 rounded-full text-xs font-medium border capitalize ${
//                 log.severity === 'critical' ? 'bg-red-900 text-red-300 border-red-500' :
//                 log.severity === 'high' ? 'bg-orange-900 text-orange-300 border-orange-500' :
//                 log.severity === 'medium' ? 'bg-yellow-900 text-yellow-300 border-yellow-500' :
//                 'bg-blue-900 text-blue-300 border-blue-500'
//               }`}>
//                 {log.severity} Priority
//               </span>
//               {isThreatLog(log) && (
//                 <span className="px-2 py-1 rounded-full text-xs font-medium bg-red-900 text-red-300 border border-red-500">
//                   THREAT
//                 </span>
//               )}
//             </div>
//             <p className="text-white font-medium">{log.description}</p>
//           </div>

//           {/* Threat-specific Information */}
//           {isThreatLog(log) && (
//             <div className="bg-red-900/20 border border-red-500 rounded-lg p-4">
//               <h4 className="text-red-300 font-medium mb-3 flex items-center space-x-2">
//                 <AlertTriangle className="h-5 w-5" />
//                 <span>Threat Information</span>
//               </h4>
//               <div className="space-y-2 text-sm">
//                 <div className="flex justify-between">
//                   <span className="text-gray-400">Rule Matched:</span>
//                   <span className="text-red-300 font-mono">{log.ruleMatched}</span>
//                 </div>
//                 <div className="flex justify-between">
//                   <span className="text-gray-400">Threat Message:</span>
//                   <span className="text-red-300">{log.message}</span>
//                 </div>
//                 <div className="flex justify-between">
//                   <span className="text-gray-400">Processing Status:</span>
//                   <span className={log.isProcessed ? 'text-green-400' : 'text-yellow-400'}>
//                     {log.isProcessed ? 'Processed' : 'Pending'}
//                   </span>
//                 </div>
//                 <div className="flex justify-between">
//                   <span className="text-gray-400">Fixed Status:</span>
//                   <span className={log.isFixed ? 'text-green-400' : 'text-red-400'}>
//                     {log.isFixed ? 'Fixed' : 'Not Fixed'}
//                   </span>
//                 </div>
//               </div>
//             </div>
//           )}

//           {/* System Information */}
//           <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
//             <h4 className="text-white font-medium mb-3">System Information</h4>
//             <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
//               <div>
//                 <p className="text-gray-400">Agent ID:</p>
//                 <p className="text-white">{log.agentId}</p>
//               </div>
//               <div>
//                 <p className="text-gray-400">IP Address:</p>
//                 <p className="text-white">{log.ip}</p>
//               </div>
//               <div>
//                 <p className="text-gray-400">Operating System:</p>
//                 <p className="text-white">{log.os}</p>
//               </div>
//               <div>
//                 <p className="text-gray-400">Computer:</p>
//                 <p className="text-white">{log.computer}</p>
//               </div>
//             </div>
//           </div>

//           {/* Event Details */}
//           <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
//             <h4 className="text-white font-medium mb-3">Event Details</h4>
//             <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
//               <div>
//                 <p className="text-gray-400">Event ID:</p>
//                 <p className="text-white">{log.eventId}</p>
//               </div>
//               <div>
//                 <p className="text-gray-400">Level:</p>
//                 <p className="text-white">{log.level}</p>
//               </div>
//               <div>
//                 <p className="text-gray-400">Source:</p>
//                 <p className="text-white">{log.source}</p>
//               </div>
//               <div>
//                 <p className="text-gray-400">Task:</p>
//                 <p className="text-white">{log.task}</p>
//               </div>
//               {isThreatLog(log) && (
//                 <div>
//                   <p className="text-gray-400">Channel:</p>
//                   <p className="text-white">{log.channel}</p>
//                 </div>
//               )}
//             </div>
//           </div>

//           {/* Timing Information */}
//           <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
//             <h4 className="text-white font-medium mb-3">Timing Information</h4>
//             <div className="space-y-2 text-sm">
//               <div className="flex justify-between">
//                 <span className="text-gray-400">Time Created:</span>
//                 <span className="text-gray-300">{formatTimestamp(log.timeCreated)}</span>
//               </div>
//             </div>
//           </div>

//           {/* Actions */}
//           <div className="flex justify-end space-x-3 pt-4 border-t border-gray-700">
//             <button
//               onClick={onClose}
//               className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors"
//             >
//               Close
//             </button>
//             {isThreatLog(log) && (
//               <>
//                 {log.isFalsePositive ? (
//                   <p className="text-yellow-400 self-center px-4">Marked as false positive</p>
//                 ) : (
//                   <button
//                     onClick={() => onMarkFalsePositive(log.id)}
//                     className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors flex items-center space-x-2"
//                   >
//                     <Shield className="h-4 w-4" />
//                     <span>Mark as False Positive</span>
//                   </button>
//                 )}
//                 <button
//                   onClick={handleCreateTicket}
//                   className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
//                 >
//                   <MessageSquare className="h-4 w-4" />
//                   <span>Create Ticket</span>
//                 </button>
//               </>
//             )}
//           </div>
//         </div>
//       </div>
//     </div>
//   );
// };

// export default LogViewModal;



import React, { useEffect, useRef, useState } from 'react';
import { ThreatLog, Log } from '../../types';
import { X, AlertTriangle, Shield, Server, MessageSquare } from 'lucide-react';
import { useOnClickOutside } from '../../hooks/useOnClickOutside';

interface LogViewModalProps {
  onClose: () => void;
  onCreateTicket: (log: ThreatLog | Log) => void;
  onMarkFalsePositive: (logId: string) => void;
  log: ThreatLog | Log;
}

const LogViewModal: React.FC<LogViewModalProps> = ({
  log,
  onClose,
  onCreateTicket,
  onMarkFalsePositive
}) => {
  const modalRef = useRef<HTMLDivElement>(null);
  useOnClickOutside(modalRef, onClose);

  const isThreatLog = (log: ThreatLog | Log): log is ThreatLog => {
    return 'ruleMatched' in log && 'message' in log;
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'border-red-500 bg-red-900/20';
      case 'high': return 'border-orange-500 bg-orange-900/20';
      case 'medium': return 'border-yellow-500 bg-yellow-900/20';
      case 'low': return 'border-blue-500 bg-blue-900/20';
      default: return 'border-gray-500 bg-gray-900/20';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <AlertTriangle className="h-5 w-5 text-red-500" />;
      case 'high': return <AlertTriangle className="h-5 w-5 text-orange-500" />;
      case 'medium': return <Shield className="h-5 w-5 text-yellow-500" />;
      case 'low': return <Shield className="h-5 w-5 text-blue-500" />;
      default: return <Shield className="h-5 w-5 text-gray-500" />;
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const handleCreateTicketClick = () => {
    onCreateTicket(log);
  };

  const [extraLogDetails, setExtraLogDetails] = useState<any>(null);
  useEffect(() => {
    if (!isThreatLog(log)) return; // ✅ Only threat logs
    if (!log.id) return;

    const fetchExtraDetails = async () => {
      try {
        const sessionId = localStorage.getItem("sessionId");
        if (!sessionId) return;

        const res = await fetch(`http://localhost:3001/api/logs/viewLog/${log.log_ref}`, {
          method: "GET",
          headers: {
            "Authorization": `Bearer ${sessionId}`
          }
        });

        if (res.ok) {
          const data = await res.json();
          setExtraLogDetails(data.log); // ✅ Save result in state
        } else {
          console.error("Failed to load extra log details");
        }
      } catch (err) {
        console.error("Error loading extra log details:", err);
      }
    };

    fetchExtraDetails();
  }, [log]);


  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div ref={modalRef} className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full max-h-[85vh] overflow-y-auto">
        <div className="flex items-center justify-between p-6 border-b border-gray-700">
          <h2 className="text-xl font-bold text-white flex items-center space-x-2">
            <Server className="h-6 w-6 text-blue-500" />
            <span>Log Details - {log.id}</span>
          </h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Severity and Basic Info */}
          <div className={`border-l-4 rounded-r-lg p-4 ${getSeverityColor(log.severity)}`}>
            <div className="flex items-center space-x-3 mb-3">
              {getSeverityIcon(log.severity)}
              <span className={`px-2 py-1 rounded-full text-xs font-medium border capitalize ${log.severity === 'critical' ? 'bg-red-900 text-red-300 border-red-500' :
                  log.severity === 'high' ? 'bg-orange-900 text-orange-300 border-orange-500' :
                    log.severity === 'medium' ? 'bg-yellow-900 text-yellow-300 border-yellow-500' :
                      'bg-blue-900 text-blue-300 border-blue-500'
                }`}>
                {log.severity} Priority
              </span>
              {isThreatLog(log) && (
                <span className="px-2 py-1 rounded-full text-xs font-medium bg-red-900 text-red-300 border border-red-500">
                  THREAT
                </span>
              )}
            </div>
            <p className="text-white font-medium">{log.description}</p>
          </div>

          {/* Threat-specific Information */}
          {isThreatLog(log) && (
            <div className="bg-red-900/20 border border-red-500 rounded-lg p-4">
              <h4 className="text-red-300 font-medium mb-3 flex items-center space-x-2">
                <AlertTriangle className="h-5 w-5" />
                <span>Threat Information</span>
              </h4>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-400">Rule Matched:</span>
                  <span className="text-red-300 font-mono">{log.ruleMatched}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Threat Message:</span>
                  <span className="text-red-300">{log.message}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Processing Status:</span>
                  <span className={log.isProcessed ? 'text-green-400' : 'text-yellow-400'}>
                    {log.isProcessed ? 'Processed' : 'Pending'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Fixed Status:</span>
                  <span className={log.isFixed ? 'text-green-400' : 'text-red-400'}>
                    {log.isFixed ? 'Fixed' : 'Not Fixed'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* System Information */}
          <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
            <h4 className="text-white font-medium mb-3">System Information</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-gray-400">Agent ID:</p>
                <p className="text-white">{log.agent_id}</p>
              </div>
              <div>
                <p className="text-gray-400">IP Address:</p>
                <p className="text-white">{log.ip}</p>
              </div>
              <div>
                <p className="text-gray-400">Operating System:</p>
                <p className="text-white">{log.os}</p>
              </div>
              <div>
                <p className="text-gray-400">Computer:</p>
                <p className="text-white">{isThreatLog(log)? (extraLogDetails?.computer || "Loading..."): log.computer}</p>
              </div>
            </div>
          </div>

          {/* Event Details */}
          <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
            <h4 className="text-white font-medium mb-3">Event Details</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-gray-400">Event ID:</p>
                <p className="text-white">{isThreatLog(log)? (extraLogDetails?.eventId || "Loading..."): log.eventId}</p>
              </div>
              <div>
                <p className="text-gray-400">Level:</p>
                <p className="text-white">{isThreatLog(log)? (extraLogDetails?.level || "Loading..."): log.level}</p>
              </div>
              <div>
                <p className="text-gray-400">Source:</p>
                <p className="text-white">{isThreatLog(log)? (extraLogDetails?.source || "Loading..."): log.source}</p>
              </div>
              <div>
                <p className="text-gray-400">Task:</p>
                <p className="text-white">{isThreatLog(log)? (extraLogDetails?.task || "Loading..."): log.task}</p>
              </div>
              <div>
                <p className="text-gray-400">Channel:</p>
                <p className="text-white">{isThreatLog(log)? (extraLogDetails?.channel || "Loading..."): log.channel}</p>
              </div>
            </div>
          </div>

          {/* Timing Information */}
          <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
            <h4 className="text-white font-medium mb-3">Timing Information</h4>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">Time Created:</span>
                <span className="text-gray-300">{formatTimestamp(log.timeCreated)}</span>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex justify-end space-x-3 pt-4 border-t border-gray-700">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors"
            >
              Close
            </button>
            {isThreatLog(log) && (
              <>
                {log.isFalsePositive ? (
                  <p className="text-yellow-400 self-center px-4">Marked as false positive</p>
                ) : (
                  <button
                    onClick={() => onMarkFalsePositive(log.id)}
                    className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors flex items-center space-x-2"
                  >
                    <Shield className="h-4 w-4" />
                    <span>Mark as False Positive</span>
                  </button>
                )}
                <button
                  onClick={handleCreateTicketClick}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
                >
                  <MessageSquare className="h-4 w-4" />
                  <span>Create Ticket</span>
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default LogViewModal;