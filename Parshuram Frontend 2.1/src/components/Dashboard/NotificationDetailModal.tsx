// import React, { useRef } from 'react';
// import { Notification } from '../../types';
// import { X, AlertTriangle, Info, CheckCircle, Bell } from 'lucide-react';
// import { useNavigate } from 'react-router-dom';
// import { useOnClickOutside } from '../../hooks/useOnClickOutside';

// interface NotificationDetailModalProps {
//   notification: Notification;
//   onClose: () => void;
// }

// const NotificationDetailModal: React.FC<NotificationDetailModalProps> = ({ 
//   notification, 
//   onClose 
// }) => {
  
//   const navigate = useNavigate();
//   const modalRef = useRef<HTMLDivElement>(null);
//   useOnClickOutside(modalRef, onClose);
  
//   const handleTakeAction = () => {
//     // Example: navigate to the threats page for a critical alert
//     if (notification.severity === 'critical') {
//       navigate('/threats');
//     }
//     onClose();
//   };

//   const getSeverityIcon = (severity: string) => {
//     switch (severity) {
//       case 'critical':
//         return <AlertTriangle className="h-6 w-6 text-red-500" />;
//       case 'high':
//         return <AlertTriangle className="h-6 w-6 text-orange-500" />;
//       case 'medium':
//         return <Info className="h-6 w-6 text-yellow-500" />;
//       case 'low':
//         return <CheckCircle className="h-6 w-6 text-blue-500" />;
//       default:
//         return <Bell className="h-6 w-6 text-gray-500" />;
//     }
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

//   const formatTimestamp = (timestamp: string) => {
//     return new Date(timestamp).toLocaleString();
//   };

//   const getTimeAgo = (timestamp: string) => {
//     const now = new Date();
//     const time = new Date(timestamp);
//     const diffInMinutes = Math.floor((now.getTime() - time.getTime()) / (1000 * 60));
    
//     if (diffInMinutes < 60) {
//       return `${diffInMinutes} minutes ago`;
//     } else if (diffInMinutes < 1440) {
//       return `${Math.floor(diffInMinutes / 60)} hours ago`;
//     } else {
//       return `${Math.floor(diffInMinutes / 1440)} days ago`;
//     }
//   };

//   return (
//     <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
//       <div ref={modalRef} className="bg-gray-800 border border-gray-700 rounded-lg max-w-md w-full">
//         <div className="flex items-center justify-between p-6 border-b border-gray-700">
//           <h2 className="text-lg font-bold text-white flex items-center space-x-2">
//             <Bell className="h-5 w-5 text-blue-500" />
//             <span>Notification Details</span>
//           </h2>
//           <button
//             onClick={onClose}
//             className="text-gray-400 hover:text-white transition-colors"
//           >
//             <X className="h-5 w-5" />
//           </button>
//         </div>

//         <div className="p-6 space-y-4">
//           {/* Severity Badge */}
//           <div className={`border-l-4 rounded-r-lg p-4 ${getSeverityColor(notification.severity)}`}>
//             <div className="flex items-center space-x-3">
//               {getSeverityIcon(notification.severity)}
//               <div>
//                 <span className={`px-2 py-1 rounded-full text-xs font-medium capitalize
//                   ${notification.severity === 'critical' ? 'bg-red-900 text-red-300' : ''}
//                   ${notification.severity === 'high' ? 'bg-orange-900 text-orange-300' : ''}
//                   ${notification.severity === 'medium' ? 'bg-yellow-900 text-yellow-300' : ''}
//                   ${notification.severity === 'low' ? 'bg-blue-900 text-blue-300' : ''}
//                 `}>
//                   {notification.severity} Priority
//                 </span>
//               </div>
//             </div>
//           </div>

//           {/* Message */}
//           <div>
//             <h3 className="text-white font-medium mb-2">Message</h3>
//             <p className="text-gray-300 text-sm leading-relaxed">
//               {notification.message}
//             </p>
//           </div>

//           {/* Timestamp Information */}
//           <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
//             <h4 className="text-white font-medium mb-2">Timing Information</h4>
//             <div className="space-y-2 text-sm">
//               <div className="flex justify-between">
//                 <span className="text-gray-400">Received:</span>
//                 <span className="text-gray-300">{getTimeAgo(notification.timestamp)}</span>
//               </div>
//               <div className="flex justify-between">
//                 <span className="text-gray-400">Full Date:</span>
//                 <span className="text-gray-300">{formatTimestamp(notification.timestamp)}</span>
//               </div>
//               <div className="flex justify-between">
//                 <span className="text-gray-400">Status:</span>
//                 <span className={`${notification.read ? 'text-green-400' : 'text-yellow-400'}`}>
//                   {notification.read ? 'Read' : 'Unread'}
//                 </span>
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
//             <button 
//             onClick={handleTakeAction}
//             className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
//               Take Action
//             </button>
//           </div>
//         </div>
//       </div>
//     </div>
//   );
// };

// export default NotificationDetailModal;

import React, { useRef } from 'react';
import { Notification } from '../../types';
import { X, AlertTriangle, Info, CheckCircle, Bell } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useOnClickOutside } from '../../hooks/useOnClickOutside';

interface NotificationDetailModalProps {
  notification: Notification;
  onClose: () => void;
}

const NotificationDetailModal: React.FC<NotificationDetailModalProps> = ({
  notification,
  onClose
}) => {
  const navigate = useNavigate();
  const modalRef = useRef<HTMLDivElement>(null);
  useOnClickOutside(modalRef, onClose);

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <AlertTriangle className="h-6 w-6 text-red-500" />;
      case 'high':
        return <AlertTriangle className="h-6 w-6 text-orange-500" />;
      case 'medium':
        return <Info className="h-6 w-6 text-yellow-500" />;
      case 'low':
        return <CheckCircle className="h-6 w-6 text-blue-500" />;
      default:
        return <Bell className="h-6 w-6 text-gray-500" />;
    }
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

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const getTimeAgo = (timestamp: string) => {
    const now = new Date();
    const time = new Date(timestamp);
    const diffInMinutes = Math.floor((now.getTime() - time.getTime()) / (1000 * 60));

    if (diffInMinutes < 60) {
      return `${diffInMinutes} minutes ago`;
    } else if (diffInMinutes < 1440) {
      return `${Math.floor(diffInMinutes / 60)} hours ago`;
    } else {
      return `${Math.floor(diffInMinutes / 1440)} days ago`;
    }
  };

  const handleTakeAction = () => {
    // Navigate to a relevant page based on the notification
    // For this example, a critical or high severity notification will go to the threats page
    if (notification.severity === 'critical' || notification.severity === 'high') {
        navigate('/threats');
    } else {
        // For other types, you might go to a different page, like agents or alerts
        navigate('/alerts');
    }
    onClose(); // Close the modal after navigating
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div ref={modalRef} className="bg-gray-800 border border-gray-700 rounded-lg max-w-md w-full">
        <div className="flex items-center justify-between p-6 border-b border-gray-700">
          <h2 className="text-lg font-bold text-white flex items-center space-x-2">
            <Bell className="h-5 w-5 text-blue-500" />
            <span>Notification Details</span>
          </h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div className={`border-l-4 rounded-r-lg p-4 ${getSeverityColor(notification.severity)}`}>
            <div className="flex items-center space-x-3">
              {getSeverityIcon(notification.severity)}
              <div>
                <span className={`px-2 py-1 rounded-full text-xs font-medium capitalize
                  ${notification.severity === 'critical' ? 'bg-red-900 text-red-300' : ''}
                  ${notification.severity === 'high' ? 'bg-orange-900 text-orange-300' : ''}
                  ${notification.severity === 'medium' ? 'bg-yellow-900 text-yellow-300' : ''}
                  ${notification.severity === 'low' ? 'bg-blue-900 text-blue-300' : ''}
                `}>
                  {notification.severity} Priority
                </span>
              </div>
            </div>
          </div>

          <div>
            <h3 className="text-white font-medium mb-2">Message</h3>
            <p className="text-gray-300 text-sm leading-relaxed">
              {notification.message}
            </p>
          </div>

          <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
            <h4 className="text-white font-medium mb-2">Timing Information</h4>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">Received:</span>
                <span className="text-gray-300">{getTimeAgo(notification.timestamp)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Full Date:</span>
                <span className="text-gray-300">{formatTimestamp(notification.timestamp)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Status:</span>
                <span className={`${notification.read ? 'text-green-400' : 'text-yellow-400'}`}>
                  {notification.read ? 'Read' : 'Unread'}
                </span>
              </div>
            </div>
          </div>

          <div className="flex justify-end space-x-3 pt-4 border-t border-gray-700">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors"
            >
              Close
            </button>
            <button
              onClick={handleTakeAction}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              Take Action
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NotificationDetailModal;