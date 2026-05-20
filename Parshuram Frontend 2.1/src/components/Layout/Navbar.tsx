// import React, { useState } from 'react';
// import { Link, useNavigate } from 'react-router-dom';
// import { useAuth } from '../../context/AuthContext';
// import { Notification } from '../../types';
// import { 
//   Shield, 
//   Bell, 
//   User, 
//   LogOut, 
//   ChevronDown,
//   Menu,
//   X
// } from 'lucide-react';
// import NotificationPanel from '../Dashboard/NotificationPanel';
// import NotificationDetailModal from '../Dashboard/NotificationDetailModal';

// const Navbar: React.FC = () => {
//   const { user, logout, isAuthenticated } = useAuth();
//   const navigate = useNavigate();
//   const [showProfileMenu, setShowProfileMenu] = useState(false);
//   const [showMobileMenu, setShowMobileMenu] = useState(false);
//   const [showNotifications, setShowNotifications] = useState(false);
//   const [selectedNotification, setSelectedNotification] = useState<Notification | null>(null);
//   const [showNotificationModal, setShowNotificationModal] = useState(false);

//   // Mock notifications - in real app, this would come from a context or API
//   const [notifications, setNotifications] = useState<Notification[]>([
//     {
//       id: '1',
//       message: 'Critical malware detected on DESKTOP-ABC123',
//       timestamp: '2025-01-02T14:30:00Z',
//       severity: 'critical',
//       read: false
//     },
//     {
//       id: '2',
//       message: 'High priority threat resolved on SERVER-XYZ789',
//       timestamp: '2025-01-02T14:25:00Z',
//       severity: 'high',
//       read: false
//     },
//     {
//       id: '3',
//       message: 'New device connection approved',
//       timestamp: '2025-01-02T14:20:00Z',
//       severity: 'low',
//       read: true
//     }
//   ]);

//   const unreadCount = notifications.filter(n => !n.read).length;

//   const handleLogout = () => {
//     logout();
//     navigate('/login');
//   };

//   const handleNotificationClick = (notification: Notification) => {
//     setSelectedNotification(notification);
//     setShowNotificationModal(true);
//     setShowNotifications(false);
    
//     // Mark as read when clicked
//     if (!notification.read) {
//       setNotifications(notifications.map(n => 
//         n.id === notification.id ? { ...n, read: true } : n
//       ));
//     }
//   };

//   const handleMarkAllRead = () => {
//     setNotifications(notifications.map(n => ({ ...n, read: true })));
//   };
//   if (!isAuthenticated) return null;

//   const navigationItems = [
//     { name: 'Dashboard', href: '/dashboard' },
//     ...(user?.role === 'admin' ? [] : [{ name: 'Threats', href: '/threats' }]),
//     ...(user?.role === 'admin' ? [] : [{ name: 'Tickets', href: '/tickets' }]),
//     { name: 'Device List', href: '/agents' },
//     ...(user?.role === 'admin' ? [
//       { name: 'Device Requests', href: '/device-requests' },
//       { name: 'Geolocation', href: '/geolocation' },
//       { name: 'Register Employee', href: '/register' },
//       { name: 'Alerts', href: '/alerts' },
//     ] : []),
//     ...(user?.role === 'soc-l4' ? [{ name: 'Policies', href: '/policies' }] : [])
//   ];

//   return (
//     <nav className="bg-gray-900 border-b border-gray-700 sticky top-0 z-50">
//       <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
//         <div className="flex justify-between items-center h-16">
//           {/* Logo and Brand */}
//           <div className="flex items-center">
//             <Link to="/dashboard" className="flex items-center space-x-2">
//               <Shield className="h-8 w-8 text-blue-500" />
//               <span className="text-xl font-bold text-white">Parshuram</span>
//             </Link>
//           </div>

//           {/* Desktop Navigation */}
//           <div className="hidden md:block">
//             <div className="ml-10 flex items-baseline space-x-4">
//               {navigationItems.map((item) => (
//                 <Link
//                   key={item.name}
//                   to={item.href}
//                   className="text-gray-300 hover:bg-gray-700 hover:text-white px-3 py-2 rounded-md text-sm font-medium transition-colors"
//                 >
//                   {item.name}
//                 </Link>
//               ))}
//             </div>
//           </div>

//           {/* Right side items */}
//           <div className="hidden md:block">
//             <div className="ml-4 flex items-center md:ml-6 space-x-4">
//               {/* Notifications */}
//               <div className="relative">
//                 <button
//                   onClick={() => setShowNotifications(!showNotifications)}
//                   className="relative p-2 text-gray-300 hover:text-white transition-colors"
//                 >
//                   <Bell className="h-6 w-6" />
//                   {unreadCount > 0 && (
//                     <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
//                       {unreadCount}
//                     </span>
//                   )}
//                 </button>
//                 {showNotifications && (
//                   <NotificationPanel 
//                     notifications={notifications}
//                     onClose={() => setShowNotifications(false)}
//                     onNotificationClick={handleNotificationClick}
//                     onMarkAllRead={handleMarkAllRead}
//                   />
//                 )}
//               </div>

//               {/* Profile dropdown */}
//               <div className="ml-3 relative">
//                 <div>
//                   <button
//                     onClick={() => setShowProfileMenu(!showProfileMenu)}
//                     className="max-w-xs bg-gray-800 rounded-full flex items-center text-sm focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-800 focus:ring-white"
//                   >
//                     <div className="flex items-center space-x-2 px-3 py-2">
//                       <User className="h-5 w-5 text-gray-300" />
//                       <span className="text-gray-300 text-sm">{user?.email}</span>
//                       <ChevronDown className="h-4 w-4 text-gray-300" />
//                     </div>
//                   </button>
//                 </div>

//                 {showProfileMenu && (
//                   <div className="origin-top-right absolute right-0 mt-2 w-48 rounded-md shadow-lg py-1 bg-gray-800 ring-1 ring-black ring-opacity-5 focus:outline-none">
//                     <div className="px-4 py-2 text-sm text-gray-400 border-b border-gray-700">
//                       <p className="font-medium">{user?.role}</p>
//                       <p>{user?.employeeId}</p>
//                     </div>
//                     <button 
//                       onClick={handleLogout}
//                       className="flex items-center w-full px-4 py-2 text-sm text-gray-300 hover:bg-gray-700"
//                     >
//                       <LogOut className="h-4 w-4 mr-2" />
//                       Logout
//                     </button>
//                   </div>
//                 )}
//               </div>
//             </div>
//           </div>

//           {/* Mobile menu button */}
//           <div className="md:hidden">
//             <button
//               onClick={() => setShowMobileMenu(!showMobileMenu)}
//               className="inline-flex items-center justify-center p-2 rounded-md text-gray-400 hover:text-white hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white"
//             >
//               {showMobileMenu ? (
//                 <X className="block h-6 w-6" />
//               ) : (
//                 <Menu className="block h-6 w-6" />
//               )}
//             </button>
//           </div>
//         </div>
//       </div>

//       {/* Mobile menu */}
//       {showMobileMenu && (
//         <div className="md:hidden">
//           <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3 bg-gray-800">
//             {navigationItems.map((item) => (
//               <Link
//                 key={item.name}
//                 to={item.href}
//                 className="text-gray-300 hover:bg-gray-700 hover:text-white block px-3 py-2 rounded-md text-base font-medium"
//                 onClick={() => setShowMobileMenu(false)}
//               >
//                 {item.name}
//               </Link>
//             ))}
//             <div className="border-t border-gray-700 pt-2">
//               <button
//                 onClick={() => {
//                   handleNotificationClick(notifications[0]); // Show first notification for demo
//                   setShowMobileMenu(false);
//                 }}
//                 className="text-gray-300 hover:bg-gray-700 hover:text-white block px-3 py-2 rounded-md text-base font-medium w-full text-left flex items-center space-x-2"
//               >
//                 <Bell className="h-5 w-5" />
//                 <span>Notifications</span>
//                 {unreadCount > 0 && (
//                   <span className="bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
//                     {unreadCount}
//                   </span>
//                 )}
//               </button>
//             </div>
//             <button 
//               onClick={handleLogout}
//               className="text-gray-300 hover:bg-gray-700 hover:text-white block px-3 py-2 rounded-md text-base font-medium w-full text-left"
//             >
//               Logout
//             </button>
//           </div>
//         </div>
//       )}

//       {/* Notification Detail Modal */}
//       {showNotificationModal && selectedNotification && (
//         <NotificationDetailModal
//           notification={selectedNotification}
//           onClose={() => setShowNotificationModal(false)}
//         />
//       )}
//     </nav>
//   );
// };

// export default Navbar;






import React, { useState, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { Notification } from '../../types';
import {
  Shield,
  Bell,
  User,
  LogOut,
  ChevronDown,
  Menu,
  X
} from 'lucide-react';
import NotificationPanel from '../Dashboard/NotificationPanel';
import NotificationDetailModal from '../Dashboard/NotificationDetailModal';
import { useOnClickOutside } from '../../hooks/useOnClickOutside';

const Navbar: React.FC = () => {
  const { user, logout, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [showMobileMenu, setShowMobileMenu] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [selectedNotification, setSelectedNotification] = useState<Notification | null>(null);
  const [showNotificationModal, setShowNotificationModal] = useState(false);

  const profileMenuRef = useRef<HTMLDivElement>(null);
  useOnClickOutside(profileMenuRef, () => setShowProfileMenu(false));

  const notificationsPanelRef = useRef<HTMLDivElement>(null);
  useOnClickOutside(notificationsPanelRef, () => setShowNotifications(false));

  const [notifications, setNotifications] = useState<Notification[]>([
    { id: '1', message: 'Critical malware detected on DESKTOP-ABC123', timestamp: '2025-01-02T14:30:00Z', severity: 'critical', read: false },
    { id: '2', message: 'High priority threat resolved on SERVER-XYZ789', timestamp: '2025-01-02T14:25:00Z', severity: 'high', read: false },
    { id: '3', message: 'New device connection approved', timestamp: '2025-01-02T14:20:00Z', severity: 'low', read: true }
  ]);

  const unreadCount = notifications.filter(n => !n.read).length;

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const handleNotificationClick = (notification: Notification) => {
    setSelectedNotification(notification);
    setShowNotificationModal(true);
    setShowNotifications(false);
    
    if (!notification.read) {
      setNotifications(notifications.map(n =>
        n.id === notification.id ? { ...n, read: true } : n
      ));
    }
  };

  const handleMarkAllRead = () => {
    setNotifications(notifications.map(n => ({ ...n, read: true })));
  };

  if (!isAuthenticated) return null;

  // UPDATED NAVIGATION ITEMS
  const navigationItems = [
    { name: 'Dashboard', href: '/dashboard' },
    ...(user?.role.startsWith('L') ? [{ name: 'Log Summary', href: '/logs' }] : []),
    ...(user?.role === 'admin' ? [] : [{ name: 'Threats', href: '/threats' }]),
    ...(user?.role === 'admin' ? [] : [{ name: 'Tickets', href: '/tickets' }]),
    { name: 'Device List', href: '/agents' },
    ...(user?.role === 'admin' ? [
      { name: 'Device Requests', href: '/device-requests' },
      { name: 'Geolocation', href: '/geolocation' },
      { name: 'Register Employee', href: '/register' },
      { name: 'Alerts', href: '/alerts' },
    ] : []),
    ...(user?.role.startsWith('L4') ? [{ name: 'Policies', href: '/policies' }] : [])
  ];

  return (
    <nav className="bg-gray-900 border-b border-gray-700 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <div className="flex items-center">
            <Link to="/dashboard" className="flex items-center space-x-2">
              <Shield className="h-8 w-8 text-blue-500" />
              <span className="text-xl font-bold text-white">Parshuram</span>
            </Link>
          </div>
          <div className="hidden md:block">
            <div className="ml-10 flex items-baseline space-x-4">
              {navigationItems.map((item) => (
                <Link
                  key={item.name}
                  to={item.href}
                  className="text-gray-300 hover:bg-gray-700 hover:text-white px-3 py-2 rounded-md text-sm font-medium transition-colors"
                >
                  {item.name}
                </Link>
              ))}
            </div>
          </div>
          <div className="hidden md:block">
            <div className="ml-4 flex items-center md:ml-6 space-x-4">
              <div className="relative" ref={notificationsPanelRef}>
                <button
                  onClick={() => setShowNotifications(!showNotifications)}
                  className="relative p-2 text-gray-300 hover:text-white transition-colors"
                >
                  <Bell className="h-6 w-6" />
                  {unreadCount > 0 && (
                    <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
                      {unreadCount}
                    </span>
                  )}
                </button>
                {showNotifications && (
                  <NotificationPanel
                    notifications={notifications}
                    onClose={() => setShowNotifications(false)}
                    onNotificationClick={handleNotificationClick}
                    onMarkAllRead={handleMarkAllRead}
                  />
                )}
              </div>
              <div className="ml-3 relative" ref={profileMenuRef}>
                <div>
                  <button
                    onClick={() => setShowProfileMenu(!showProfileMenu)}
                    className="max-w-xs bg-gray-800 rounded-full flex items-center text-sm focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-800 focus:ring-white"
                  >
                    <div className="flex items-center space-x-2 px-3 py-2">
                      <User className="h-5 w-5 text-gray-300" />
                      <span className="text-gray-300 text-sm">{user?.email}</span>
                      <ChevronDown className="h-4 w-4 text-gray-300" />
                    </div>
                  </button>
                </div>
                {showProfileMenu && (
                  <div className="origin-top-right absolute right-0 mt-2 w-48 rounded-md shadow-lg py-1 bg-gray-800 ring-1 ring-black ring-opacity-5 focus:outline-none">
                    <div className="px-4 py-2 text-sm text-gray-400 border-b border-gray-700">
                      <p className="font-medium">{user?.role}</p>
                      <p>{user?.employeeId}</p>
                    </div>
                    <button
                      onClick={handleLogout}
                      className="flex items-center w-full px-4 py-2 text-sm text-gray-300 hover:bg-gray-700"
                    >
                      <LogOut className="h-4 w-4 mr-2" />
                      Logout
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
          <div className="md:hidden">
            <button
              onClick={() => setShowMobileMenu(!showMobileMenu)}
              className="inline-flex items-center justify-center p-2 rounded-md text-gray-400 hover:text-white hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white"
            >
              {showMobileMenu ? <X className="block h-6 w-6" /> : <Menu className="block h-6 w-6" />}
            </button>
          </div>
        </div>
      </div>
      {showMobileMenu && (
        <div className="md:hidden">
          <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3 bg-gray-800">
            {navigationItems.map((item) => (
              <Link
                key={item.name}
                to={item.href}
                className="text-gray-300 hover:bg-gray-700 hover:text-white block px-3 py-2 rounded-md text-base font-medium"
                onClick={() => setShowMobileMenu(false)}
              >
                {item.name}
              </Link>
            ))}
            <div className="border-t border-gray-700 pt-2">
              <button
                onClick={() => {
                  handleNotificationClick(notifications[0]);
                  setShowMobileMenu(false);
                }}
                className="text-gray-300 hover:bg-gray-700 hover:text-white block px-3 py-2 rounded-md text-base font-medium w-full text-left flex items-center space-x-2"
              >
                <Bell className="h-5 w-5" />
                <span>Notifications</span>
                {unreadCount > 0 && (
                  <span className="bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
                    {unreadCount}
                  </span>
                )}
              </button>
            </div>
            <button
              onClick={handleLogout}
              className="text-gray-300 hover:bg-gray-700 hover:text-white block px-3 py-2 rounded-md text-base font-medium w-full text-left"
            >
              Logout
            </button>
          </div>
        </div>
      )}
      {showNotificationModal && selectedNotification && (
        <NotificationDetailModal
          notification={selectedNotification}
          onClose={() => setShowNotificationModal(false)}
        />
      )}
    </nav>
  );
};

export default Navbar;