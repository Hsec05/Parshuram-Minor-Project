// import React, { useState, useRef } from 'react';
// import { Agent } from '../../types';
// import { 
//   Server, 
//   Search, 
//   Filter, 
//   Eye, 
//   MapPin, 
//   Clock, 
//   AlertTriangle,
//   CheckCircle,
//   XCircle,
//   Activity,
//   Shield,
//   Monitor
// } from 'lucide-react';

// import { useNavigate } from 'react-router-dom';
// import { useOnClickOutside } from '../../hooks/useOnClickOutside';

// const AgentsPage: React.FC = () => {
//   const [searchTerm, setSearchTerm] = useState('');
//   const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
//   const [showAgentModal, setShowAgentModal] = useState(false);
//   const [filters, setFilters] = useState({
//     status: '',
//     location: '',
//     os: ''
//   });
//   const [showFilters, setShowFilters] = useState(false);

// const navigate = useNavigate();
// const modalRef = useRef<HTMLDivElement>(null);
// useOnClickOutside(modalRef, () => setShowAgentModal(false));

//   // Mock data - replace with real API calls
//   const [agents] = useState<Agent[]>([
//     {
//       id: 'WIN-001',
//       name: 'DESKTOP-ABC123',
//       ip: '192.168.1.100',
//       location: 'New York Office',
//       os: 'Windows 11 Pro',
//       version: '22H2',
//       status: 'active',
//       lastSeen: '2025-01-02T14:30:00Z',
//       uptime: '15 days, 4 hours',
//       geolocation: {
//         lat: 40.7128,
//         lng: -74.0060,
//         city: 'New York',
//         country: 'USA'
//       },
//       alertsCount: 2,
//       threatsCount: 5
//     },
//     {
//       id: 'LIN-003',
//       name: 'SERVER-XYZ789',
//       ip: '192.168.1.102',
//       location: 'San Francisco Office',
//       os: 'Ubuntu 22.04 LTS',
//       version: '5.15.0-91',
//       status: 'active',
//       lastSeen: '2025-01-02T14:25:00Z',
//       uptime: '45 days, 12 hours',
//       geolocation: {
//         lat: 37.7749,
//         lng: -122.4194,
//         city: 'San Francisco',
//         country: 'USA'
//       },
//       alertsCount: 0,
//       threatsCount: 3
//     },
//     {
//       id: 'NET-005',
//       name: 'FIREWALL-001',
//       ip: '192.168.1.50',
//       location: 'Austin Office',
//       os: 'pfSense 2.7.0',
//       version: '2.7.0-RELEASE',
//       status: 'disconnected',
//       lastSeen: '2025-01-02T12:15:00Z',
//       uptime: '0 days, 0 hours',
//       geolocation: {
//         lat: 30.2672,
//         lng: -97.7431,
//         city: 'Austin',
//         country: 'USA'
//       },
//       alertsCount: 1,
//       threatsCount: 0
//     },
//     {
//       id: 'MAC-007',
//       name: 'MACBOOK-DEV01',
//       ip: '192.168.1.105',
//       location: 'Remote - Seattle',
//       os: 'macOS Sonoma',
//       version: '14.2.1',
//       status: 'maintenance',
//       lastSeen: '2025-01-02T10:00:00Z',
//       uptime: '0 days, 0 hours',
//       geolocation: {
//         lat: 47.6062,
//         lng: -122.3321,
//         city: 'Seattle',
//         country: 'USA'
//       },
//       alertsCount: 0,
//       threatsCount: 1
//     }
//   ]);

//   const getStatusIcon = (status: Agent['status']) => {
//     switch (status) {
//       case 'active': return <CheckCircle className="h-5 w-5 text-green-500" />;
//       case 'disconnected': return <XCircle className="h-5 w-5 text-red-500" />;
//       case 'maintenance': return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
//       default: return <XCircle className="h-5 w-5 text-gray-500" />;
//     }
//   };

//   const getStatusColor = (status: Agent['status']) => {
//     switch (status) {
//       case 'active': return 'bg-green-900 text-green-300 border-green-500';
//       case 'disconnected': return 'bg-red-900 text-red-300 border-red-500';
//       case 'maintenance': return 'bg-yellow-900 text-yellow-300 border-yellow-500';
//       default: return 'bg-gray-900 text-gray-300 border-gray-500';
//     }
//   };

//   const filteredAgents = agents.filter(agent => {
//     const matchesSearch = !searchTerm || 
//       agent.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
//       agent.ip.includes(searchTerm) ||
//       agent.id.toLowerCase().includes(searchTerm.toLowerCase());

//     const matchesFilters = 
//       (!filters.status || agent.status === filters.status) &&
//       (!filters.location || agent.location.toLowerCase().includes(filters.location.toLowerCase())) &&
//       (!filters.os || agent.os.toLowerCase().includes(filters.os.toLowerCase()));

//     return matchesSearch && matchesFilters;
//   });

//   const handleViewAgent = (agent: Agent) => {
//     setSelectedAgent(agent);
//     setShowAgentModal(true);
//   };

//   const formatTimestamp = (timestamp: string) => {
//     return new Date(timestamp).toLocaleString();
//   };

//   const getTimeAgo = (timestamp: string) => {
//     const now = new Date();
//     const time = new Date(timestamp);
//     const diffInMinutes = Math.floor((now.getTime() - time.getTime()) / (1000 * 60));
    
//     if (diffInMinutes < 60) {
//       return `${diffInMinutes}m ago`;
//     } else if (diffInMinutes < 1440) {
//       return `${Math.floor(diffInMinutes / 60)}h ago`;
//     } else {
//       return `${Math.floor(diffInMinutes / 1440)}d ago`;
//     }
//   };

//   return (
//     <div className="px-4 py-6">
//       <div className="mb-8">
//         <h1 className="text-3xl font-bold text-white mb-2">Agent Management</h1>
//         <p className="text-gray-400">Monitor and manage all security agents across your infrastructure.</p>
//       </div>

//       {/* Search and Filter Bar */}
//       <div className="mb-6 space-y-4">
//         <div className="flex space-x-4">
//           <div className="flex-1 relative">
//             <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
//             <input
//               type="text"
//               placeholder="Search agents..."
//               className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
//               value={searchTerm}
//               onChange={(e) => setSearchTerm(e.target.value)}
//             />
//           </div>
//           <button
//             onClick={() => setShowFilters(!showFilters)}
//             className="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 transition-colors flex items-center space-x-2"
//           >
//             <Filter className="h-4 w-4" />
//             <span>Filters</span>
//           </button>
//         </div>

//         {showFilters && (
//           <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
//             <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
//               <select
//                 className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
//                 value={filters.status}
//                 onChange={(e) => setFilters({ ...filters, status: e.target.value })}
//               >
//                 <option value="">All Statuses</option>
//                 <option value="active">Active</option>
//                 <option value="disconnected">Disconnected</option>
//                 <option value="maintenance">Maintenance</option>
//               </select>
//               <input
//                 type="text"
//                 placeholder="Filter by location"
//                 className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
//                 value={filters.location}
//                 onChange={(e) => setFilters({ ...filters, location: e.target.value })}
//               />
//               <input
//                 type="text"
//                 placeholder="Filter by OS"
//                 className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
//                 value={filters.os}
//                 onChange={(e) => setFilters({ ...filters, os: e.target.value })}
//               />
//             </div>
//           </div>
//         )}
//       </div>

//       {/* Agents Grid */}
//       <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
//         {filteredAgents.map((agent) => (
//           <div
//             key={agent.id}
//             className="bg-gray-800 border border-gray-700 rounded-lg p-6 hover:border-gray-600 transition-colors"
//           >
//             <div className="flex items-start justify-between mb-4">
//               <div className="flex items-center space-x-3">
//                 {getStatusIcon(agent.status)}
//                 <div>
//                   <h3 className="text-lg font-semibold text-white">{agent.name}</h3>
//                   <p className="text-sm text-gray-400">{agent.id}</p>
//                 </div>
//               </div>
//               <button
//                 onClick={() => handleViewAgent(agent)}
//                 className="p-2 text-gray-400 hover:text-white transition-colors"
//               >
//                 <Eye className="h-5 w-5" />
//               </button>
//             </div>

//             <div className="space-y-2 mb-4">
//               <div className="flex items-center space-x-2 text-sm text-gray-300">
//                 <Server className="h-4 w-4" />
//                 <span>{agent.ip}</span>
//               </div>
//               <div className="flex items-center space-x-2 text-sm text-gray-300">
//                 <MapPin className="h-4 w-4" />
//                 <span>{agent.location}</span>
//               </div>
//               <div className="flex items-center space-x-2 text-sm text-gray-300">
//                 <Monitor className="h-4 w-4" />
//                 <span>{agent.os}</span>
//               </div>
//               <div className="flex items-center space-x-2 text-sm text-gray-300">
//                 <Clock className="h-4 w-4" />
//                 <span>Last seen: {getTimeAgo(agent.lastSeen)}</span>
//               </div>
//             </div>

//             <div className="flex items-center justify-between">
//               <span className={`px-2 py-1 rounded-full text-xs font-medium border capitalize ${getStatusColor(agent.status)}`}>
//                 {agent.status}
//               </span>
//               <div className="flex items-center space-x-4 text-sm">
//                 <div className="flex items-center space-x-1 text-red-400">
//                   <AlertTriangle className="h-4 w-4" />
//                   <span>{agent.alertsCount}</span>
//                 </div>
//                 <div className="flex items-center space-x-1 text-orange-400">
//                   <Shield className="h-4 w-4" />
//                   <span>{agent.threatsCount}</span>
//                 </div>
//               </div>
//             </div>
//           </div>
//         ))}
//       </div>

//       {filteredAgents.length === 0 && (
//         <div className="text-center py-12 bg-gray-800 border border-gray-700 rounded-lg">
//           <Server className="h-16 w-16 text-gray-600 mx-auto mb-4" />
//           <h3 className="text-xl font-medium text-gray-400 mb-2">No agents found</h3>
//           <p className="text-gray-500">Try adjusting your search or filter criteria.</p>
//         </div>
//       )}

//       {/* Agent Detail Modal */}
//       {showAgentModal && selectedAgent && (
//         <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
//           <div className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full max-h-[85vh] overflow-y-auto">
//             <div className="flex items-center justify-between p-6 border-b border-gray-700">
//               <h2 className="text-xl font-bold text-white flex items-center space-x-2">
//                 <Server className="h-6 w-6 text-blue-500" />
//                 <span>Agent Details - {selectedAgent.name}</span>
//               </h2>
//               <button
//                 onClick={() => setShowAgentModal(false)}
//                 className="text-gray-400 hover:text-white transition-colors"
//               >
//                 <XCircle className="h-6 w-6" />
//               </button>
//             </div>

//             <div className="p-6 space-y-6">
//               {/* Status and Basic Info */}
//               <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//                 <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
//                   <h4 className="text-white font-medium mb-3">Status Information</h4>
//                   <div className="space-y-2">
//                     <div className="flex items-center space-x-2">
//                       {getStatusIcon(selectedAgent.status)}
//                       <span className={`px-2 py-1 rounded-full text-xs font-medium border capitalize ${getStatusColor(selectedAgent.status)}`}>
//                         {selectedAgent.status}
//                       </span>
//                     </div>
//                     <p className="text-gray-300 text-sm">Uptime: {selectedAgent.uptime}</p>
//                     <p className="text-gray-300 text-sm">Last seen: {formatTimestamp(selectedAgent.lastSeen)}</p>
//                   </div>
//                 </div>

//                 <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
//                   <h4 className="text-white font-medium mb-3">System Information</h4>
//                   <div className="space-y-2 text-sm">
//                     <p className="text-gray-300">IP: {selectedAgent.ip}</p>
//                     <p className="text-gray-300">OS: {selectedAgent.os}</p>
//                     <p className="text-gray-300">Version: {selectedAgent.version}</p>
//                     <p className="text-gray-300">Location: {selectedAgent.location}</p>
//                   </div>
//                 </div>
//               </div>

//               {/* Security Metrics */}
//               <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
//                 <h4 className="text-white font-medium mb-3">Security Metrics</h4>
//                 <div className="grid grid-cols-2 gap-4">
//                   <div className="text-center">
//                     <div className="flex items-center justify-center space-x-2 mb-2">
//                       <AlertTriangle className="h-5 w-5 text-red-500" />
//                       <span className="text-2xl font-bold text-red-400">{selectedAgent.alertsCount}</span>
//                     </div>
//                     <p className="text-gray-300 text-sm">Active Alerts</p>
//                   </div>
//                   <div className="text-center">
//                     <div className="flex items-center justify-center space-x-2 mb-2">
//                       <Shield className="h-5 w-5 text-orange-500" />
//                       <span className="text-2xl font-bold text-orange-400">{selectedAgent.threatsCount}</span>
//                     </div>
//                     <p className="text-gray-300 text-sm">Threats Detected</p>
//                   </div>
//                 </div>
//               </div>

//               {/* Actions */}
//               <div className="flex justify-end space-x-3 pt-4 border-t border-gray-700">
//                 <button
//                   onClick={() => setShowAgentModal(false)}
//                   className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors"
//                 >
//                   Close
//                 </button>
//                 <button 
//                   onClick={() => navigate('/logs')}
//                   className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
//                   View Logs
//                 </button>
//                 <button 
//                   onClick={() => navigate('/alerts')}
//                   className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors">
//                   View Alerts
//                 </button>
//               </div>
//             </div>
//           </div>
//         </div>
//       )}
//     </div>
//   );
// };

// export default AgentsPage;

import React, { useState, useRef, useEffect } from 'react';
import { Agent } from '../../types';
import {
  Server,
  Search,
  Filter,
  Eye,
  MapPin,
  Clock,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Shield,
  Monitor
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useOnClickOutside } from '../../hooks/useOnClickOutside';
import api from '../../api/axios';
import debounce from 'lodash.debounce';

const AgentsPage: React.FC = () => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [filteredAgents, setFilteredAgents] = useState<Agent[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [showAgentModal, setShowAgentModal] = useState(false);
  const [filters, setFilters] = useState({ status: '', location: '', os: '' });
  const [showFilters, setShowFilters] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const modalRef = useRef<HTMLDivElement>(null);

  useOnClickOutside(modalRef, () => closeModal());

  // Fetch agents from API
 useEffect(() => {
  const fetchAgents = async () => {
    setLoading(true);
    setError(null);

    try {
      const sessionId = localStorage.getItem('sessionId');

      if (!sessionId) {
        setError('No session found. Please log in again.');
        return;
      }

      const response = await api.get('/agents/list', {
        headers: {
          Authorization: `Bearer ${sessionId}`,
        },
      });
      console.log(response.data.agents);
      

      setAgents(response.data.agents);      // ✅ using "agents" array from response
      setFilteredAgents(response.data.agents);

    } catch (err: any) {
      console.error(err);
      setError('Failed to fetch agents. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  fetchAgents();
}, []);



  // Debounced search + filter
  useEffect(() => {
    const filterAgents = () => {
      const filtered = agents.filter(agent => {
        const matchesSearch =
          !searchTerm ||
          agent.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          agent.ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
          agent.id.toLowerCase().includes(searchTerm.toLowerCase());

        const matchesFilters =
          (!filters.status || agent.status === filters.status) &&
          (!filters.location || agent.location.toLowerCase().includes(filters.location.toLowerCase())) &&
          (!filters.os || agent.os.toLowerCase().includes(filters.os.toLowerCase()));

        return matchesSearch && matchesFilters;
      });
      setFilteredAgents(filtered);
    };

    const debounced = debounce(filterAgents, 300);
    debounced();

    return () => debounced.cancel();
  }, [agents, searchTerm, filters]);

  const getStatusIcon = (status: Agent['status']) => {
    switch (status) {
      case 'active':
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'disconnected':
        return <XCircle className="h-5 w-5 text-red-500" />;
      case 'maintenance':
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      default:
        return <XCircle className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status: Agent['status']) => {
    switch (status) {
      case 'active':
        return 'bg-green-900 text-green-300 border-green-500';
      case 'disconnected':
        return 'bg-red-900 text-red-300 border-red-500';
      case 'maintenance':
        return 'bg-yellow-900 text-yellow-300 border-yellow-500';
      default:
        return 'bg-gray-900 text-gray-300 border-gray-500';
    }
  };

  const formatTimestamp = (timestamp: string) =>
    isNaN(Date.parse(timestamp)) ? 'Invalid Date' : new Date(timestamp).toLocaleString();

  const getTimeAgo = (timestamp: string) => {
    const now = new Date();
    const time = new Date(timestamp);
    if (isNaN(time.getTime())) return 'Unknown';
    const diffInMinutes = Math.floor((now.getTime() - time.getTime()) / (1000 * 60));
    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)}h ago`;
    return `${Math.floor(diffInMinutes / 1440)}d ago`;
  };

  const handleViewAgent = (agent: Agent) => {
    setSelectedAgent(agent);
    setShowAgentModal(true);
  };

  const closeModal = () => {
    setShowAgentModal(false);
    setSelectedAgent(null);
  };

  if (loading)
    return (
      <div className="min-h-screen flex items-center justify-center text-white text-xl">
        Loading agents...
      </div>
    );

  if (error)
    return (
      <div className="min-h-screen flex items-center justify-center text-red-400 text-center px-4">
        {error}
      </div>
    );

  return (
    <div className="px-4 py-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Agent Management</h1>
        <p className="text-gray-400">Monitor and manage all security agents across your infrastructure.</p>
      </div>

      {/* Search & Filter */}
      <div className="mb-6 space-y-4">
        <div className="flex space-x-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search agents..."
              className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 transition-colors flex items-center space-x-2"
          >
            <Filter className="h-4 w-4" />
            <span>Filters</span>
          </button>
        </div>

        {showFilters && (
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <select
                className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={filters.status}
                onChange={(e) => setFilters({ ...filters, status: e.target.value })}
              >
                <option value="">All Statuses</option>
                <option value="active">Active</option>
                <option value="disconnected">Disconnected</option>
                <option value="maintenance">Maintenance</option>
              </select>
              <input
                type="text"
                placeholder="Filter by location"
                className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={filters.location}
                onChange={(e) => setFilters({ ...filters, location: e.target.value })}
              />
              <input
                type="text"
                placeholder="Filter by OS"
                className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={filters.os}
                onChange={(e) => setFilters({ ...filters, os: e.target.value })}
              />
            </div>
          </div>
        )}
      </div>

      {/* Agents Grid */}
      {filteredAgents.length === 0 ? (
        <div className="text-center py-12 bg-gray-800 border border-gray-700 rounded-lg">
          <Server className="h-16 w-16 text-gray-600 mx-auto mb-4" />
          <h3 className="text-xl font-medium text-gray-400 mb-2">No agents found</h3>
          <p className="text-gray-500">Try adjusting your search or filter criteria.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
          {filteredAgents.map((agent) => (
            <div
              key={agent.id}
              className="bg-gray-800 border border-gray-700 rounded-lg p-6 hover:border-gray-600 transition-colors"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-3">
                  {getStatusIcon(agent.status)}
                  <div>
                    <h3 className="text-lg font-semibold text-white">{agent.name}</h3>
                    <p className="text-sm text-gray-400">{agent.id}</p>
                  </div>
                </div>
                <button
                  onClick={() => handleViewAgent(agent)}
                  className="p-2 text-gray-400 hover:text-white transition-colors"
                >
                  <Eye className="h-5 w-5" />
                </button>
              </div>

              <div className="space-y-2 mb-4">
                <div className="flex items-center space-x-2 text-sm text-gray-300">
                  <Server className="h-4 w-4" />
                  <span>{agent.ip}</span>
                </div>
                <div className="flex items-center space-x-2 text-sm text-gray-300">
                  <MapPin className="h-4 w-4" />
                  <span>{agent.location}</span>
                </div>
                <div className="flex items-center space-x-2 text-sm text-gray-300">
                  <Monitor className="h-4 w-4" />
                  <span>{agent.os}</span>
                </div>
                <div className="flex items-center space-x-2 text-sm text-gray-300">
                  <Clock className="h-4 w-4" />
                  <span>Last seen: {getTimeAgo(agent.lastSeen)}</span>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <span
                  className={`px-2 py-1 rounded-full text-xs font-medium border capitalize ${getStatusColor(
                    agent.status
                  )}`}
                >
                  {agent.status}
                </span>
                <div className="flex items-center space-x-4 text-sm">
                  <div className="flex items-center space-x-1 text-red-400">
                    <AlertTriangle className="h-4 w-4" />
                    <span>{agent.alertsCount}</span>
                  </div>
                  <div className="flex items-center space-x-1 text-orange-400">
                    <Shield className="h-4 w-4" />
                    <span>{agent.threatsCount}</span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Agent Modal */}
      {showAgentModal && selectedAgent && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div ref={modalRef} className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between p-6 border-b border-gray-700">
              <h2 className="text-xl font-bold text-white flex items-center space-x-2">
                <Server className="h-6 w-6 text-blue-500" />
                <span>Agent Details - {selectedAgent.name}</span>
              </h2>
              <button onClick={closeModal} className="text-gray-400 hover:text-white transition-colors">
                <XCircle className="h-6 w-6" />
              </button>
            </div>

            <div className="p-6 space-y-6">
              {/* Status & System Info */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
                  <h4 className="text-white font-medium mb-3">Status Information</h4>
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2">
                      {getStatusIcon(selectedAgent.status)}
                      <span
                        className={`px-2 py-1 rounded-full text-xs font-medium border capitalize ${getStatusColor(
                          selectedAgent.status
                        )}`}
                      >
                        {selectedAgent.status}
                      </span>
                    </div>
                    <p className="text-gray-300 text-sm">Last seen: {formatTimestamp(selectedAgent.lastSeen)}</p>
                  </div>
                </div>

                <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
                  <h4 className="text-white font-medium mb-3">System Information</h4>
                  <div className="space-y-2 text-sm">
                    <p className="text-gray-300">IP: {selectedAgent.ip}</p>
                    <p className="text-gray-300">OS: {selectedAgent.os}</p>
                    <p className="text-gray-300">Location: {selectedAgent.location}</p>
                  </div>
                </div>
              </div>

              {/* Security Metrics */}
              <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
                <h4 className="text-white font-medium mb-3">Security Metrics</h4>
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center">
                    <div className="flex items-center justify-center space-x-2 mb-2">
                      <AlertTriangle className="h-5 w-5 text-red-500" />
                      <span className="text-2xl font-bold text-red-400">{selectedAgent.alertsCount}</span>
                    </div>
                    <p className="text-gray-300 text-sm">Active Alerts</p>
                  </div>
                  <div className="text-center">
                    <div className="flex items-center justify-center space-x-2 mb-2">
                      <Shield className="h-5 w-5 text-orange-500" />
                      <span className="text-2xl font-bold text-orange-400">{selectedAgent.threatsCount}</span>
                    </div>
                    <p className="text-gray-300 text-sm">Threats Detected</p>
                  </div>
                </div>
              </div>

              {/* Actions */}
              <div className="flex justify-end space-x-3 pt-4 border-t border-gray-700">
                <button
                  onClick={closeModal}
                  className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AgentsPage;
