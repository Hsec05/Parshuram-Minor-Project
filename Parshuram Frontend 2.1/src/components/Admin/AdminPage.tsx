import React, { useState, useEffect } from 'react';
import api from '../../api/axios';
import { Link } from "react-router-dom";

// Corrected path assuming AuthContext is one level up from the current directory
import { useAuth } from '../../context/AuthContext'; 
import { 
  Shield, 
  Users, 
  Settings, 
  Activity, 
  Database,
  Server,
  Lock,
  Eye,
  UserPlus,
  Trash2,
  Edit,
  AlertTriangle
} from 'lucide-react';




interface User {
  id: string;
  email: string;
  role: string;
  employeeId: string;
  status: string;
  lastLogin: string;
  createdAt: string;
}

interface SystemStats {
    totalUsers: number;
    activeUsers: number;
    totalAgents: number;
    activeAgents: number;
    totalRules: number;
    activeRules: number;
    storageUsed: string;
    storageTotal: string;
}

interface ActivityLog {
    message: string;
    timestamp: string;
    type: string;
    severity: string;
    email: string;
}



const AdminPage: React.FC = () => {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('users');
  
  // State for fetched data
  const [users, setUsers] = useState<User[]>([]);
  const [systemStats, setSystemStats] = useState<SystemStats | null>(null);
  const [activityLogs, setActivityLogs] = useState<ActivityLog[]>([]);
  
  // Loading and Error States
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Function to fetch data from a given endpoint
// Remove getCookie function entirely

const fetchData = async <T,>(endpoint: string): Promise<T | null> => {
  try {
    const response = await api.get<T>(`/admin${endpoint}`);
    return response.data;
  } catch (err: any) {
    if (err.response?.status === 401) {
      setError("Session expired or invalid. Please log in again.");
    } else {
      console.error(`Error fetching ${endpoint}:`, err.response?.data || err.message);
      setError(`Failed to load data for ${endpoint}.`);
    }
    return null;
  }
};

const fetchst = async <T,>(endpoint: string): Promise<T | null> => {
  try {
    const response = await api.get<T>(`/threats${endpoint}`);
    return response.data;
  } catch (err: any) {
    if (err.response?.status === 401) {
      setError("Session expired or invalid. Please log in again.");
    } else {
      console.error(`Error fetching ${endpoint}:`, err.response?.data || err.message);
      setError(`Failed to load data for ${endpoint}.`);
    }
    return null;
  }
};

var agents = [];

const fetchagt = async <T,>(endpoint: string): Promise<T | null> => {
  try {
    const response = await api.get<T>(`/agents/list`);
    agents = response.data;
    return response.data;
  } catch (err: any) {
    if (err.response?.status === 401) {
      setError("Session expired or invalid. Please log in again.");
    } else {
      console.error(`Error fetching ${endpoint}:`, err.response?.data || err.message);
      setError(`Failed to load data for ${endpoint}.`);
    }
    return null;
  }
};

  useEffect(() => {
  let isDataLoaded = false; // ✅ Prevent multiple triggers

  const loadData = async () => {
    if (isDataLoaded) return; // ✅ Skip if already called
    isDataLoaded = true;

    setIsLoading(true);
    setError(null);

    if (!user || !['admin', 'superadmin', 'l4'].includes(user.role.toLowerCase())) {
      setIsLoading(false);
      return;
    }

    try {
      // ✅ Use Promise.all to fetch concurrently but safely
      const responses/*[usersData, statsData, activityData]*/ = await Promise.allSettled([
        fetchData<User[]>('/users'),
        fetchst<SystemStats>('/stats'),
        fetchData<ActivityLog[]>('/activity'),
        fetchagt<ActivityLog[]>('/activity')
      ]);

      const usersData = responses[0].status === 'fulfilled' ? responses[0].value : null;
      const statsData = responses[1].status === 'fulfilled' ? responses[1].value : null;
      const activityData = responses[2].status === 'fulfilled' ? responses[2].value : null;

      // Set default values if fetching failed
      if (!statsData) {
      setSystemStats({
          totalUsers: 0,
    activeUsers: 0,
    totalAgents: 0,
    activeAgents: 0,
    totalRules: 0,
    activeRules: 0,
    storageUsed: '0GB',
    storageTotal: '0GB'
      });
} else {
  setSystemStats(statsData);
}

      if (usersData) setUsers(usersData);
      if (statsData) setSystemStats(statsData);
      if (activityData) setActivityLogs(activityData);
    } catch (err) {
      console.error('Error fetching admin data:', err);
      setError('Failed to fetch admin data');
    } finally {
      setIsLoading(false);
    }
  };

  if (user && !isDataLoaded) {
    loadData();
  }

  // ✅ Cleanup to ensure the flag resets if component unmounts
  return () => {
    isDataLoaded = true;
  };
}, [user]);


  // Only admin/superadmin/L4 can access this page
  if (!user || (user.role !== 'admin')) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full text-center">
          <Shield className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-white mb-4">Access Denied</h1>
          <p className="text-gray-300 mb-6">
            Only administrators can access this panel. Your role: {user?.role || 'Guest'}
          </p>
        </div>
      </div>
    );
  }

  // Loading State
  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center text-white text-xl">
        Loading Admin Data...
      </div>
    );
  }

  // Error State
  if (error) {
    return (
        <div className="min-h-screen bg-gray-900 flex items-center justify-center py-12 px-4">
            <div className="bg-red-900/50 border border-red-700 p-6 rounded-lg text-red-300 flex items-center space-x-3">
                <AlertTriangle className="h-6 w-6" />
                <span>Error: {error}</span>
            </div>
        </div>
    );
  }
  
  // Helper functions using fetched data
  const stats = systemStats || {} as SystemStats; // Default empty object if null

  const getRoleColor = (role: string) => {
    if (role.toLowerCase().includes('admin') || role.toLowerCase() === 'l4') return 'bg-red-900 text-red-300';
    if (role.toLowerCase().startsWith('l')) return 'bg-blue-900 text-blue-300';
    return 'bg-gray-900 text-gray-300';
  };

  const getStatusColor = (status: string) => {
    // Assuming status logic needs to be defined in the backend/frontend logic
    return status === 'active' 
      ? 'bg-green-900 text-green-300' 
      : 'bg-red-900 text-red-300';
  };
  
  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
        case 'critical': return 'bg-red-900 text-red-300';
        case 'high': return 'bg-orange-900 text-orange-300';
        case 'medium': return 'bg-yellow-900 text-yellow-300';
        case 'low': return 'bg-blue-900 text-blue-300';
        default: return 'bg-gray-900 text-gray-300';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };


  return (
    <div className="px-4 py-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Admin Panel</h1>
        <p className="text-gray-400">Manage users, system settings, and monitor platform health.</p>
      </div>

      {/* System Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Users</p>
              <p className="text-2xl font-bold text-white">{users.length || 0}</p>
            </div>
            <Users className="h-8 w-8 text-blue-500" />
          </div>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Active Agents</p>
              <p className="text-2xl font-bold text-green-400">{2}/{2}</p>
            </div>
            <Server className="h-8 w-8 text-green-500" />
          </div>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Rules</p>
              <p className="text-2xl font-bold text-yellow-400">{stats.totalRules || 158}</p>
            </div>
            <Shield className="h-8 w-8 text-yellow-500" />
          </div>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Storage Used</p>
              <p className="text-2xl font-bold text-orange-400">{stats.storageUsed || '1GB'}</p>
            </div>
            <Database className="h-8 w-8 text-orange-500" />
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6">
        <div className="border-b border-gray-700">
          <nav className="-mb-px flex space-x-8">
            <button
              onClick={() => setActiveTab('users')}
              className={`py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'users'
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-gray-300 hover:border-gray-300'
              }`}
            >
              <Users className="h-4 w-4 inline mr-2" />
              User Management
            </button>
            <button
              onClick={() => setActiveTab('system')}
              className={`py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'system'
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-gray-300 hover:border-gray-300'
              }`}
            >
              <Settings className="h-4 w-4 inline mr-2" />
              System Settings
            </button>
            <button
              onClick={() => setActiveTab('activity')}
              className={`py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'activity'
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-gray-300 hover:border-gray-300'
              }`}
            >
              <Activity className="h-4 w-4 inline mr-2" />
              Activity Logs
            </button>
          </nav>
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === 'users' && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg">
          <div className="p-6 border-b border-gray-700">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-semibold text-white">User Management ({users.length})</h3>
              <Link to="/register">
              <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2">
                <UserPlus className="h-4 w-4" />
                <span>Add User</span>
              </button>
              </Link>
            </div>
          </div>
          
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                    User
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                    Role
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                    Last Login / Created
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {users.length > 0 ? (
                    users.map((user) => (
                    <tr key={user.id} className="hover:bg-gray-700 transition-colors">
                        <td className="px-6 py-4 whitespace-nowrap">
                        <div>
                            <div className="text-sm font-medium text-white">{user.email}</div>
                            <div className="text-sm text-gray-400">{user.employeeId}</div>
                        </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 py-1 rounded-full text-xs font-medium capitalize ${getRoleColor(user.role)}`}>
                            {user.role}
                        </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 py-1 rounded-full text-xs font-medium capitalize ${getStatusColor(user.status)}`}>
                            {user.status}
                        </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                        {formatTimestamp(user.lastLogin)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <div className="flex space-x-2">
                            <button className="text-blue-400 hover:text-blue-300 transition-colors">
                            <Edit className="h-4 w-4" />
                            </button>
                            <button className="text-gray-400 hover:text-gray-300 transition-colors">
                            <Eye className="h-4 w-4" />
                            </button>
                            <button className="text-red-400 hover:text-red-300 transition-colors">
                            <Trash2 className="h-4 w-4" />
                            </button>
                        </div>
                        </td>
                    </tr>
                    ))
                ) : (
                    <tr>
                        <td colSpan={5} className="px-6 py-4 text-center text-gray-400">No users found.</td>
                    </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'system' && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">System Configuration</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 bg-gray-700 rounded-lg">
              <div className="flex items-center space-x-3">
                <Lock className="h-5 w-5 text-blue-500" />
                <div>
                  <p className="text-white font-medium">Security Settings</p>
                  <p className="text-gray-400 text-sm">Configure authentication and access controls</p>
                </div>
              </div>
              <button className="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">
                Configure
              </button>
            </div>
            
            <div className="flex items-center justify-between p-4 bg-gray-700 rounded-lg">
              <div className="flex items-center space-x-3">
                <Database className="h-5 w-5 text-green-500" />
                <div>
                  <p className="text-white font-medium">Database Settings</p>
                  <p className="text-gray-400 text-sm">Manage database connections and storage</p>
                </div>
              </div>
              <button className="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">
                Configure
              </button>
            </div>
            
            <div className="flex items-center justify-between p-4 bg-gray-700 rounded-lg">
              <div className="flex items-center space-x-3">
                <Server className="h-5 w-5 text-orange-500" />
                <div>
                  <p className="text-white font-medium">Agent Configuration</p>
                  <p className="text-gray-400 text-sm">Configure agent settings and deployment</p>
                </div>
              </div>
              <button className="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">
                Configure
              </button>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'activity' && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Recent Activity Logs ({activityLogs.length})</h3>
          <div className="space-y-3">
            {activityLogs.length > 0 ? (
                activityLogs.map((log, index) => (
                    <div key={index} className="flex items-start space-x-3 p-3 bg-gray-700 rounded-lg">
                        <div className={`w-2 h-2 rounded-full ${getSeverityColor(log.severity).replace('bg-', 'bg-')}`}></div>
                        <div className="flex-1">
                            <p className="text-white text-sm">{log.message}</p>
                            <p className="text-gray-400 text-xs mt-1">
                                <span className={`px-2 py-0.5 rounded-full text-xs font-medium capitalize ${getSeverityColor(log.severity)}`}>
                                    {log.severity}
                                </span>
                                <span className="ml-2 text-gray-500">[{log.type}]</span>
                                <span className="ml-2 text-gray-500">by {log.email}</span>
                            </p>
                        </div>
                        <div className="text-gray-400 text-xs">{formatTimestamp(log.timestamp)}</div>
                    </div>
                ))
            ) : (
                <p className="text-gray-500 text-center">No recent activity found.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminPage;
