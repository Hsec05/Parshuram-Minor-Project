import React, { useState, useEffect } from 'react';
// @ts-ignore
import api from '../../api/axios';

// Correct path: two levels up to context/
import { useAuth } from '../../context/AuthContext';
import AdminPage from '../Admin/AdminPage';
import { ThreatLog, Notification } from '../../types/index'; // Ensure types are imported correctly
import {
    Shield,
    AlertTriangle,
    CheckCircle,
    Clock,
    Bell,
    TrendingUp,
    Activity,
    Server,
    Loader
} from 'lucide-react';
import {
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    PieChart,
    Pie,
    Cell,
    LineChart,
    Line
} from 'recharts';
import NotificationPanel from './NotificationPanel'; // Assuming this component is correct

// Utility function to get a cookie by name
// const getCookie = (name: string): string | null => {
//   const nameEQ = name + "=";
//   const ca = document.cookie.split(';');
//   for(let i = 0; i < ca.length; i++) {
//     let c = ca[i];
//     while (c.charAt(0) === ' ') c = c.substring(1, c.length);
//     if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
//   }
//   return null;
// }

// --- Analyst Dashboard View Logic (Original Content) ---
const AnalystDashboardView: React.FC<{ user: any }> = ({ user }) => {
    const [threatStats, setThreatStats] = useState<any | null>(null);
    const [threatTrends, setThreatTrends] = useState<any[]>([]);
    const [deviceThreats, setDeviceThreats] = useState<any[]>([]);
    const [recentThreats, setRecentThreats] = useState<ThreatLog[]>([]);
    const [notifications, setNotifications] = useState<Notification[]>([]);
    const [isLoadingData, setIsLoadingData] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [showNotifications, setShowNotifications] = useState(false);

    // const BASE_URL = 'http://localhost:3001/api';

    // FIX 1: Update the function signature to accept the full Notification object
    const handleNotificationClick = (notification: Notification) => {
        console.log(`Notification clicked: ${notification.id} - ${notification.message}`);
        // Add logic to mark as read and show detail modal
    };
    const handleMarkAllRead = () => {
        console.log('Marking all notifications as read');
        // Add API call to clear notifications
    };

    const getSeverityColor = (severity: string): string => {
        switch (severity?.toLowerCase()) {
            case 'critical': return 'bg-red-900 text-red-300';
            case 'high': return 'bg-orange-900 text-orange-300';
            case 'medium': return 'bg-yellow-900 text-yellow-300';
            case 'low': return 'bg-blue-900 text-blue-300';
            default: return 'bg-gray-400';
        }
    };


    const fetchDashboardData = async () => {
        setIsLoadingData(true);
        setError(null);

        //     const AUTH_TOKEN = getCookie('sessionId'); 

        //     if (!AUTH_TOKEN) {
        //       setError("Authorization token not found. Please log in.");
        //       setIsLoadingData(false);
        //       return;
        //     }

        //     const authHeaders = {
        //       'Content-Type': 'application/json',
        //       'Authorization': `Bearer ${AUTH_TOKEN}`
        //     };

        try {
            const end = new Date();
            const start = new Date();
            start.setMonth(start.getMonth() - 1);

            const responses = await Promise.all([
                api.get('/threats/stats'),
                api.get('/threats/trends', { params: { startDate: start.toISOString(), endDate: end.toISOString(), interval: 'day' } }),
                api.get('/threats/by-device'),
                api.get('/threats/recent'),
                api.get('/threats/notifications')
            ]);


            for (const response of responses) {
                if (response.status < 200 || response.status >= 300) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
            }


            const [statsData, trendsData, deviceData, recentData, notificationsData] = responses.map((r: { data: any; }) => r.data);
            console.log("TREND DATA:", trendsData);


            // Assuming statsData returns {totalThreats, processingTickets, resolvedTickets, criticalThreats}
            setThreatStats({
                total: statsData.totalThreats,
                processing: statsData.processingTickets,
                resolved: statsData.resolvedTickets,
                critical: statsData.criticalThreats,
            });
            setThreatTrends(
                trendsData.map((item: any) => ({
                    name: item.name,           // e.g. "2025-10"
                    threats: item.threats || 0,
                    resolved: item.resolved || 0
                }))
            );
            setDeviceThreats(deviceData);
            setRecentThreats(recentData);
            setNotifications(notificationsData);

        } catch (err: any) {
            console.error("Failed to fetch dashboard data:", err);
            setError("Failed to load dashboard data. Please check the backend server and ensure the token is valid.");
        } finally {
            setIsLoadingData(false);
        }
    };

    const sessionId = user?.sessionId;

    useEffect(() => {
        if (user) {
            fetchDashboardData();
        }
    }, [user]);

    const unreadCount = notifications.filter(n => !n.read).length;

    if (isLoadingData) {
        return <div className="text-white text-center py-12"><Loader className="h-6 w-6 animate-spin mx-auto" /> Loading Analyst Data...</div>;
    }

    if (error) {
        return <div className="text-red-400 text-center py-12">Error: {error}</div>;
    }

    // Use a default empty object for threatStats if it's null to prevent errors
    const stats = threatStats ?? {
        total: 0,
        processing: 0,
        resolved: 0,
        critical: 0,
    };


    // --- Analyst Dashboard JSX (Original Content) ---
    return (
        <div className="px-4 py-6">
            <div className="mb-8 flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold text-white mb-2">Security Dashboard</h1>
                    <p className="text-gray-400">Real-time overview of your security posture</p>
                </div>
                <button
                    onClick={() => setShowNotifications(!showNotifications)}
                    className="relative text-white p-2 rounded-full hover:bg-gray-700 transition-colors"
                >
                    <Bell className="h-6 w-6" />
                    {unreadCount > 0 && (
                        <span className="absolute top-0 right-0 inline-flex items-center justify-center h-5 w-5 rounded-full bg-red-600 text-white text-xs font-bold transform translate-x-1 -translate-y-1">
                            {unreadCount}
                        </span>
                    )}
                </button>
            </div>

            {/* Stats Overview */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-gray-400 text-sm">Total Threats</p>
                            <p className="text-2xl font-bold text-white">{stats.total || 0}</p>
                        </div>
                        <Shield className="h-8 w-8 text-blue-500" />
                    </div>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-gray-400 text-sm">Being Processed</p>
                            <p className="text-2xl font-bold text-yellow-400">{stats.processing || 0}</p>
                        </div>
                        <Clock className="h-8 w-8 text-yellow-500" />
                    </div>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-gray-400 text-sm">Resolved</p>
                            <p className="text-2xl font-bold text-green-400">{stats.resolved || 0}</p>
                        </div>
                        <CheckCircle className="h-8 w-8 text-green-500" />
                    </div>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-gray-400 text-sm">Critical Active</p>
                            <p className="text-2xl font-bold text-red-400">{stats.critical || 0}</p>
                        </div>
                        <AlertTriangle className="h-8 w-8 text-red-500" />
                    </div>
                </div>
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
                {/* Threat Trends */}
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <div className="flex items-center space-x-2 mb-4">
                        <TrendingUp className="h-5 w-5 text-blue-500" />
                        <h3 className="text-lg font-semibold text-white">Threat Trends</h3>
                    </div>
                    <ResponsiveContainer width="100%" height={300}>
                        <LineChart data={threatTrends}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                            <XAxis
                                dataKey="name"
                                stroke="#9CA3AF"
                                tickFormatter={(value) => {
                                    if (value.includes("T")) return value.split("T")[0]; // Remove time
                                    return value;
                                }}
                            />
                            <YAxis stroke="#9CA3AF" />

                            <Tooltip
                                contentStyle={{
                                    backgroundColor: '#1F2937',
                                    border: '1px solid #374151',
                                    borderRadius: '8px'
                                }}
                                labelFormatter={(val) => `Date: ${val}`}
                            />

                            <Line
                                type="monotone"
                                dataKey="threats"
                                stroke="#EF4444"
                                strokeWidth={2}
                                dot={{ r: 4 }}
                                name="Threats Detected"
                            />

                            {/* <Line
                                type="monotone"
                                dataKey="resolved"
                                stroke="#10B981"
                                strokeWidth={2}
                                dot={{ r: 4 }}
                                name="Threats Resolved"
                            /> */}
                        </LineChart>
                    </ResponsiveContainer>
                </div>

                {/* Device-specific Threats */}
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <div className="flex items-center space-x-2 mb-4">
                        <Server className="h-5 w-5 text-green-500" />
                        <h3 className="text-lg font-semibold text-white">Threats by Device Type</h3>
                    </div>
                    <ResponsiveContainer width="100%" height={300}>
                        <PieChart>
                            <Pie
                                data={deviceThreats}
                                cx="50%"
                                cy="50%"
                                outerRadius={100}
                                fill="#8884d8"
                                dataKey="value"
                                label={({ name, percent }: { name?: string, percent?: number }) => {
                                    if (name && percent !== undefined) {
                                        return `${name} ${(percent * 100).toFixed(0)}%`;
                                    }
                                    return '';
                                }}
                            >
                                {deviceThreats.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={entry.color} />
                                ))}
                            </Pie>
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: '#1F2937',
                                    border: '1px solid #374151',
                                    borderRadius: '8px'
                                }}
                            />
                        </PieChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Recent Threats */}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                <div className="flex items-center space-x-2 mb-4">
                    <Activity className="h-5 w-5 text-red-500" />
                    <h3 className="text-lg font-semibold text-white">Recent Threat Activity</h3>
                </div>
                <div className="space-y-3">
                    {recentThreats.length > 0 ? (
                        recentThreats.map((threat) => (
                            <div key={threat.id} className="flex items-start justify-between p-3 bg-gray-700 rounded-lg">
                                <div className="flex-1">
                                    <div className="flex items-center space-x-2 mb-1">
                                        <span className={`px-2 py-1 rounded text-xs font-medium capitalize ${getSeverityColor(threat.severity)}`}>
                                            {threat.severity}
                                        </span>
                                        <span className="text-gray-400 text-sm">{threat.agent_id}</span>
                                    </div>
                                    <p className="text-white text-sm">{threat.message}</p>
                                </div>
                                <div className="text-gray-400 text-sm">
                                    {new Date(threat.timestamp).toLocaleTimeString()}
                                </div>
                            </div>
                        ))
                    ) : (
                        <p className="text-gray-500 text-center">No recent threats found.</p>
                    )}
                </div>
            </div>

            {/* Notification Panel */}
            {showNotifications && (
                <NotificationPanel
                    notifications={notifications}
                    onClose={() => setShowNotifications(false)}
                    onNotificationClick={handleNotificationClick}
                    onMarkAllRead={handleMarkAllRead}
                />
            )}
        </div>
    );
}

// --- Main Dashboard Component (Role Router) ---

const Dashboard: React.FC = () => {
    // FIX 2: Assume the correct property in AuthContext is named 'loading' or 'isAuthenticating' 
    // since 'isLoading' caused a TypeScript error. We'll use 'loading' for now.
    const { user, isAuthenticated, isInitialized } = useAuth();

    // Define roles that get the Admin view. Normalizing to lowercase for comparison.
    const adminRoles = ['superadmin', 'admin'];

    if (!isInitialized) {
        return (
            <div className="min-h-screen bg-gray-900 flex items-center justify-center text-white">
                <Loader className="h-6 w-6 animate-spin mr-2" /> Authenticating User Role...
            </div>
        );
    }

    // FIX: This check is redundant if the component relies on the PrivateRoute/Router
    // to enforce authentication. However, since we need to prevent unauthorized access
    // if the user is not authenticated after init, we add a clear error state.
    if (!isAuthenticated) {
        return (
            <div className="min-h-screen bg-gray-900 flex flex-col items-center justify-center text-red-400">
                <AlertTriangle className="h-10 w-10 mb-4" />
                <p className="text-lg">Access Denied: Please log in to view the dashboard.</p>
            </div>
        );
    }

    // Determine if the user is an admin-level role
    const isUserAdmin = adminRoles.includes(user?.role?.toLowerCase() || '');

    // Conditional rendering based on role
    if (isUserAdmin) {
        return <AdminPage />;
    }

    // Default: Render the Analyst view
    return <AnalystDashboardView user={user} />;
};

export default Dashboard;
