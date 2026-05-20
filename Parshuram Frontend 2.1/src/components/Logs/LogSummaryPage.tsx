import React, { useEffect, useState } from 'react';
import { Log, ThreatLog, Ticket } from '../../types';
import { Search, Filter, Eye, Shield, Server, AlertTriangle, MessageSquare } from 'lucide-react';
import LogViewModal from './LogViewModal';
import TicketModal from '../Tickets/TicketModal';
import { useAuth } from '../../context/AuthContext';
import { useNavigate } from 'react-router-dom';

const API_BASE_URL = 'http://localhost:3001/api';
const LogSummaryPage: React.FC = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedLog, setSelectedLog] = useState<Log | ThreatLog | null>(null);
  const [showLogModal, setShowLogModal] = useState(false);
  const [showTicketModal, setShowTicketModal] = useState(false);
  const [isCreateTicketMode, setIsCreateTicketMode] = useState(false);
  const [tickets, setTickets] = useState<Ticket[]>([]);

  const [filters, setFilters] = useState({
    agentId: '',
    ip: '',
    os: '',
    severity: '',
    source: '',
    computer: '',
    channel: '',
    startDate: '',
    endDate: ''
  });
  const [showFilters, setShowFilters] = useState(false);

  // const [logs] = useState<(Log | ThreatLog)[]>([
  //   {
  //   } as Log
  // ]);
  const [logs, setLogs] = useState<(Log | ThreatLog)[]>([]);
  useEffect(() => {
    const fetchLogs = async () => {
      const sessionId = localStorage.getItem('sessionId');
      if (!sessionId) return;

      try {
        const response = await fetch(`${API_BASE_URL}/logs/listLogs`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${sessionId}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(filters)
        });

        if (response.ok) {
          const { logs: fetchedLogs } = await response.json();
          setLogs(fetchedLogs);
        } else {
          console.error("Failed to fetch logs");
        }
      } catch (err) {
        console.error("Error fetching logs", err);
      }
    };

    fetchLogs();
  }, [filters]);


  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <AlertTriangle className="h-4 w-4 text-red-500" />;
      case 'high': return <AlertTriangle className="h-4 w-4 text-orange-500" />;
      case 'medium': return <Shield className="h-4 w-4 text-yellow-500" />;
      case 'low': return <Shield className="h-4 w-4 text-blue-500" />;
      default: return <Shield className="h-4 w-4 text-gray-500" />;
    }
  };

  const filteredLogs = logs.filter(log => {
    const logDate = new Date(log.timeCreated);
    const startDate = filters.startDate ? new Date(filters.startDate) : null;
    const endDate = filters.endDate ? new Date(filters.endDate) : null;

    if (startDate && logDate < startDate) return false;
    if (endDate && logDate > endDate) return false;

    return (
      (filters.agentId ? log.agentId.toLowerCase().includes(filters.agentId.toLowerCase()) : true) &&
      (filters.ip ? log.ip.includes(filters.ip) : true) &&
      (filters.os ? log.os.toLowerCase().includes(filters.os.toLowerCase()) : true) &&
      (filters.severity ? log.severity === filters.severity : true) &&
      (filters.source ? log.source.toLowerCase().includes(filters.source.toLowerCase()) : true) &&
      (filters.computer ? log.computer.toLowerCase().includes(filters.computer.toLowerCase()) : true) &&
      (filters.channel ? log.channel === filters.channel : true) &&
      (searchTerm ? log.description.toLowerCase().includes(searchTerm.toLowerCase()) : true)
    );
  });

  const handleViewLog = (log: Log | ThreatLog) => {
    setSelectedLog(log);
    setShowLogModal(true);
  };

  const handleCreateTicket = (log: Log | ThreatLog) => {
    setSelectedLog(log);
    setIsCreateTicketMode(true);
    setShowTicketModal(true);
    setShowLogModal(false);
  };

  const handleMarkFalsePositive = (logId: string) => {
    console.log(`Marking log ${logId} as false positive`);
    alert(`Log ${logId} marked as false positive`);
    setShowLogModal(false);
  };

  const handleSaveTicket = (ticketData: any) => {
    const newTicket: Ticket = {
      id: `T-${String(tickets.length + 1).padStart(3, '0')}`,
      title: ticketData.title || `Log Event: ${selectedLog?.description}`,
      description: ticketData.description || `Investigation for log ID ${selectedLog?.id}`,
      severity: ticketData.severity || selectedLog?.severity || 'medium',
      status: 'open',
      assignee: ticketData.assignee || 'SOC L1',
      reporter: user?.email || 'SIEM System',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      relatedLogId: selectedLog?.id,
      attachments: ticketData.attachments || [],
      comments: [],
    };
    setTickets([newTicket, ...tickets]);
    setShowTicketModal(false);
    setIsCreateTicketMode(false);
    navigate(`/tickets/`);
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const isThreatLog = (log: Log | ThreatLog): log is ThreatLog => {
    return 'isThreat' in log && (log as any).isThreat === true;
  };

  return (
    <div className="px-4 py-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Log Summary</h1>
        <p className="text-gray-400">Monitor and analyze system logs and security events.</p>
      </div>

      <div className="mb-6 space-y-4">
        <div className="flex space-x-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search logs..."
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
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <input type="text" placeholder="Agent ID" value={filters.agentId} onChange={e => setFilters({ ...filters, agentId: e.target.value })} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded" />
            <input type="text" placeholder="IP Address" value={filters.ip} onChange={e => setFilters({ ...filters, ip: e.target.value })} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded" />
            <input type="text" placeholder="OS" value={filters.os} onChange={e => setFilters({ ...filters, os: e.target.value })} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded" />
            <select value={filters.severity} onChange={e => setFilters({ ...filters, severity: e.target.value })} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded">
              <option value="">Any Severity</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
            <input type="text" placeholder="Source" value={filters.source} onChange={e => setFilters({ ...filters, source: e.target.value })} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded" />
            <input type="text" placeholder="Computer Name" value={filters.computer} onChange={e => setFilters({ ...filters, computer: e.target.value })} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded" />
            <select value={filters.channel} onChange={e => setFilters({ ...filters, channel: e.target.value })} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded">
              <option value="">Any Channel</option>
              <option value="system">System</option>
              <option value="security">Security</option>
              <option value="application">Application</option>
            </select>
            <div className="flex items-center space-x-2">
              <label htmlFor="startDate" className="text-sm text-gray-400">From:</label>
              <input id="startDate" type="date" value={filters.startDate} onChange={e => setFilters({ ...filters, startDate: e.target.value })} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded w-full" />
            </div>
            <div className="flex items-center space-x-2">
              <label htmlFor="endDate" className="text-sm text-gray-400">To:</label>
              <input id="endDate" type="date" value={filters.endDate} onChange={e => setFilters({ ...filters, endDate: e.target.value })} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded w-full" />
            </div>
          </div>
        )}
      </div>

      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Severity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Timestamp</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Computer</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Description</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {filteredLogs.map((log) => (
                <tr key={log.id} className="hover:bg-gray-700 transition-colors">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center space-x-2">
                      {getSeverityIcon(log.severity)}
                      <span className={`px-2 py-1 rounded-full text-xs font-medium capitalize
                        ${log.severity === 'critical' ? 'bg-red-900 text-red-300' : ''}
                        ${log.severity === 'high' ? 'bg-orange-900 text-orange-300' : ''}
                        ${log.severity === 'medium' ? 'bg-yellow-900 text-yellow-300' : ''}
                        ${log.severity === 'low' ? 'bg-blue-900 text-blue-300' : ''}
                      `}>
                        {log.severity}
                      </span>
                      {isThreatLog(log) && (
                        <span className="px-2 py-1 rounded-full text-xs font-medium bg-red-900 text-red-300">
                          THREAT
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">{formatTimestamp(log.timeCreated)}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">{log.computer}</td>
                  <td className="px-6 py-4 text-sm text-gray-300 max-w-xs truncate">{log.description}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <button
                      onClick={() => handleViewLog(log)}
                      className="text-blue-400 hover:text-blue-300 transition-colors flex items-center space-x-1"
                    >
                      <Eye className="h-4 w-4" />
                      <span>View Details</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {filteredLogs.length === 0 && (
        <div className="text-center py-12 bg-gray-800 border border-gray-700 rounded-lg mt-6">
          <Server className="h-16 w-16 text-gray-600 mx-auto mb-4" />
          <h3 className="text-xl font-medium text-gray-400 mb-2">No logs found</h3>
          <p className="text-gray-500">Try adjusting your search or filter criteria.</p>
        </div>
      )}

      {showLogModal && selectedLog && (
        <LogViewModal
          log={selectedLog}
          onClose={() => setShowLogModal(false)}
          onCreateTicket={handleCreateTicket}
          onMarkFalsePositive={handleMarkFalsePositive}
        />
      )}

      {showTicketModal && (
        <TicketModal
          ticket={selectedLog}
          isCreateMode={isCreateTicketMode}
          onSave={handleSaveTicket}
          onClose={() => {
            setShowTicketModal(false);
            setIsCreateTicketMode(false);
          }}
          relatedLogId={selectedLog?.id}
        />
      )}
    </div>
  );
};

export default LogSummaryPage;