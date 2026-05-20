import React, { useState, useEffect } from 'react';
import { ThreatLog, Ticket, Log } from '../../types';
import { Search, Filter, Eye, AlertTriangle, Shield } from 'lucide-react';
import LogViewModal from '../Logs/LogViewModal';
import TicketModal from '../Tickets/TicketModal';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

interface ThreatSummaryPageProps {
  tickets: Ticket[];
  setTickets: React.Dispatch<React.SetStateAction<Ticket[]>>;
}

const API_BASE_URL = 'http://localhost:3001/api';

const ThreatSummaryPage: React.FC<ThreatSummaryPageProps> = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedThreat, setSelectedThreat] = useState<ThreatLog | null>(null);
  const [showLogModal, setShowLogModal] = useState(false);
  const [showTicketModal, setShowTicketModal] = useState(false);
  const [isCreateTicketMode, setIsCreateTicketMode] = useState(false);
  const [filters, setFilters] = useState({
    agent_id: '',
    ip: '',
    os: '',
    severity: '',
    ruleMatched: '',
    channel: '',
    startDate: '',
    endDate: ''
  });
  const [showFilters, setShowFilters] = useState(false);
  const [threats, setThreats] = useState<ThreatLog[]>([]);

  useEffect(() => {
    const fetchThreats = async () => {
      const sessionId = localStorage.getItem('sessionId');
      if (!sessionId) return;
      try {
        const response = await fetch(`${API_BASE_URL}/logs/listThreats`, {
          method: 'POST', // Corrected to POST
          headers: {
            'Authorization': `Bearer ${sessionId}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(filters),
        });
        if (response.ok) {
          const { threats: fetchedThreats } = await response.json();
          setThreats(fetchedThreats);
        } else {
          console.error('Failed to fetch threats');
        }
      } catch (error) {
        console.error('Error fetching threats:', error);
      }
    };
    fetchThreats();
  }, [filters]);

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <AlertTriangle className="h-5 w-5 text-red-500" />;
      case 'high': return <AlertTriangle className="h-5 w-5 text-orange-500" />;
      case 'medium': return <Shield className="h-5 w-5 text-yellow-500" />;
      case 'low': return <Shield className="h-5 w-5 text-blue-500" />;
      default: return <Shield className="h-5 w-5 text-gray-500" />;
    }
  };

  const filteredThreats = threats.filter(threat => {
    const threatDate = new Date(threat.timestamp);
    const startDate = filters.startDate ? new Date(filters.startDate) : null;
    const endDate = filters.endDate ? new Date(filters.endDate) : null;

    if (startDate && threatDate < startDate) return false;
    if (endDate && threatDate > endDate) return false;
    
    return (
      (filters.agent_id ? threat.agent_id.toLowerCase().includes(filters.agent_id.toLowerCase()) : true) &&
      (filters.ip ? threat.ip.includes(filters.ip) : true) &&
      (filters.os ? threat.os.toLowerCase().includes(filters.os.toLowerCase()) : true) &&
      (filters.severity ? threat.severity === filters.severity : true) &&
      (filters.ruleMatched ? threat.ruleMatched.some(r => r.toLowerCase().includes(filters.ruleMatched.toLowerCase())) : true) &&
      (filters.channel ? threat.channel === filters.channel : true) &&
      (searchTerm ? threat.message.toLowerCase().includes(searchTerm.toLowerCase()) : true)
    );
  });

  const handleViewLog = (threat: ThreatLog) => {
    setSelectedThreat(threat);
    setShowLogModal(true);
  };
  
  const handleCreateTicket = (log: ThreatLog | Log) => {
    if ('ruleMatched' in log) {
        setSelectedThreat(log);
        setIsCreateTicketMode(true);
        setShowTicketModal(true);
        setShowLogModal(false);
    }
  };

  const handleMarkFalsePositive = async (threatId: string) => {
    const sessionId = localStorage.getItem('sessionId');
    if (!sessionId) return;
    try {
      const response = await fetch(`${API_BASE_URL}/logs/markFalsePositive`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${sessionId}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ threatId }),
      });
      if (response.ok) {
        setThreats(threats.filter(t => t.id !== threatId));
        setShowLogModal(false);
      } else {
        console.error('Failed to mark as false positive');
      }
    } catch (error) {
      console.error('Error marking as false positive:', error);
    }
  };

  const handleSaveTicket = async (ticketData: Partial<Ticket>) => {
    const sessionId = localStorage.getItem('sessionId');
    if (!sessionId || !selectedThreat) return;

    try {
      const payload = {
        ...ticketData,
        log_refs: selectedThreat.id ? [selectedThreat.log_ref] : ["68d102bd2ade7d572ccac130"],
        severity: selectedThreat.severity,
        attachments: [],
        files: ticketData.files?.map(f => f.fileName) || [],
      };
      
      const response = await fetch(`${API_BASE_URL}/tickets/raise`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${sessionId}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });
        console.log(payload);


      if (response.ok) {
        const { ticketID } = await response.json();
        navigate(`/tickets/${ticketID}`);
      } else {
        console.error('Failed to create ticket: ', response);
      }
    } catch (error) {
      console.error('Error creating ticket:', error);
    }
  };
  
  return (
    <div className="px-4 py-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Threat Summary</h1>
        <p className="text-gray-400">Monitor and analyze security threats detected across your infrastructure.</p>
      </div>

      <div className="mb-6 space-y-4">
        <div className="flex space-x-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search threat messages..."
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
              <input type="text" placeholder="Agent ID" value={filters.agent_id} onChange={e => setFilters({...filters, agent_id: e.target.value})} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded" />
              <input type="text" placeholder="IP Address" value={filters.ip} onChange={e => setFilters({...filters, ip: e.target.value})} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded" />
              <input type="text" placeholder="OS" value={filters.os} onChange={e => setFilters({...filters, os: e.target.value})} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded" />
              <select value={filters.severity} onChange={e => setFilters({...filters, severity: e.target.value})} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded">
                  <option value="">Any Severity</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
              </select>
              <input type="text" placeholder="Rule Matched" value={filters.ruleMatched} onChange={e => setFilters({...filters, ruleMatched: e.target.value})} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded" />
              <select value={filters.channel} onChange={e => setFilters({...filters, channel: e.target.value})} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded">
                  <option value="">Any Channel</option>
                  <option value="system">System</option>
                  <option value="security">Security</option>
                  <option value="application">Application</option>
              </select>
              <div className="flex items-center space-x-2">
                  <label htmlFor="startDate" className="text-sm text-gray-400">From:</label>
                  <input id="startDate" type="date" value={filters.startDate} onChange={e => setFilters({...filters, startDate: e.target.value})} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded w-full"/>
              </div>
              <div className="flex items-center space-x-2">
                   <label htmlFor="endDate" className="text-sm text-gray-400">To:</label>
                  <input id="endDate" type="date" value={filters.endDate} onChange={e => setFilters({...filters, endDate: e.target.value})} className="px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded w-full"/>
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
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Agent ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">IP Address</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">OS</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Message</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Rule ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {filteredThreats.map((threat) => (
                <tr key={threat.id} className="hover:bg-gray-700 transition-colors">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center space-x-2">
                      {getSeverityIcon(threat.severity)}
                      <span className={`px-2 py-1 rounded-full text-xs font-medium capitalize
                        ${threat.severity === 'critical' ? 'bg-red-900 text-red-300' : ''}
                        ${threat.severity === 'high' ? 'bg-orange-900 text-orange-300' : ''}
                        ${threat.severity === 'medium' ? 'bg-yellow-900 text-yellow-300' : ''}
                        ${threat.severity === 'low' ? 'bg-blue-900 text-blue-300' : ''}
                      `}>
                        {threat.severity}
                      </span>
                    </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">{threat.agent_id}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">{threat.ip}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">{threat.os}</td>
                <td className="px-6 py-4 text-sm text-gray-300 max-w-xs truncate">{threat.message}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">{Array.isArray(threat.ruleMatched) ? threat.ruleMatched.join(', ') : threat.ruleMatched}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                  <button
                    onClick={() => handleViewLog(threat)}
                    className="text-blue-400 hover:text-blue-300 transition-colors flex items-center space-x-1"
                  >
                    <Eye className="h-4 w-4" />
                    <span>View Log</span>
                  </button>
                </td>
              </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {filteredThreats.length === 0 && (
        <div className="text-center py-12 bg-gray-800 border border-gray-700 rounded-lg mt-6">
          <Shield className="h-16 w-16 text-gray-600 mx-auto mb-4" />
          <h3 className="text-xl font-medium text-gray-400 mb-2">No threats found</h3>
          <p className="text-gray-500">Try adjusting your search or filter criteria.</p>
        </div>
      )}

      {showLogModal && selectedThreat && (
        <LogViewModal
          log={selectedThreat}
          onClose={() => setShowLogModal(false)}
          onCreateTicket={handleCreateTicket}
          onMarkFalsePositive={handleMarkFalsePositive}
        />
      )}

      {showTicketModal && (
        <TicketModal
          ticket={{...selectedThreat, files:[]}}
          isCreateMode={isCreateTicketMode}
          onSave={handleSaveTicket}
          onClose={() => {
            setShowTicketModal(false);
            setIsCreateTicketMode(false);
          }}
          relatedLogId={selectedThreat?.id}
        />
      )}
    </div>
  );
};
export default ThreatSummaryPage;