import React, { useRef } from 'react';
import { Agent } from '../../types';
import { Server, XCircle, CheckCircle, AlertTriangle, Shield, Monitor, Clock } from 'lucide-react';
import { useOnClickOutside } from '../../hooks/useOnClickOutside';

interface AgentDetailsModalProps {
  agent: Agent | null;
  onClose: () => void;
}

const AgentDetailsModal: React.FC<AgentDetailsModalProps> = ({ agent, onClose }) => {
  const modalRef = useRef<HTMLDivElement>(null);
  useOnClickOutside(modalRef, onClose);

  if (!agent) return null;

  const getStatusIcon = (status: Agent['status']) => {
    switch (status) {
      case 'active': return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'disconnected': return <XCircle className="h-5 w-5 text-red-500" />;
      case 'maintenance': return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      default: return <XCircle className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status: Agent['status']) => {
    switch (status) {
      case 'active': return 'bg-green-900 text-green-300 border-green-500';
      case 'disconnected': return 'bg-red-900 text-red-300 border-red-500';
      case 'maintenance': return 'bg-yellow-900 text-yellow-300 border-yellow-500';
      default: return 'bg-gray-900 text-gray-300 border-gray-500';
    }
  };
  
  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div ref={modalRef} className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full max-h-[85vh] overflow-y-auto">
        <div className="flex items-center justify-between p-6 border-b border-gray-700">
          <h2 className="text-xl font-bold text-white flex items-center space-x-2">
            <Server className="h-6 w-6 text-blue-500" />
            <span>Agent Details - {agent.name}</span>
          </h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <XCircle className="h-6 w-6" />
          </button>
        </div>
        <div className="p-6 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
              <h4 className="text-white font-medium mb-3">Status Information</h4>
              <div className="space-y-2">
                <div className="flex items-center space-x-2">
                  {getStatusIcon(agent.status)}
                  <span className={`px-2 py-1 rounded-full text-xs font-medium border capitalize ${getStatusColor(agent.status)}`}>
                    {agent.status}
                  </span>
                </div>
                <p className="text-gray-300 text-sm">Last seen: {formatTimestamp(agent.lastSeen)}</p>
              </div>
            </div>
            <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
              <h4 className="text-white font-medium mb-3">System Information</h4>
              <div className="space-y-2 text-sm">
                <p className="text-gray-300">IP: {agent.ip}</p>
                <p className="text-gray-300">OS: {agent.os}</p>
                <p className="text-gray-300">Location: {agent.location}</p>
              </div>
            </div>
          </div>
          <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
            <h4 className="text-white font-medium mb-3">Security Metrics</h4>
            <div className="grid grid-cols-2 gap-4">
              <div className="text-center">
                <div className="flex items-center justify-center space-x-2 mb-2">
                  <AlertTriangle className="h-5 w-5 text-red-500" />
                  <span className="text-2xl font-bold text-red-400">{agent.alertsCount}</span>
                </div>
                <p className="text-gray-300 text-sm">Active Alerts</p>
              </div>
              <div className="text-center">
                <div className="flex items-center justify-center space-x-2 mb-2">
                  <Shield className="h-5 w-5 text-orange-500" />
                  <span className="text-2xl font-bold text-orange-400">{agent.threatsCount}</span>
                </div>
                <p className="text-gray-300 text-sm">Threats Detected</p>
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
          </div>
        </div>
      </div>
    </div>
  );
};

export default AgentDetailsModal;