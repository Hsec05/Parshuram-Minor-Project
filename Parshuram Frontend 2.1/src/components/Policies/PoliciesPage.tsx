import React, { useState } from 'react';
import { Policy } from '../../types';
import { useAuth } from '../../context/AuthContext';
import { Shield, Plus, Edit, Trash2, CheckCircle, XCircle } from 'lucide-react';
import PolicyModal from './PolicyModal';

const PoliciesPage: React.FC = () => {
  const { user } = useAuth();
  const [showPolicyModal, setShowPolicyModal] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState<Partial<Policy> | null>(null);

  const [policies, setPolicies] = useState<Policy[]>([
    {
      id: 'pol-1',
      name: 'Failed Login Brute Force',
      description: 'Detects multiple failed login attempts from a single IP.',
      conditions: {
        eventType: 'login_failed',
        threshold: 5,
        timeWindow: '10m',
        source: 'AuthLogs'
      },
      actions: {
        alert: true,
        raiseTicket: true,
        notifyEmail: 'soc@parshuram.com'
      },
      isActive: true,
      createdBy: 'admin@parshuram.com',
      createdAt: '2025-09-20T10:00:00Z',
      updatedAt: '2025-09-21T14:30:00Z',
    },
    {
      id: 'pol-2',
      name: 'Potential Malware C2 Traffic',
      description: 'Identifies outbound traffic to known malicious domains.',
      conditions: {
        eventType: 'network_outbound',
        threshold: 1,
        timeWindow: '1m',
        source: 'FirewallLogs'
      },
      actions: {
        alert: true,
        raiseTicket: true,
      },
      isActive: true,
      createdBy: 'soc-l4@parshuram.com',
      createdAt: '2025-08-15T09:00:00Z',
      updatedAt: '2025-09-18T11:00:00Z',
    }
  ]);
  
  if (!user || user.role !== 'L4') {
    return (
      <div className="text-center py-12 text-white">
        <h1 className="text-2xl font-bold">Access Denied</h1>
        <p>Only SOC L4 analysts can manage policies.</p>
      </div>
    );
  }

  const handleCreate = () => {
    setSelectedPolicy(null);
    setShowPolicyModal(true);
  };

  const handleEdit = (policy: Policy) => {
    setSelectedPolicy(policy);
    setShowPolicyModal(true);
  };

  const handleDelete = (policyId: string) => {
    if (window.confirm('Are you sure you want to delete this policy? This action cannot be undone.')) {
        setPolicies(policies.filter(p => p.id !== policyId));
        // In a real app, you would also make a DELETE API call here.
    }
  };

  const handleSave = (policyData: Partial<Policy>) => {
    if (policyData.id) {
      // Update existing policy
      setPolicies(policies.map(p => p.id === policyData.id ? { ...p, ...policyData, updatedAt: new Date().toISOString() } as Policy : p));
    } else {
      // Create new policy
      const newPolicy: Policy = {
        id: `pol-${Date.now()}`,
        ...policyData,
        createdBy: user.email,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      } as Policy;
      setPolicies([newPolicy, ...policies]);
    }
    setShowPolicyModal(false);
  };

  const formatTimestamp = (ts: string) => new Date(ts).toLocaleString();

  return (
    <div className="px-4 py-6 text-white">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold">Policy Management</h1>
          <p className="text-gray-400">Create, view, and manage SIEM detection policies.</p>
        </div>
        <button onClick={handleCreate} className="px-4 py-2 bg-blue-600 rounded-lg hover:bg-blue-700 flex items-center space-x-2">
          <Plus className="h-4 w-4"/>
          <span>Create Policy</span>
        </button>
      </div>

      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase">Policy Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase">Event Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase">Threshold / Window</th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase">Last Updated</th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {policies.map(policy => (
                <tr key={policy.id} className="hover:bg-gray-750">
                  <td className="px-6 py-4 whitespace-nowrap">
                    {policy.isActive ? <CheckCircle className="h-5 w-5 text-green-500"/> : <XCircle className="h-5 w-5 text-gray-500"/>}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap font-medium">{policy.name}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-gray-300 font-mono text-sm">{policy.conditions.eventType}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-gray-300">{policy.conditions.threshold} / {policy.conditions.timeWindow}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-gray-400 text-sm">{formatTimestamp(policy.updatedAt)}</td>
                  <td className="px-6 py-4 whitespace-nowrap flex space-x-4">
                    <button onClick={() => handleEdit(policy)} className="text-blue-400 hover:text-blue-300"><Edit className="h-5 w-5"/></button>
                    <button onClick={() => handleDelete(policy.id)} className="text-red-400 hover:text-red-300"><Trash2 className="h-5 w-5"/></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showPolicyModal && (
        <PolicyModal
          policy={selectedPolicy}
          onSave={handleSave}
          onClose={() => setShowPolicyModal(false)}
        />
      )}
    </div>
  );
};

export default PoliciesPage;