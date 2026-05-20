import React, { useState, useEffect, useRef } from 'react';
import { Policy } from '../../types';
import { X, Save, Shield, AlertTriangle } from 'lucide-react';
import { useOnClickOutside } from '../../hooks/useOnClickOutside';

interface PolicyModalProps {
  policy: Partial<Policy> | null;
  onSave: (policy: Partial<Policy>) => void;
  onClose: () => void;
}

const PolicyModal: React.FC<PolicyModalProps> = ({ policy, onSave, onClose }) => {
  const isCreateMode = !policy?.id;
  const modalRef = useRef<HTMLDivElement>(null);
  useOnClickOutside(modalRef, onClose);

  const [formData, setFormData] = useState({
    name: '',
    description: '',
    conditions: {
      eventType: '',
      threshold: 1,
      timeWindow: '5m',
      source: '',
    },
    actions: {
      alert: true,
      raiseTicket: false,
      notifyEmail: '',
    },
    ...policy,
  });

  const [errors, setErrors] = useState<Record<string, string>>({});

  const validate = (): boolean => {
    const newErrors: Record<string, string> = {};
    if (!formData.name.trim()) newErrors.name = 'Policy name is required.';
    if (!formData.conditions.eventType.trim()) newErrors.eventType = 'Event type is required.';
    if (formData.conditions.threshold < 1) newErrors.threshold = 'Threshold must be at least 1.';
    if (!/^\d+[smh]$/.test(formData.conditions.timeWindow)) newErrors.timeWindow = 'Invalid format (e.g., 10s, 5m, 1h).';
    if (formData.actions.notifyEmail && !/\S+@\S+\.\S+/.test(formData.actions.notifyEmail)) newErrors.notifyEmail = 'Please enter a valid email address.';
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (validate()) {
      onSave(formData);
    }
  };

  const handleChange = (section: 'conditions' | 'actions', field: string, value: any) => {
    setFormData(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [field]: value,
      },
    }));
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center p-4 z-50">
      <div ref={modalRef} className="bg-gray-800 border border-gray-700 rounded-lg max-w-3xl w-full max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-6 border-b border-gray-700 sticky top-0 bg-gray-800">
          <h2 className="text-xl font-bold text-white flex items-center space-x-2">
            <Shield className="h-6 w-6 text-blue-500" />
            <span>{isCreateMode ? 'Create New Policy' : `Edit Policy: ${policy?.name}`}</span>
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white"><X className="h-6 w-6" /></button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-8">
          {/* General Information */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-200 border-b border-gray-600 pb-2">General</h3>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Policy Name</label>
              <input type="text" value={formData.name} onChange={e => setFormData({...formData, name: e.target.value})} className="w-full bg-gray-700 border border-gray-600 rounded p-2" />
              {errors.name && <p className="text-red-400 text-xs mt-1">{errors.name}</p>}
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
              <textarea value={formData.description} onChange={e => setFormData({...formData, description: e.target.value})} className="w-full bg-gray-700 border border-gray-600 rounded p-2" rows={3}></textarea>
            </div>
          </div>

          {/* Conditions */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-200 border-b border-gray-600 pb-2">Conditions</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Event Type</label>
                <input type="text" value={formData.conditions.eventType} onChange={e => handleChange('conditions', 'eventType', e.target.value)} className="w-full bg-gray-700 border border-gray-600 rounded p-2" />
                 {errors.eventType && <p className="text-red-400 text-xs mt-1">{errors.eventType}</p>}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Source (Optional)</label>
                <input type="text" value={formData.conditions.source} onChange={e => handleChange('conditions', 'source', e.target.value)} className="w-full bg-gray-700 border border-gray-600 rounded p-2" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Threshold</label>
                <input type="number" value={formData.conditions.threshold} onChange={e => handleChange('conditions', 'threshold', parseInt(e.target.value, 10))} className="w-full bg-gray-700 border border-gray-600 rounded p-2" />
                 {errors.threshold && <p className="text-red-400 text-xs mt-1">{errors.threshold}</p>}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Time Window</label>
                <input type="text" value={formData.conditions.timeWindow} onChange={e => handleChange('conditions', 'timeWindow', e.target.value)} className="w-full bg-gray-700 border border-gray-600 rounded p-2" />
                 {errors.timeWindow && <p className="text-red-400 text-xs mt-1">{errors.timeWindow}</p>}
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-200 border-b border-gray-600 pb-2">Actions</h3>
            <div className="flex items-center space-x-6">
                <label className="flex items-center space-x-2 cursor-pointer"><input type="checkbox" checked={formData.actions.alert} onChange={e => handleChange('actions', 'alert', e.target.checked)} className="h-4 w-4 bg-gray-700 border-gray-600 rounded"/><span>Generate Alert</span></label>
                <label className="flex items-center space-x-2 cursor-pointer"><input type="checkbox" checked={formData.actions.raiseTicket} onChange={e => handleChange('actions', 'raiseTicket', e.target.checked)} className="h-4 w-4 bg-gray-700 border-gray-600 rounded"/><span>Raise Ticket</span></label>
            </div>
            <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Notify Email (Optional)</label>
                <input type="email" value={formData.actions.notifyEmail} onChange={e => handleChange('actions', 'notifyEmail', e.target.value)} className="w-full md:w-1/2 bg-gray-700 border border-gray-600 rounded p-2" />
                {errors.notifyEmail && <p className="text-red-400 text-xs mt-1">{errors.notifyEmail}</p>}
            </div>
          </div>

          <div className="flex justify-end space-x-3 pt-6 border-t border-gray-700">
            <button type="button" onClick={onClose} className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700">Cancel</button>
            <button type="submit" className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center space-x-2">
              <Save className="h-4 w-4" />
              <span>{isCreateMode ? 'Create Policy' : 'Save Changes'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default PolicyModal;