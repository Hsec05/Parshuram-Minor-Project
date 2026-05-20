import React, { useState } from 'react';
import { Device } from '../../types';
import { Monitor, MapPin, Clock, Check, X, Server, Cpu, HardDrive, ChevronDown, ChevronUp } from 'lucide-react';

const DeviceRequestsPage: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([
    {
      id: '1',
      ip: '192.168.1.100',
      location: 'New York, NY',
      os: 'Windows 11 Pro',
      version: '22H2',
      hardwareInfo: [
        'Intel Core i7-12700K',
        '32GB DDR4 RAM',
        '1TB NVMe SSD',
        'NVIDIA RTX 3070'
      ],
      requestTime: '2025-01-02T10:30:00Z',
      status: 'pending'
    },
    {
      id: '2',
      ip: '192.168.1.101',
      location: 'San Francisco, CA',
      os: 'Ubuntu 22.04 LTS',
      version: '5.15.0-91',
      hardwareInfo: [
        'AMD Ryzen 9 5900X',
        '64GB DDR4 RAM',
        '2TB NVMe SSD',
        'AMD Radeon RX 6800 XT'
      ],
      requestTime: '2025-01-02T11:15:00Z',
      status: 'pending'
    },
    {
      id: '3',
      ip: '192.168.1.102',
      location: 'Austin, TX',
      os: 'macOS Sonoma',
      version: '14.2.1',
      hardwareInfo: [
        'Apple M2 Pro',
        '16GB Unified Memory',
        '512GB SSD',
        'Integrated GPU'
      ],
      requestTime: '2025-01-02T09:45:00Z',
      status: 'approved'
    }
  ]);

  const [expandedDevice, setExpandedDevice] = useState<string | null>(null);

  const handleAcceptDevice = (deviceId: string) => {
    setDevices(devices.map(device => 
      device.id === deviceId 
        ? { ...device, status: 'approved' as const }
        : device
    ));
  };

  const handleRejectDevice = (deviceId: string) => {
    setDevices(devices.map(device => 
      device.id === deviceId 
        ? { ...device, status: 'rejected' as const }
        : device
    ));
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const getSeverityColor = (status: Device['status']) => {
    switch (status) {
      case 'pending': return 'border-yellow-500 bg-yellow-900/20';
      case 'approved': return 'border-green-500 bg-green-900/20';
      case 'rejected': return 'border-red-500 bg-red-900/20';
      default: return 'border-gray-500 bg-gray-900/20';
    }
  };

  const getStatusIcon = (status: Device['status']) => {
    switch (status) {
      case 'approved': return <Check className="h-5 w-5 text-green-500" />;
      case 'rejected': return <X className="h-5 w-5 text-red-500" />;
      default: return <Clock className="h-5 w-5 text-yellow-500" />;
    }
  };

  return (
    <div className="px-4 py-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Device Connection Requests</h1>
        <p className="text-gray-400">Review and manage new device connection requests to your network.</p>
      </div>

      <div className="space-y-4">
        {devices.map((device) => (
          <div
            key={device.id}
            className={`bg-gray-800 border-l-4 rounded-lg p-6 ${getSeverityColor(device.status)}`}
          >
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  {getStatusIcon(device.status)}
                  <span className="text-lg font-semibold text-white">{device.ip}</span>
                </div>
                <span className={`px-2 py-1 rounded-full text-xs font-medium capitalize
                  ${device.status === 'pending' ? 'bg-yellow-900 text-yellow-300' : ''}
                  ${device.status === 'approved' ? 'bg-green-900 text-green-300' : ''}
                  ${device.status === 'rejected' ? 'bg-red-900 text-red-300' : ''}
                `}>
                  {device.status}
                </span>
              </div>
              <div className="flex items-center space-x-2">
                {device.status === 'pending' && (
                  <>
                    <button
                      onClick={() => handleAcceptDevice(device.id)}
                      className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors flex items-center space-x-1"
                    >
                      <Check className="h-4 w-4" />
                      <span>Accept</span>
                    </button>
                    <button
                      onClick={() => handleRejectDevice(device.id)}
                      className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors flex items-center space-x-1"
                    >
                      <X className="h-4 w-4" />
                      <span>Reject</span>
                    </button>
                  </>
                )}
                <button
                  onClick={() => setExpandedDevice(expandedDevice === device.id ? null : device.id)}
                  className="p-2 text-gray-400 hover:text-white transition-colors"
                >
                  {expandedDevice === device.id ? (
                    <ChevronUp className="h-5 w-5" />
                  ) : (
                    <ChevronDown className="h-5 w-5" />
                  )}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div className="flex items-center space-x-2 text-gray-300">
                <MapPin className="h-4 w-4" />
                <span>{device.location}</span>
              </div>
              <div className="flex items-center space-x-2 text-gray-300">
                <Monitor className="h-4 w-4" />
                <span>{device.os} {device.version}</span>
              </div>
              <div className="flex items-center space-x-2 text-gray-300">
                <Clock className="h-4 w-4" />
                <span>{formatTimestamp(device.requestTime)}</span>
              </div>
            </div>

            {expandedDevice === device.id && (
              <div className="border-t border-gray-700 pt-4 mt-4">
                <h4 className="text-white font-medium mb-3 flex items-center space-x-2">
                  <Server className="h-4 w-4" />
                  <span>Hardware Information</span>
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {device.hardwareInfo.map((info, index) => (
                    <div key={index} className="flex items-center space-x-2 text-gray-300">
                      <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                      <span>{info}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {devices.length === 0 && (
        <div className="text-center py-12">
          <Monitor className="h-16 w-16 text-gray-600 mx-auto mb-4" />
          <h3 className="text-xl font-medium text-gray-400 mb-2">No device requests</h3>
          <p className="text-gray-500">New device connection requests will appear here.</p>
        </div>
      )}
    </div>
  );
};

export default DeviceRequestsPage;