import React, { useState, useRef } from 'react';
import { Agent } from '../../types';
import { MapPin, Users, Globe, Filter, Eye } from 'lucide-react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L, { Map } from 'leaflet';
import { useOnClickOutside } from '../../hooks/useOnClickOutside';

// Fix for default icon issue with webpack
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.7.1/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.7.1/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.7.1/dist/images/marker-shadow.png',
});

const GeolocationPage: React.FC = () => {
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [showAgentModal, setShowAgentModal] = useState(false);
  const modalRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<Map | null>(null);

  useOnClickOutside(modalRef, () => setShowAgentModal(false));
  
  const [agents] = useState<Agent[]>([
    {
      id: 'WIN-001',
      name: 'DESKTOP-ABC123',
      ip: '192.168.1.100',
      location: 'New York Office',
      os: 'Windows 11 Pro',
      version: '22H2',
      status: 'active',
      lastSeen: '2025-01-02T14:30:00Z',
      uptime: '15 days, 4 hours',
      geolocation: { lat: 40.7128, lng: -74.0060, city: 'New York', country: 'USA' },
      alertsCount: 2,
      threatsCount: 5
    },
    {
      id: 'LIN-003',
      name: 'SERVER-XYZ789',
      ip: '192.168.1.102',
      location: 'San Francisco Office',
      os: 'Ubuntu 22.04 LTS',
      version: '5.15.0-91',
      status: 'active',
      lastSeen: '2025-01-02T14:25:00Z',
      uptime: '45 days, 12 hours',
      geolocation: { lat: 37.7749, lng: -122.4194, city: 'San Francisco', country: 'USA' },
      alertsCount: 0,
      threatsCount: 3
    },
    {
      id: 'NET-005',
      name: 'FIREWALL-001',
      ip: '192.168.1.50',
      location: 'Austin Office',
      os: 'pfSense 2.7.0',
      version: '2.7.0-RELEASE',
      status: 'disconnected',
      lastSeen: '2025-01-02T12:15:00Z',
      uptime: '0 days, 0 hours',
      geolocation: { lat: 30.2672, lng: -97.7431, city: 'Austin', country: 'USA' },
      alertsCount: 1,
      threatsCount: 0
    },
    {
      id: 'MAC-007',
      name: 'MACBOOK-DEV01',
      ip: '192.168.1.105',
      location: 'Remote - Seattle',
      os: 'macOS Sonoma',
      version: '14.2.1',
      status: 'maintenance',
      lastSeen: '2025-01-02T10:00:00Z',
      uptime: '0 days, 0 hours',
      geolocation: { lat: 47.6062, lng: -122.3321, city: 'Seattle', country: 'USA' },
      alertsCount: 0,
      threatsCount: 1
    }
  ]);

  const locationStats = {
    totalLocations: new Set(agents.map(a => a.geolocation.city)).size,
    activeAgents: agents.filter(a => a.status === 'active').length,
    totalAgents: agents.length,
    countries: new Set(agents.map(a => a.geolocation.country)).size
  };

  const getStatusColor = (status: Agent['status']) => {
    switch (status) {
      case 'active': return '#10B981';
      case 'disconnected': return '#EF4444';
      case 'maintenance': return '#F59E0B';
      default: return '#6B7280';
    }
  };

  const handleViewAgent = (agent: Agent) => {
    setSelectedAgent(agent);
    setShowAgentModal(true);
  };

  const handleViewOnMap = (agent: Agent) => {
    setShowAgentModal(false);
    const map = mapRef.current;
    if (map) {
      map.flyTo([agent.geolocation.lat, agent.geolocation.lng], 13);
    }
  };

  return (
    <div className="px-4 py-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Geolocation Map</h1>
        <p className="text-gray-400">Monitor agent locations and employee access points across the globe.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Locations</p>
              <p className="text-2xl font-bold text-white">{locationStats.totalLocations}</p>
            </div>
            <MapPin className="h-8 w-8 text-blue-500" />
          </div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Active Agents</p>
              <p className="text-2xl font-bold text-green-400">{locationStats.activeAgents}/{locationStats.totalAgents}</p>
            </div>
            <Users className="h-8 w-8 text-green-500" />
          </div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Countries</p>
              <p className="text-2xl font-bold text-purple-400">{locationStats.countries}</p>
            </div>
            <Globe className="h-8 w-8 text-purple-500" />
          </div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Remote Workers</p>
              <p className="text-2xl font-bold text-orange-400">{agents.filter(a => a.location.includes('Remote')).length}</p>
            </div>
            <Users className="h-8 w-8 text-orange-500" />
          </div>
        </div>
      </div>

      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-8">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white flex items-center space-x-2">
            <Globe className="h-5 w-5 text-blue-500" />
            <span>Global Agent Distribution</span>
          </h3>
        </div>
        
        {/* CORRECTED: Added relative and z-10 to contain the map */}
        <div className="bg-gray-700 border border-gray-600 rounded-lg h-96 overflow-hidden relative z-10">
          <MapContainer
            center={[39.8283, -98.5795]}
            zoom={4}
            style={{ height: '100%', width: '100%', backgroundColor: '#374151' }}
            ref={mapRef}
          >
            <TileLayer
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
            />
            {agents.map((agent) => (
              <Marker key={agent.id} position={[agent.geolocation.lat, agent.geolocation.lng]}>
                <Popup>
                  <b>{agent.name}</b><br />
                  {agent.location}<br />
                  Status: <span style={{ color: getStatusColor(agent.status) }}>{agent.status}</span>
                </Popup>
              </Marker>
            ))}
          </MapContainer>
        </div>
      </div>

      <div className="bg-gray-800 border border-gray-700 rounded-lg">
        <div className="p-6 border-b border-gray-700">
          <h3 className="text-lg font-semibold text-white">Agent Locations</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Agent</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Location</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Coordinates</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {agents.map((agent) => (
                <tr key={agent.id} className="hover:bg-gray-700 transition-colors">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div>
                      <div className="text-sm font-medium text-white">{agent.name}</div>
                      <div className="text-sm text-gray-400">{agent.id}</div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center space-x-2">
                      <MapPin className="h-4 w-4 text-gray-400" />
                      <div>
                        <div className="text-sm text-white">{agent.geolocation.city}, {agent.geolocation.country}</div>
                        <div className="text-sm text-gray-400">{agent.location}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {agent.geolocation.lat.toFixed(4)}, {agent.geolocation.lng.toFixed(4)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center space-x-2">
                      <div
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: getStatusColor(agent.status) }}
                      ></div>
                      <span className="text-sm text-white capitalize">{agent.status}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <button
                      onClick={() => handleViewAgent(agent)}
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

      {showAgentModal && selectedAgent && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div ref={modalRef} className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between p-6 border-b border-gray-700">
              <h2 className="text-xl font-bold text-white flex items-center space-x-2">
                <MapPin className="h-6 w-6 text-blue-500" />
                <span>Location Details - {selectedAgent.name}</span>
              </h2>
              <button
                onClick={() => setShowAgentModal(false)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                X
              </button>
            </div>
            <div className="p-6 space-y-6">
              <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
                <h4 className="text-white font-medium mb-3">Geographic Information</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-gray-400">City:</p>
                    <p className="text-white">{selectedAgent.geolocation.city}</p>
                  </div>
                  <div>
                    <p className="text-gray-400">Country:</p>
                    <p className="text-white">{selectedAgent.geolocation.country}</p>
                  </div>
                  <div>
                    <p className="text-gray-400">Latitude:</p>
                    <p className="text-white">{selectedAgent.geolocation.lat.toFixed(6)}</p>
                  </div>
                  <div>
                    <p className="text-gray-400">Longitude:</p>
                    <p className="text-white">{selectedAgent.geolocation.lng.toFixed(6)}</p>
                  </div>
                  <div className="md:col-span-2">
                    <p className="text-gray-400">Office Location:</p>
                    <p className="text-white">{selectedAgent.location}</p>
                  </div>
                </div>
              </div>
              <div className="bg-gray-700 border border-gray-600 rounded-lg p-4">
                <h4 className="text-white font-medium mb-3">Agent Information</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-gray-400">Agent ID:</p>
                    <p className="text-white">{selectedAgent.id}</p>
                  </div>
                  <div>
                    <p className="text-gray-400">IP Address:</p>
                    <p className="text-white">{selectedAgent.ip}</p>
                  </div>
                  <div>
                    <p className="text-gray-400">Operating System:</p>
                    <p className="text-white">{selectedAgent.os}</p>
                  </div>
                  <div>
                    <p className="text-gray-400">Status:</p>
                    <div className="flex items-center space-x-2">
                      <div
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: getStatusColor(selectedAgent.status) }}
                      ></div>
                      <span className="text-white capitalize">{selectedAgent.status}</span>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex justify-end space-x-3 pt-4 border-t border-gray-700">
                <button
                  onClick={() => setShowAgentModal(false)}
                  className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors"
                >
                  Close
                </button>
                <button
                  onClick={() => handleViewOnMap(selectedAgent)}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
                  View on Map
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default GeolocationPage;