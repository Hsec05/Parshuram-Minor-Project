import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import Layout from './components/Layout/Layout';
import PrivateRoute from './components/PrivateRoute';
import LoginPage from './components/Auth/LoginPage';
import ForgotPasswordPage from './components/Auth/ForgotPasswordPage';
import RegisterPage from './components/Auth/RegisterPage';
import OTPPage from './components/Auth/OTPPage';
import NewPasswordPage from './components/Auth/NewPasswordPage';
import Dashboard from './components/Dashboard/Dashboard';
import DeviceRequestsPage from './components/DeviceRequests/DeviceRequestsPage';
import ThreatSummaryPage from './components/Threats/ThreatSummaryPage';
import LogSummaryPage from './components/Logs/LogSummaryPage';
import TicketingPage from './components/Tickets/TicketingPage';
import AdminPage from './components/Admin/AdminPage';
import AgentsPage from './components/Agents/AgentsPage';
import GeolocationPage from './components/Geolocation/GeolocationPage';
import AlertsPage from './components/Alerts/AlertsPage';
import PoliciesPage from './components/Policies/PoliciesPage';
import { Ticket } from './types';
import TicketDetailsPage from './components/Tickets/TicketDetailsPage';
import WaitingPage from './components/Auth/WaitingPage';
import CreateTicketPage from './components/Tickets/CreateTicketPage';

function App() {
  const [tickets, setTickets] = useState<Ticket[]>([
    {
      id: 'T-001',
      title: 'Investigation: Malware detected on DESKTOP-ABC123',
      description: 'Critical malware detection requires immediate investigation and remediation. Initial analysis shows suspicious process `svchost.exe` communicating with a known malicious IP `123.45.67.89`.',
      severity: 'critical',
      status: 'under_review',
      assignee: 'SOC L2',
      reporter: 'SIEM System',
      createdAt: '2025-09-20T10:30:00Z',
      updatedAt: '2025-09-21T11:00:00Z',
      log_refs: ['1'],
      relatedAlertId: 'ALT-002',
      contributors: ['soc-l1@parshuram.com', 'soc-l2@parshuram.com'],
      files: [
        { id: 'att-main-1', fileName: 'initial-payload.bin', fileSize: '2.1 MB', fileType: 'application/octet-stream' }
      ],
      updates: [
          {id: 'C-1', employee_id: 'soc-l1@parshuram.com', updated_at: '2025-09-20T11:05:00Z', message: 'Initial triage complete. IOCs identified and attached.', attachments: ['iocs.csv']},
          {id: 'C-2', employee_id: 'soc-l1@parshuram.com', updated_at: '2025-09-20T11:15:00Z', message: 'Escalated to L2 for deeper analysis.'},
      ]
    },
    {
      id: 'T-002',
      title: 'SSH Brute Force Attack Analysis',
      description: 'Multiple failed SSH attempts detected from external IP `98.76.54.32`. Need to analyze attack patterns and implement blocking measures.',
      severity: 'high',
      status: 'under_review',
      assignee: 'SOC L1',
      reporter: 'SIEM System',
      createdAt: '2025-09-21T09:15:00Z',
      updatedAt: '2025-09-21T09:45:00Z',
      log_refs: ['2'],
      contributors: ['soc-l1@parshuram.com'],
      updates: [
        {id: 'C-3', employee_id: 'soc-l1@parshuram.com', updated_at: '2025-09-21T09:45:00Z', message: 'Alert validated. IP has been temporarily blocked. Monitoring for further activity.'}
      ]
    },
  ]);

  return (
    <AuthProvider>
      <Router>
        <div className="min-h-screen bg-gray-900">
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/otp" element={<OTPPage />} />
            <Route path="/new-password" element={<NewPasswordPage />} />
            <Route path="/waiting-for-approval" element={<WaitingPage />} />

            <Route path="/dashboard" element={<PrivateRoute><Layout><Dashboard /></Layout></PrivateRoute>} />
            <Route path="/agents" element={<PrivateRoute><Layout><AgentsPage /></Layout></PrivateRoute>} />
            <Route path="/device-requests" element={<PrivateRoute><Layout><DeviceRequestsPage /></Layout></PrivateRoute>} />
            <Route path="/geolocation" element={<PrivateRoute><Layout><GeolocationPage /></Layout></PrivateRoute>} />
            <Route path="/logs" element={<PrivateRoute><Layout><LogSummaryPage /></Layout></PrivateRoute>} />
            <Route path="/policies" element={<PrivateRoute><Layout><PoliciesPage /></Layout></PrivateRoute>} />
            <Route path="/admin" element={<PrivateRoute><Layout><AdminPage /></Layout></PrivateRoute>} />

            <Route path="/threats" element={<PrivateRoute><Layout><ThreatSummaryPage tickets={tickets} setTickets={setTickets} /></Layout></PrivateRoute>} />
            <Route path="/alerts" element={<PrivateRoute><Layout><AlertsPage tickets={tickets} setTickets={setTickets} /></Layout></PrivateRoute>} />
            <Route path="/tickets" element={<PrivateRoute><Layout><TicketingPage tickets={tickets} setTickets={setTickets}/></Layout></PrivateRoute>} />
            <Route path="/tickets/:id" element={<PrivateRoute><Layout><TicketDetailsPage tickets={tickets} setTickets={setTickets} /></Layout></PrivateRoute>} />
            <Route path="/tickets/create" element={<PrivateRoute><Layout><CreateTicketPage tickets={tickets} setTickets={setTickets} /></Layout></PrivateRoute>} />
            
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;