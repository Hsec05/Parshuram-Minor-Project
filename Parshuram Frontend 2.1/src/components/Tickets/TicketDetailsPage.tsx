import React, { useState, useRef, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Ticket, Alert, Attachment, TicketComment } from '../../types';
import { useAuth } from '../../context/AuthContext';
import { ArrowLeft, User, Paperclip, ArrowUpCircle, CheckCircle, AlertTriangle, Clock, Users } from 'lucide-react';

const API_BASE_URL = 'http://localhost:3001/api';

interface TicketDetailsPageProps {
  tickets: Ticket[];
  setTickets: React.Dispatch<React.SetStateAction<Ticket[]>>;
}

const TicketDetailsPage: React.FC<TicketDetailsPageProps> = () => {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const [ticket, setTicket] = useState<Ticket | null>(null);
  const [relatedAlert, setRelatedAlert] = useState<Alert | null>(null);
  const [newComment, setNewComment] = useState('');
  const [newStatus, setNewStatus] = useState(ticket?.status || 'open');
  const [newSeverity, setNewSeverity] = useState(ticket?.severity || 'medium');
  const [uploadedFiles, setUploadedFiles] = useState<File[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const fetchTicketDetails = async () => {
      const sessionId = localStorage.getItem('sessionId');
      if (!sessionId) return;
      try {
        const response = await fetch(`${API_BASE_URL}/tickets/view/${id}`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${sessionId}`,
          },
        });
        if (response.ok) {
          const fetchedTicket = await response.json();
          // console.log(fetchedTicket);

          setTicket(fetchedTicket);
          setNewStatus(fetchedTicket.status);
          setNewSeverity(fetchedTicket.severity);

          if (fetchedTicket.relatedAlertId) {
            const alertResponse = await fetch(`${API_BASE_URL}/logs/viewThreat/${fetchedTicket.relatedAlertId}`, {
              method: 'GET',
              headers: {
                'Authorization': `Bearer ${sessionId}`,
              },
            });
            if (alertResponse.ok) {
              const { threat: fetchedThreat } = await alertResponse.json();

              let agentName = 'N/A';
              if (fetchedThreat.log_ref) {
                const logResponse = await fetch(`${API_BASE_URL}/logs/viewLog/${fetchedThreat.log_ref}`, {
                  method: 'GET',
                  headers: {
                    'Authorization': `Bearer ${sessionId}`,
                  },
                });
                if (logResponse.ok) {
                  const { log: fetchedLog } = await logResponse.json();
                  agentName = fetchedLog.computer;
                }
              }

              setRelatedAlert({
                id: fetchedThreat.log_ref,
                agentId: fetchedThreat.agent_id,
                agentName: agentName,
                type: fetchedThreat.channel,
                message: fetchedThreat.message,
                severity: fetchedThreat.severity,
                timestamp: fetchedThreat.timestamp,
                acknowledged: false,
              });
            }
          }
        } else {
          console.error('Failed to fetch ticket details');
        }
      } catch (error) {
        console.error('Error fetching ticket details:', error);
      }
    };
    fetchTicketDetails();
  }, [id]);

  if (!ticket) {
    return (
      <div className="text-center py-12 text-white">
        <h1 className="text-2xl font-bold">Ticket Not Found</h1>
        <Link to="/tickets" className="text-blue-400 hover:underline mt-4 inline-block">
          <ArrowLeft className="inline-block h-4 w-4 mr-1" />
          Back to Ticket Dashboard
        </Link>
      </div>
    );
  }

  const lastUpdate = ticket.updates && ticket.updates.length > 0
    ? ticket.updates[ticket.updates.length - 1].updated_at
    : ticket.createdAt;

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (files) {
      setUploadedFiles(prev => [...prev, ...Array.from(files)]);
    }
  };

  const handleRemoveFile = (index: number) => {
    setUploadedFiles(prev => prev.filter((_, i) => i !== index));
  };

  const handleUpdateTicket = async () => {
    const sessionId = localStorage.getItem('sessionId');
    if (!sessionId || !ticket || !user) return;
    try {
      const uploadedFileNames: string[] = [];
      if (uploadedFiles.length > 0) {
        const formData = new FormData();
        uploadedFiles.forEach(file => formData.append('file', file));

        const uploadResponse = await fetch(`${API_BASE_URL}/tickets/upload`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${sessionId}`,
          },
          body: formData,
        });

        if (uploadResponse.ok) {
          const { filename } = await uploadResponse.json();
          uploadedFileNames.push(filename);
        } else {
          console.error('Failed to upload file');
        }
      }

      const payload = {
        ticketID: ticket.id,
        message: newComment,
        status: newStatus,
        severity: newSeverity,
        attachments: uploadedFileNames,
      };

      const updateResponse = await fetch(`${API_BASE_URL}/tickets/update`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${sessionId}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (updateResponse.ok) {
        window.location.reload();

        const fetchResponse = await fetch(`${API_BASE_URL}/tickets/view/${id}`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${sessionId}`,
          },
        });
        if (fetchResponse.ok) {
          const { ticket: updatedTicket } = await fetchResponse.json();
          setTicket(updatedTicket);
        }
        setNewComment('');
        setUploadedFiles([]);
      } else {
        console.error('Failed to update ticket');
      }
    } catch (error) {
      console.error('Error updating ticket:', error);
    }
  };

  const handleEscalate = async () => {
    const sessionId = localStorage.getItem('sessionId');
    if (!sessionId || !ticket) return;

    const payload = {
      ticketID: ticket.id,
      message: 'Escalation performed.'
    };

    try {
      const response = await fetch(`${API_BASE_URL}/tickets/addLevel`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${sessionId}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });
      const data = await response.json();

      if (response.ok) {
        // Refresh updated ticket details
        const fetchResponse = await fetch(`${API_BASE_URL}/tickets/view/${ticket.id}`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${sessionId}`,
          },
        });

        if (fetchResponse.ok) {
          window.location.reload();
          return;
        }
      } else {
        console.error('Failed to escalate ticket');
        alert(data.message)
      }
    } catch (error) {
      console.error('Error escalating ticket:', error);
    }
  };



  const handleResolveTicket = async () => {
    const sessionId = localStorage.getItem('sessionId');
    if (!sessionId || !ticket || !user) return;
    try {
      const payload = {
        ticketID: ticket.id,
        message: 'Ticket has been resolved and closed.',
        status: 'closed',
        severity: ticket.severity,
        attachments: [],
      };

      const response = await fetch(`${API_BASE_URL}/tickets/update`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${sessionId}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        const fetchResponse = await fetch(`${API_BASE_URL}/tickets/view/${id}`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${sessionId}`,
          },
        });
        if (fetchResponse.ok) {
          const { ticket: updatedTicket } = await fetchResponse.json();
          setTicket(updatedTicket);
        }
      } else {
        console.error('Failed to resolve ticket');
      }
    } catch (error) {
      console.error('Error resolving ticket:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-900 text-red-300 border-red-500';
      case 'high': return 'bg-orange-900 text-orange-300 border-orange-500';
      case 'medium': return 'bg-yellow-900 text-yellow-300 border-yellow-500';
      case 'low': return 'bg-blue-900 text-blue-300 border-blue-500';
      case 'urgent': return 'bg-purple-900 text-purple-300 border-purple-500';
      default: return 'bg-gray-900 text-gray-300 border-gray-500';
    }
  };

  const AttachmentList: React.FC<{ files: Attachment[] }> = ({ files }) => (
    <div className="mt-2 flex flex-wrap gap-2">
      {files.map((att) => (
        <a
          href="#"
          key={att.id}
          className="bg-gray-600 px-2 py-1 rounded text-xs text-blue-300 hover:bg-gray-500 flex items-center space-x-1"
        >
          <Paperclip className="h-3 w-3" />
          <span>
            {att.fileName} ({att.fileSize})
          </span>
        </a>
      ))}
    </div>
  );

  const UpdateAttachmentsList: React.FC<{ attachments: string[] }> = ({ attachments }) => (
    <div className="mt-2 flex flex-wrap gap-2">
      {attachments.map((fileName, index) => (
        <a
          href="#"
          key={index}
          className="bg-gray-600 px-2 py-1 rounded text-xs text-blue-300 hover:bg-gray-500 flex items-center space-x-1"
        >
          <Paperclip className="h-3 w-3" />
          <span>{fileName}</span>
        </a>
      ))}
    </div>
  );

  const formatAssignedLevel = (assignee: string | undefined): string => {
    if (!assignee) return 'N/A';
    return assignee.toLowerCase().replace(' ', '-');
  };

  return (
    <div className="px-4 py-6 text-white">
      <Link
        to="/tickets"
        className="inline-flex items-center text-sm text-blue-400 hover:text-blue-300 transition-colors mb-4"
      >
        <ArrowLeft className="h-4 w-4 mr-1" />
        Back to Dashboard
      </Link>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="border-b border-gray-700 pb-4 mb-4">
            <div className="flex justify-between items-center">
              <h1 className="text-2xl font-bold">{ticket.title}</h1>
              <span
                className={`px-3 py-1 rounded-full text-sm font-semibold capitalize ${getSeverityColor(
                  ticket.severity,
                )}`}
              >
                {ticket.severity}
              </span>
            </div>
            <p className="text-sm text-gray-400">ID: {ticket.id}</p>
          </div>
          <p className="text-gray-300 mb-6 whitespace-pre-wrap">{ticket.description}</p>
          {ticket.files && ticket.files.length > 0 && (
            <div className="bg-gray-700 p-4 rounded-lg mt-6">
              <h3 className="font-semibold mb-2 text-lg text-blue-300">Ticket Files</h3>
              <AttachmentList files={ticket.files} />
            </div>
          )}

          {relatedAlert && (
            <div className="bg-gray-700 p-4 rounded-lg mt-6">
              <h3 className="font-semibold mb-2 text-lg text-blue-300">Linked SIEM Alert</h3>
              <div className="space-y-1 text-sm text-gray-300">
                <p>
                  <strong>Alert ID:</strong>{' '}
                  <Link to={`/alerts`} className="text-blue-400 hover:underline">
                    {relatedAlert.id}
                  </Link>
                </p>
                <p>
                  <strong>Message:</strong> {relatedAlert.message}
                </p>
                <p>
                  <strong>Source:</strong> {relatedAlert.agentName} ({relatedAlert.agentId})
                </p>
              </div>
            </div>
          )}

          <div className="mt-8 space-y-4">
            <h3 className="font-semibold text-lg border-b border-gray-700 pb-2">Investigation Timeline</h3>
            {ticket.updates?.map((update) => (
              <div key={update.id} className="flex space-x-3">
                <User className="h-6 w-6 text-gray-400 flex-shrink-0 mt-1" />
                <div className="flex-1 bg-gray-700 rounded-lg p-3">
                  <div className="flex justify-between items-center mb-1">
                    <p className="font-semibold text-blue-400">{update.employee_id}</p>
                    <p className="text-xs text-gray-400">{new Date(update.updated_at).toLocaleString()}</p>
                  </div>
                  <div className="flex items-center space-x-2 text-sm text-gray-400">
                    {update.status && (
                      <span className="capitalize">
                        Status: <span className="font-bold">{update.status.replace('_', ' ')}</span>
                      </span>
                    )}
                    {update.severity && (
                      <span className="capitalize">
                        Severity: <span className="font-bold">{update.severity}</span>
                      </span>
                    )}
                  </div>
                  <p className="text-gray-300 whitespace-pre-wrap">{update.message}</p>
                  {update.attachments && update.attachments.length > 0 && <UpdateAttachmentsList attachments={update.attachments} />}
                </div>
              </div>
            ))}
            <div className="flex space-x-3 mt-6">
              <User className="h-6 w-6 text-gray-400 flex-shrink-0 mt-1" />
              <div className="flex-1">
                <textarea
                  value={newComment}
                  onChange={(e) => setNewComment(e.target.value)}
                  className="w-full bg-gray-700 rounded-md p-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Add a comment or update ticket..."
                  rows={4}
                />
                <div className="mt-2 flex flex-wrap items-center gap-4">
                  <div className="flex items-center space-x-2">
                    <label className="text-sm">Status:</label>
                    <select
                      value={newStatus}
                      onChange={(e) => setNewStatus(e.target.value as Ticket['status'])}
                      className="px-3 py-1 bg-gray-700 border border-gray-600 rounded"
                    >
                      <option value="open">Open</option>
                      <option value="under_review">Under Review</option>
                      <option value="closed">Closed</option>
                    </select>
                  </div>
                  <div className="flex items-center space-x-2">
                    <label className="text-sm">Severity:</label>
                    <select
                      value={newSeverity}
                      onChange={(e) => setNewSeverity(e.target.value as Ticket['severity'])}
                      className="px-3 py-1 bg-gray-700 border border-gray-600 rounded"
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                      <option value="urgent">Urgent</option>
                    </select>
                  </div>
                  <input
                    type="file"
                    multiple
                    ref={fileInputRef}
                    onChange={handleFileChange}
                    className="hidden"
                  />
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="px-3 py-1 bg-gray-600 rounded-lg hover:bg-gray-500 text-sm flex items-center space-x-1"
                  >
                    <Paperclip className="h-4 w-4" />
                    <span>Attach File</span>
                  </button>
                  <div className="flex-1">
                    {uploadedFiles.map((file, index) => (
                      <span key={index} className="inline-flex items-center px-2 py-1 mr-2 text-xs font-medium text-white bg-gray-700 rounded-full">
                        {file.name}
                        <button type="button" onClick={() => handleRemoveFile(index)} className="ml-1 text-gray-400 hover:text-white">x</button>
                      </span>
                    ))}
                  </div>
                  <button
                    onClick={handleUpdateTicket}
                    className="px-4 py-2 bg-blue-600 rounded-lg hover:bg-blue-700 font-semibold"
                  >
                    Update
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <h3 className="font-semibold mb-4 text-lg">Ticket Information</h3>
            <div className="space-y-3">
              <p className="text-sm text-gray-400">
                <strong>Ticket ID:</strong> {ticket.id}
              </p>
              <p className="text-sm text-gray-400">
                <strong>Reporter:</strong> {ticket.reporter}
              </p>
              <p className="text-sm text-gray-400">
                <strong>Log Refs:</strong> {ticket.log_refs && ticket.log_refs.length > 0 ? ticket.log_refs.join(', ') : 'N/A'}
              </p>
              <p className="text-sm text-gray-400">
                <strong>Created At:</strong> {new Date(ticket.createdAt).toLocaleString()}
              </p>
            </div>
          </div>
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <h3 className="font-semibold mb-4 text-lg">Current Status</h3>
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="h-4 w-4 text-orange-400" />
                <p>
                  <strong>Severity:</strong>{' '}
                  <span
                    className={`font-bold text-${ticket.severity === 'critical'
                      ? 'red'
                      : ticket.severity === 'high'
                        ? 'orange'
                        : ticket.severity === 'urgent'
                          ? 'purple'
                          : 'yellow'
                      }-400`}
                  >
                    {ticket.severity.toUpperCase()}
                  </span>
                </p>
              </div>
              <div className="flex items-center space-x-2">
                <Clock className="h-4 w-4 text-gray-400" />
                <p>
                  <strong>State:</strong> <span className="font-bold">{ticket.status.toUpperCase().replace('_', ' ')}</span>
                </p>
              </div>
              <div className="flex items-center space-x-2">
                <User className="h-4 w-4 text-gray-400" />
                <p>
                  <strong>Assigned Group:</strong> <span className="font-bold">{ticket.assignee}</span>
                </p>
              </div>
              <p className="text-sm text-gray-400">
                <strong>Last Update:</strong> {new Date(lastUpdate).toLocaleString()}
              </p>
            </div>
          </div>
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <h3 className="font-semibold mb-4 text-lg">Contributors</h3>
            <div className="space-y-2">
              {ticket.contributors && ticket.contributors.length > 0 ? (
                ticket.contributors.map((contributor, index) => (
                  <div key={index} className="flex items-center space-x-2 text-gray-300 text-sm">
                    <Users className="h-4 w-4" />
                    <span>{contributor}</span>
                  </div>
                ))
              ) : (
                <p className="text-sm text-gray-400">No contributors yet.</p>
              )}
            </div>
          </div>
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <h3 className="font-semibold mb-4 text-lg">Actions</h3>
            <div className="space-y-3">
              {ticket.status !== 'closed' && (
                <>
                  {ticket.levels && !ticket.levels.includes('L4') && (
                    <button
                      onClick={handleEscalate}
                      className="w-full px-4 py-2 bg-yellow-600 rounded-lg hover:bg-yellow-700 transition-colors flex items-center justify-center space-x-2"
                    >
                      <ArrowUpCircle className="h-4 w-4" />
                      <span>Escalate Ticket</span>
                    </button>
                  )}
                  <button
                    onClick={handleResolveTicket}
                    className="w-full px-4 py-2 bg-green-600 rounded-lg hover:bg-green-700 transition-colors flex items-center justify-center space-x-2"
                  >
                    <CheckCircle className="h-4 w-4" />
                    <span>Resolve & Close</span>
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TicketDetailsPage;