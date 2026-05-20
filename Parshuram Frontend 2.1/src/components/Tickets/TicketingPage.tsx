import React, { useState, useEffect } from 'react';
import { Ticket } from '../../types';
import { useAuth } from '../../context/AuthContext';
import { Link, useNavigate } from 'react-router-dom';
import { Search, Eye, Filter, Plus } from 'lucide-react';

interface TicketingPageProps {
    tickets: Ticket[];
    setTickets: React.Dispatch<React.SetStateAction<Ticket[]>>;
}

const API_BASE_URL = 'http://localhost:3001/api';

const TicketingPage: React.FC<TicketingPageProps> = ({ tickets, setTickets }) => {
    const { user } = useAuth();
    const navigate = useNavigate();
    const [showFilters, setShowFilters] = useState(false);
    // const [filteredTickets, setFilteredTickets] = useState<Ticket[]>([]);
    // const filteredTickets = tickets.filter(ticket => {
    //     const ticketDate = new Date(ticket.createdAt);
    //     const startDate = filters.startDate ? new Date(filters.startDate) : null;
    //     const endDate = filters.endDate ? new Date(filters.endDate) : null;

    //     // Corrected filter logic: A ticket is visible if the user is an admin or their role matches the current assignee.
    //     const userRole = user?.role;
    //     const isAssignedToUser = userRole === 'admin' || ticket.assignee.toLowerCase().replace(' ', '-') === userRole;

    //     if (!isAssignedToUser) return false;

    //     if (startDate && ticketDate < startDate) return false;
    //     if (endDate && ticketDate > endDate) return false;

    //     return (
    //         (filters.title ? ticket.title.toLowerCase().includes(filters.title.toLowerCase()) : true) &&
    //         (filters.createdBy ? ticket.reporter.toLowerCase().includes(filters.createdBy.toLowerCase()) : true) &&
    //         (filters.log_refs ? ticket.log_refs?.some(ref => ref.includes(filters.log_refs)) : true) &&
    //         (filters.contributors ? ticket.contributors?.some(c => c.toLowerCase().includes(filters.contributors.toLowerCase())) : true) &&
    //         (filters.status.length > 0 ? filters.status.includes(ticket.status) : true) &&
    //         (filters.severity.length > 0 ? filters.severity.includes(ticket.severity) : true)
    //     );
    // });

    const [filters, setFilters] = useState({
        title: '',
        createdBy: '',
        log_refs: '',
        status: [] as string[],
        severity: [] as string[],
        contributors: '',
        startDate: '',
        endDate: ''
    });

    useEffect(() => {
        const fetchTickets = async () => {
            const sessionId = localStorage.getItem('sessionId');
            if (!sessionId) return;
            try {
                const response = await fetch(`${API_BASE_URL}/tickets/list`, {
                    method: 'POST', // Corrected to POST
                    headers: {
                        'Authorization': `Bearer ${sessionId}`,
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(filters),
                });
                console.log(filters);

                if (response.ok) {
                    const data = await response.json();
                    // const mapped = data.tickets.map((t: any) => ({
                    //     id: t.ticketID,                // ✅ backend ticketID → frontend id
                    //     title: t.title,
                    //     reporter: t.createdBy,         // ✅ backend createdBy → frontend reporter
                    //     severity: t.severity,
                    //     status: t.status,
                    //     created_at: t.created_at
                    // }));

                    // setFilteredTickets(mapped);
                    const container = document.querySelector(".lg\\:col-span-3.space-y-4");
                    if (!container) return;

                        container.innerHTML = ""; // clear old tickets

    // severity colors (same as your filter buttons)
    const severityColors: any = {
        low: "bg-blue-900 text-blue-300",
        medium: "bg-yellow-900 text-yellow-300",
        high: "bg-orange-900 text-orange-300",
        critical: "bg-red-900 text-red-300",
        urgent: "bg-purple-900 text-purple-300",
        none: "bg-gray-900 text-gray-300"
    };

    data.tickets.forEach((t: any) => {

        const sev = t.severity || "none";
        const sevColor = severityColors[sev] || severityColors["none"];

        const html = `
            <div class="bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-blue-500 transition-colors">
                <div class="flex justify-between items-start mb-2">
                    <div>
                        <a href="/tickets/${t.ticketID}" class="font-semibold text-lg text-blue-400 hover:underline"> ${t.title}</a>
                        <p class="text-sm text-gray-400">
                            <span class="font-semibold text-gray-300">Ticket ID:</span> #${t.ticketID || "N/A"}
                        </p>
                        <p class="text-sm text-gray-400">
                            <span class="font-semibold text-gray-300">Created By:</span> ${t.createdBy || "system"}
                        </p>
                        <p class="text-sm text-gray-400">
                            <span class="font-semibold text-gray-300">Created At:</span> ${new Date(t.created_at).toLocaleString()}
                        </p>
                    </div>

                    <div class="flex flex-col items-end space-y-1">
                        <span class="px-2 py-1 text-xs font-bold rounded-full capitalize ${sevColor}">
                            ${sev}
                        </span>
                        <span class="px-2 py-1 text-xs font-bold rounded-full capitalize bg-gray-700 text-gray-300">
                            ${t.status}
                        </span>
                    </div>
                </div>

                <div class="mt-3 border-t border-gray-700 pt-2">
                    <p class="text-sm text-gray-300">
                        <span class="font-semibold">Comments:</span> ${t.no_of_comments}
                    </p>
                </div>
            </div>
        `;

        container.insertAdjacentHTML("beforeend", html);
    });
                    console.log(data);

                } else {
                    console.error('Failed to fetch tickets');
                }
            } catch (error) {
                console.error('Error fetching tickets:', error);
            }
        };
        fetchTickets();
    }, [filters]);

    const handleMultiSelectChange = (field: 'status' | 'severity', value: string) => {
        const currentValues = filters[field] as string[];
        const newValues = currentValues.includes(value)
            ? currentValues.filter(v => v !== value)
            : [...currentValues, value];
        setFilters({ ...filters, [field]: newValues });
    };

    const getSeverityColor = (severity: Ticket['severity']) => {
        switch (severity) {
            case 'critical': return 'bg-red-900 text-red-300';
            case 'high': return 'bg-orange-900 text-orange-300';
            case 'medium': return 'bg-yellow-900 text-yellow-300';
            case 'low': return 'bg-blue-900 text-blue-300';
            case 'urgent': return 'bg-purple-900 text-purple-300';
            default: return 'bg-gray-900 text-gray-300';
        }
    };

    return (
        <div className="px-4 py-6 text-white">
            <div className="flex justify-between items-center mb-8">
                <div>
                    <h1 className="text-3xl font-bold mb-2">Ticket Dashboard</h1>
                    <p className="text-gray-400">Search, filter, and manage all security tickets.</p>
                </div>
                <div className="flex space-x-2">
                    <button onClick={() => setShowFilters(!showFilters)} className="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 flex items-center space-x-2">
                        <Filter className="h-4 w-4" />
                        <span>Filters</span>
                    </button>
                </div>
            </div>

            {showFilters && (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 mb-6 space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <input type="text" placeholder="Search by Title..." value={filters.title} onChange={e => setFilters({ ...filters, title: e.target.value })} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded" />
                        <input type="text" placeholder="Created By..." value={filters.createdBy} onChange={e => setFilters({ ...filters, createdBy: e.target.value })} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded" />
                        <input type="text" placeholder="Log Reference..." value={filters.log_refs} onChange={e => setFilters({ ...filters, log_refs: e.target.value })} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded" />
                        <input type="text" placeholder="Contributors..." value={filters.contributors} onChange={e => setFilters({ ...filters, contributors: e.target.value })} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded" />
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                            <label className="text-sm text-gray-400 block mb-2">Status</label>
                            <div className="flex flex-wrap gap-2">
                                {['open', 'under_review', 'closed'].map(status => (
                                    <button
                                        key={status}
                                        type="button"
                                        onClick={() => handleMultiSelectChange('status', status)}
                                        className={`px-3 py-1 rounded-full text-xs capitalize ${filters.status.includes(status)
                                            ? 'bg-blue-600 text-white'
                                            : 'bg-gray-700 text-gray-300'
                                            }`}
                                    >
                                        {status.replace('_', ' ')}
                                    </button>
                                ))}
                            </div>
                        </div>
                        <div>
                            <label className="text-sm text-gray-400 block mb-2">Severity</label>
                            <div className="flex flex-wrap gap-2">
                                {['low', 'medium', 'high', 'critical', 'urgent'].map(severity => (
                                    <button
                                        key={severity}
                                        type="button"
                                        onClick={() => handleMultiSelectChange('severity', severity)}
                                        className={`px-3 py-1 rounded-full text-xs capitalize ${filters.severity.includes(severity)
                                            ? getSeverityColor(severity as Ticket['severity'])
                                            : 'bg-gray-700 text-gray-300'
                                            }`}
                                    >
                                        {severity}
                                    </button>
                                ))}
                            </div>
                        </div>
                        <div>
                            <label className="text-sm text-gray-400 block mb-2">Date Range</label>
                            <div className="flex items-center space-x-2">
                                <input id="startDate" type="date" value={filters.startDate} onChange={e => setFilters({ ...filters, startDate: e.target.value })} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded" />
                                <input id="endDate" type="date" value={filters.endDate} onChange={e => setFilters({ ...filters, endDate: e.target.value })} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded" />
                            </div>
                        </div>
                    </div>
                </div>
            )}

            <div className="lg:col-span-3 space-y-4">
                {/* {filteredTickets.map(ticket => (
                    <div key={ticket.id} className="bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-blue-500 transition-colors">
                        <div className="flex justify-between items-start">
                            <div>
                                <Link to={`/tickets/${ticket.id}`} className="font-semibold text-lg text-blue-400 hover:underline">{ticket.title}</Link>
                                <p className="text-sm text-gray-400">#{ticket.id} opened by {ticket.reporter}</p>
                            </div>
                            <div className="flex flex-col items-end space-y-1">
                                <span className={`px-2 py-1 text-xs font-bold rounded-full capitalize ${getSeverityColor(ticket.severity)}`}>
                                    {ticket.severity}
                                </span>
                                <span className={`px-2 py-1 text-xs font-bold rounded-full capitalize bg-gray-700 text-gray-300`}>
                                    {ticket.status.replace('_', ' ')}
                                </span>
                            </div>
                        </div>
                    </div>
                ))} */}
            </div>
        </div>
    );
};

export default TicketingPage;