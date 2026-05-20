// import React, { useState } from 'react';
// import { Ticket } from '../../types';
// import { useAuth } from '../../context/AuthContext';
// import { Link, useNavigate } from 'react-router-dom';
// import {
//   Save,
//   ArrowLeft
// } from 'lucide-react';

// interface CreateTicketPageProps {
//   tickets: Ticket[];
//   setTickets: React.Dispatch<React.SetStateAction<Ticket[]>>;
// }

// const CreateTicketPage: React.FC<CreateTicketPageProps> = ({ tickets, setTickets }) => {
//     const { user } = useAuth();
//     const navigate = useNavigate();
//     const [formData, setFormData] = useState({
//         title: '',
//         description: '',
//         severity: 'medium' as Ticket['severity'],
//         assignee: 'SOC L1',
//     });

//     const handleSave = () => {
//         if (!formData.title || !formData.description) {
//             alert('Please fill in a title and description.');
//             return;
//         }

//         const newTicket: Ticket = {
//             id: `T-${String(tickets.length + 1).padStart(3, '0')}`,
//             ...formData,
//             status: 'open',
//             reporter: user?.email || 'Unknown',
//             createdAt: new Date().toISOString(),
//             updatedAt: new Date().toISOString(),
//         };

//         setTickets([newTicket, ...tickets]);
//         navigate('/tickets');
//     };

//     return (
//         <div className="px-4 py-6 text-white">
//             <Link to="/tickets" className="inline-flex items-center text-sm text-blue-400 hover:text-blue-300 transition-colors mb-6">
//                 <ArrowLeft className="h-4 w-4 mr-1" />
//                 Back to Ticket Dashboard
//             </Link>
//             <div className="max-w-2xl mx-auto bg-gray-800 border border-gray-700 rounded-lg p-6">
//                 <h1 className="text-2xl font-bold mb-6">Create Manual Ticket</h1>
//                 <div className="space-y-4">
//                     <div>
//                         <label className="block text-sm font-medium text-gray-300 mb-2">Title</label>
//                         <input 
//                             type="text"
//                             value={formData.title}
//                             onChange={(e) => setFormData({...formData, title: e.target.value})}
//                             className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
//                         />
//                     </div>
//                      <div>
//                         <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
//                         <textarea 
//                             rows={5}
//                             value={formData.description}
//                             onChange={(e) => setFormData({...formData, description: e.target.value})}
//                             className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
//                         />
//                     </div>
//                     <div className="grid grid-cols-2 gap-4">
//                         <div>
//                             <label className="block text-sm font-medium text-gray-300 mb-2">Severity</label>
//                              <select value={formData.severity} onChange={(e) => setFormData({...formData, severity: e.target.value as Ticket['severity']})} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
//                                 <option value="low">Low</option>
//                                 <option value="medium">Medium</option>
//                                 <option value="high">High</option>
//                                 <option value="critical">Critical</option>
//                              </select>
//                         </div>
//                         <div>
//                             <label className="block text-sm font-medium text-gray-300 mb-2">Assign To</label>
//                              <select value={formData.assignee} onChange={(e) => setFormData({...formData, assignee: e.target.value})} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
//                                 <option value="SOC L1">SOC L1</option>
//                                 <option value="SOC L2">SOC L2</option>
//                                 <option value="SOC L3">SOC L3</option>
//                                 <option value="SOC L4">SOC L4</option>
//                              </select>
//                         </div>
//                     </div>
//                     <div className="flex justify-end pt-4">
//                         <button onClick={handleSave} className="px-4 py-2 bg-blue-600 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2">
//                             <Save className="h-4 w-4"/>
//                             <span>Create Ticket</span>
//                         </button>
//                     </div>
//                 </div>
//             </div>
//         </div>
//     );
// };

// export default CreateTicketPage;

// import React, { useState } from 'react';
// import { Ticket } from '../../types';
// import { useAuth } from '../../context/AuthContext';
// import { Link, useNavigate } from 'react-router-dom';
// import { Save, ArrowLeft } from 'lucide-react';

// interface CreateTicketPageProps {
//   tickets: Ticket[];
//   setTickets: React.Dispatch<React.SetStateAction<Ticket[]>>;
// }

// const CreateTicketPage: React.FC<CreateTicketPageProps> = ({ tickets, setTickets }) => {
//     const { user } = useAuth();
//     const navigate = useNavigate();
//     const [formData, setFormData] = useState({
//         title: '',
//         description: '',
//         severity: 'medium' as Ticket['severity'],
//         assignee: 'SOC L1',
//     });

//     const handleSave = () => {
//         if (!formData.title || !formData.description) {
//             alert('Please fill in a title and description.');
//             return;
//         }

//         const newTicket: Ticket = {
//             id: `T-${String(tickets.length + 1).padStart(3, '0')}`,
//             ...formData,
//             status: 'open',
//             reporter: user?.email || 'Unknown',
//             createdAt: new Date().toISOString(),
//             updatedAt: new Date().toISOString(),
//         };

//         setTickets([newTicket, ...tickets]);
//         navigate('/tickets');
//     };

//     return (
//         <div className="px-4 py-6 text-white">
//             <Link to="/tickets" className="inline-flex items-center text-sm text-blue-400 hover:text-blue-300 transition-colors mb-6">
//                 <ArrowLeft className="h-4 w-4 mr-1" />
//                 Back to Ticket Dashboard
//             </Link>
//             <div className="max-w-2xl mx-auto bg-gray-800 border border-gray-700 rounded-lg p-6">
//                 <h1 className="text-2xl font-bold mb-6">Create Manual Ticket</h1>
//                 <div className="space-y-4">
//                     <div>
//                         <label className="block text-sm font-medium text-gray-300 mb-2">Title</label>
//                         <input
//                             type="text"
//                             value={formData.title}
//                             onChange={(e) => setFormData({...formData, title: e.target.value})}
//                             className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
//                             placeholder="Enter a clear and concise title"
//                         />
//                     </div>
//                      <div>
//                         <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
//                         <textarea
//                             rows={5}
//                             value={formData.description}
//                             onChange={(e) => setFormData({...formData, description: e.target.value})}
//                             className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
//                             placeholder="Provide a detailed description of the issue or task"
//                         />
//                     </div>
//                     <div className="grid grid-cols-2 gap-4">
//                         <div>
//                             <label className="block text-sm font-medium text-gray-300 mb-2">Severity</label>
//                              <select value={formData.severity} onChange={(e) => setFormData({...formData, severity: e.target.value as Ticket['severity']})} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
//                                 <option value="low">Low</option>
//                                 <option value="medium">Medium</option>
//                                 <option value="high">High</option>
//                                 <option value="critical">Critical</option>
//                              </select>
//                         </div>
//                         <div>
//                             <label className="block text-sm font-medium text-gray-300 mb-2">Assign To</label>
//                              <select value={formData.assignee} onChange={(e) => setFormData({...formData, assignee: e.target.value})} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
//                                 <option value="SOC L1">SOC L1</option>
//                                 <option value="SOC L2">SOC L2</option>
//                                 <option value="SOC L3">SOC L3</option>
//                                 <option value="SOC L4">SOC L4</option>
//                              </select>
//                         </div>
//                     </div>
//                     <div className="flex justify-end pt-4">
//                         <button onClick={handleSave} className="px-4 py-2 bg-blue-600 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2">
//                             <Save className="h-4 w-4"/>
//                             <span>Create Ticket</span>
//                         </button>
//                     </div>
//                 </div>
//             </div>
//         </div>
//     );
// };

// export default CreateTicketPage;


import React, { useState } from 'react';
import { Ticket } from '../../types';
import { useAuth } from '../../context/AuthContext';
import { Link, useNavigate } from 'react-router-dom';
import { Save, ArrowLeft } from 'lucide-react';

interface CreateTicketPageProps {
  tickets: Ticket[];
  setTickets: React.Dispatch<React.SetStateAction<Ticket[]>>;
}

const CreateTicketPage: React.FC<CreateTicketPageProps> = ({ tickets, setTickets }) => {
    const { user } = useAuth();
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        title: '',
        description: '',
        severity: 'medium' as Ticket['severity'],
        assignee: 'SOC L1',
    });

    const handleSave = () => {
        if (!formData.title || !formData.description) {
            alert('Please fill in a title and description.');
            return;
        }

        const newTicket: Ticket = {
            id: `T-${String(tickets.length + 1).padStart(3, '0')}`,
            ...formData,
            status: 'open',
            reporter: user?.email || 'Unknown',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        };

        setTickets([newTicket, ...tickets]);
        navigate('/tickets');
    };

    return (
        <div className="px-4 py-6 text-white">
            <Link to="/tickets" className="inline-flex items-center text-sm text-blue-400 hover:text-blue-300 transition-colors mb-6">
                <ArrowLeft className="h-4 w-4 mr-1" />
                Back to Ticket Dashboard
            </Link>
            <div className="max-w-2xl mx-auto bg-gray-800 border border-gray-700 rounded-lg p-6">
                <h1 className="text-2xl font-bold mb-6">Create Manual Ticket</h1>
                <div className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">Title</label>
                        <input
                            type="text"
                            value={formData.title}
                            onChange={(e) => setFormData({...formData, title: e.target.value})}
                            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                            placeholder="Enter a clear and concise title"
                        />
                    </div>
                     <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
                        <textarea
                            rows={5}
                            value={formData.description}
                            onChange={(e) => setFormData({...formData, description: e.target.value})}
                            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                            placeholder="Provide a detailed description of the issue or task"
                        />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm font-medium text-gray-300 mb-2">Severity</label>
                             <select value={formData.severity} onChange={(e) => setFormData({...formData, severity: e.target.value as Ticket['severity']})} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
                                <option value="low">Low</option>
                                <option value="medium">Medium</option>
                                <option value="high">High</option>
                                <option value="critical">Critical</option>
                             </select>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-gray-300 mb-2">Assign To</label>
                             <select value={formData.assignee} onChange={(e) => setFormData({...formData, assignee: e.target.value})} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
                                <option value="SOC L1">SOC L1</option>
                                <option value="SOC L2">SOC L2</option>
                                <option value="SOC L3">SOC L3</option>
                                <option value="SOC L4">SOC L4</option>
                             </select>
                        </div>
                    </div>
                    <div className="flex justify-end pt-4">
                        <button onClick={handleSave} className="px-4 py-2 bg-blue-600 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2">
                            <Save className="h-4 w-4"/>
                            <span>Create Ticket</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default CreateTicketPage;