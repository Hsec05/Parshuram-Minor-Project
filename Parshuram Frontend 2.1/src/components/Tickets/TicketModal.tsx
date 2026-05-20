import React, { useState, useEffect, useRef } from 'react';
import { Ticket, Attachment, ThreatLog, Log } from '../../types';
import { X, Save, Paperclip } from 'lucide-react';
import { useOnClickOutside } from '../../hooks/useOnClickOutside';

interface TicketModalProps {
  ticket: Partial<Ticket & ThreatLog & Log> | null;
  isCreateMode: boolean;
  onSave: (ticket: Partial<Ticket>) => void;
  onClose: () => void;
  relatedLogId?: string;
}

const TicketModal: React.FC<TicketModalProps> = ({ ticket, isCreateMode, onSave, onClose, relatedLogId }) => {
  const modalRef = useRef<HTMLDivElement>(null);
  useOnClickOutside(modalRef, onClose);

  const [source, setSource] = useState("");
  const [des, setDes] = useState("");

  const [formData, setFormData] = useState({
    title: '',
    description: '',
    severity: (ticket as any)?.severity || 'medium',
    assignee: (ticket as any)?.assignee || 'SOC L1',
    log_refs: relatedLogId ? [relatedLogId] : [],
  });
  const [uploadedFiles, setUploadedFiles] = useState<File[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (!isCreateMode || !ticket) return;

    const fetchExtraDetails = async () => {
      try {
        const sessionId = localStorage.getItem("sessionId");
        if (!sessionId) return;

        const logRef = ticket.log_ref || ticket.log_refs?.[0];
        if (!logRef) return;

        const res = await fetch(
          `http://localhost:3001/api/logs/viewLog/${logRef}`,
          {
            method: "GET",
            headers: { "Authorization": `Bearer ${sessionId}` }
          }
        );

        if (res.ok) {
          const data = await res.json();

          // ✅ Update state
          setSource(data.log.source);
          setDes(data.log.description);
          const data2 = data.log;
          console.log(data2);
          console.log(data2.source);
          
          
          console.log("Fetched:", data2.source, data2.description);
          console.log("FULL DATA:", data);// ✅ Update state (async)
          setSource(data2.source);
          setDes(data2.description);




          // ✅ Build description NOW (after data arrived!)
          const isThreatLog = (t: typeof ticket): t is ThreatLog =>
            "message" in t;

          const title = isThreatLog(ticket)
            ? `Threat Detected: ${ticket.message}`
            : `Log Event ${ticket.id}`;

          const description = `Investigation for the following event:\n\nID: ${ticket.id}\nSource: ${data2.source}\nDescription: ${data2.description}`;

          setFormData(prev => ({
            ...prev,
            title,
            description,
            severity: (ticket as any).severity,
            log_refs: ticket.id ? [ticket.id] : [],
          }));

          console.log("Fetched:", data.source, data.description);
        }
      } catch (err) {
        console.error("Error loading extra details:", err);
      }
    };

    fetchExtraDetails();
  }, [isCreateMode, ticket]);

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files) {
      const newFiles = Array.from(event.target.files);
      setUploadedFiles(prev => [...prev, ...newFiles]);
    }
  };

  const handleSaveTicket = async (e: React.FormEvent) => {
    e.preventDefault();

    const newAttachmentObjects: Attachment[] = uploadedFiles.map(file => ({
      id: `att-${Date.now()}-${file.name}`,
      fileName: file.name,
      fileType: file.type,
      fileSize: `${(file.size / 1024).toFixed(2)} KB`,
    }));

    onSave({
      title: formData.title,
      description: formData.description,
      severity: formData.severity,
      assignee: formData.assignee,
      log_refs: formData.log_refs,
      files: newAttachmentObjects,
    });
  };

  const handleInputChange = (field: keyof Omit<typeof formData, 'log_refs'>, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full max-h-[85vh] overflow-y-auto" ref={modalRef}>
        <div className="flex items-center justify-between p-6 border-b border-gray-700">
          <h2 className="text-xl font-bold text-white">Create New Ticket</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white"><X /></button>
        </div>

        <form onSubmit={handleSaveTicket} className="p-6 space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Title <span className="text-red-400">*</span></label>
            <input type="text" required className="w-full px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded-lg" value={formData.title} onChange={(e) => handleInputChange('title', e.target.value)} />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Description <span className="text-red-400">*</span></label>
            <textarea required rows={4} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded-lg" value={formData.description} onChange={(e) => handleInputChange('description', e.target.value)} />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Severity <span className="text-red-400">*</span></label>
              <select value={formData.severity} onChange={(e) => handleInputChange('severity', e.target.value)} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
                <option value="urgent">Urgent</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Assign to (Level) <span className="text-red-400">*</span></label>
              <select value={formData.assignee} onChange={(e) => handleInputChange('assignee', e.target.value)} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
                <option value="SOC L1">SOC L1</option>
                <option value="SOC L2">SOC L2</option>
                <option value="SOC L3">SOC L3</option>
                <option value="SOC L4">SOC L4</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Log Reference(s)</label>
            <input type="text" disabled className="w-full px-3 py-2 bg-gray-700 border border-gray-600 text-gray-400 rounded-lg" value={formData.log_refs.join(', ')} />
            <p className="text-xs text-gray-500 mt-1">This field is pre-populated from the selected log and is not editable.</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Attachments</label>
            <div className="bg-gray-700 border border-gray-600 rounded-lg p-3">
              {uploadedFiles.length > 0 ? (
                <div className="space-y-2">
                  {uploadedFiles.map((file, index) => (
                    <div key={index} className="flex items-center justify-between text-sm">
                      <span className="text-gray-300">{file.name}</span>
                      <span className="text-gray-400">{`${(file.size / 1024).toFixed(2)} KB`}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-gray-400 text-sm text-center">No files attached.</p>
              )}
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
                className="mt-3 w-full px-3 py-2 bg-blue-600 rounded-lg text-sm hover:bg-blue-700 flex items-center justify-center space-x-2"
              >
                <Paperclip className="h-4 w-4" />
                <span>Upload File</span>
              </button>
            </div>
          </div>

          <div className="flex justify-end space-x-3 pt-4 border-t border-gray-700">
            <button type="button" onClick={onClose} className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700">Cancel</button>
            <button type="submit" className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center space-x-2">
              <Save className="h-4 w-4" />
              <span>Create Ticket</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default TicketModal;