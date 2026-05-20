const WindowsLog = require('../models/windows_logs');
const WindowsThreat = require('../models/windows_threats');

const viewLog = async (req, res) => {
    try {
        const { logID } = req.params;

        if (!logID) return res.status(400).json({ message: 'Log ID is required' });
        const log = await WindowsLog.findById(logID, { _id: 0, __v: 0 }).lean();
        if (!log) return res.status(404).json({ message: 'Log not found' });

        console.log(log);
        
        res.status(200).json({ log });
    } catch (error) {
        console.error('Error in showing log:', err);
        res.status(500).json({ message: 'Server error' });
    }
}

const viewThreat = async (req, res) => {
    try {
        const { threatID } = req.params;

        if (!threatID) return res.status(400).json({ message: 'Threat ID is required' });
        const threat = await WindowsThreat.findById(threatID, { _id: 0, __v: 0 }).lean();
        if (!threat) return res.status(404).json({ message: 'Log not found' });

        res.status(200).json({ threat });
    } catch (error) {
        console.error('Error in showing threat:', err);
        res.status(500).json({ message: 'Server error' });
    }
}

const listThreats = async (req, res) => {
    try {
        const { agent_id, ip, os, severity, ruleMatched, startDate, endDate, channel } = req.body;
        const filters = {};
        if (agent_id) filters.agent_id = agent_id;
        if (ip) filters.ip = ip;
        if (os) filters.os = os;
        if (severity) filters.severity = severity;
        if (channel) filters.channel = channel;
        if (ruleMatched) filters.ruleMatched = { $in: Array.isArray(ruleMatched) ? ruleMatched : [ruleMatched] };
        if (startDate || endDate) {
            filters.created_at = {};
            if (startDate) filters.timestamp.$gte = new Date(startDate);
            if (endDate) filters.timestamp.$lte = new Date(endDate);
        }

        const threats = await WindowsThreat.find(filters, {
            // exclude _id
            __v: 0,         // exclude __v
        }).lean();

        var threat = threats.map(t => ({
            id: t.log_ref,
            timeCreated: t.timestamp,
            ...t,
            _id: undefined,
            timestamp: undefined
        }));

        res.status(200).json({
            count: threats.length,
            threats: threat
        });
    } catch (error) {
        console.error('Error in showing list of threats:', error);
        res.status(500).json({ message: 'Server error' });
    }
}

const listLogs = async (req, res) => {
    try {
        const { agent_id, ip, os, severity, source, computer, channel, startDate, endDate } = req.body;
        const filters = {};
        if (agent_id) filters.agent_id = agent_id;
        if (ip) filters.ip = ip;
        if (os) filters.os = os;
        if (severity) filters.severity = severity;
        if (source) filters.source = source;
        if (computer) filters.computer = computer;
        if (channel) filters.channel = channel;
        if (startDate || endDate) {
            filters.created_at = {};
            if (startDate) filters.timestamp.$gte = new Date(startDate);
            if (endDate) filters.timestamp.$lte = new Date(endDate);
        }

        const logs = await WindowsLog.find(filters, {
            _id: 0,         // exclude _id
            __v: 0,         // exclude __v
        }).lean();

        var log = logs.map(t => ({
            id: t._id,
            timeCreated: t.timestamp,
            ...t,
            _id: undefined,
            timestamp: undefined
        }));

        res.status(200).json({
            count: logs.length,
            logs: log
        });
    } catch (error) {
        console.error('Error in showing list of logs:', error);
        res.status(500).json({ message: 'Server error' });
    }
}

const markFalsePositive = async (req, res) => {
    try {
        const { threatId } = req.body;
        if (!threatId) {
            return res.status(400).json({ message: 'Threat ID is required' });
        }

        const threat = await WindowsThreat.findById(threatId);
        if (!threat) {
            return res.status(404).json({ message: 'Threat not found' });
        }

        const logId = threat.log_ref;

        await threat.deleteOne();
        await WindowsLog.findByIdAndUpdate(logId, { $unset: { threat: "" } });

        res.status(200).json({ message: 'Threat marked as false positive successfully' });
    } catch (error) {
        console.error('Error in marking false positive:', error);
        res.status(500).json({ message: 'Server error' });
    }
}

module.exports = { viewLog, viewThreat, listLogs, listThreats, markFalsePositive }