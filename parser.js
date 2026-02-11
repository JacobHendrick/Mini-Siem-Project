/* ═══════════════════════════════════════════════════════════════════════════
   SIEM LOG PARSER ENGINE
   Parses uploaded log files into normalized security events.
   Supports: Syslog, Apache/Nginx, Auth logs, CSV, JSON, Windows Events,
   Firewall logs, and generic timestamped text logs.
   ═══════════════════════════════════════════════════════════════════════════ */

const LogParser = {

    // ── Main entry: parse raw text into events array ──
    parseFile(text, filename) {
        const lines = text.split("\n").filter(l => l.trim());
        if (!lines.length) return [];

        // Try JSON array first
        try {
            const json = JSON.parse(text);
            if (Array.isArray(json)) return json.map((item, i) => this.normalizeJSON(item, i));
            if (json.events && Array.isArray(json.events)) return json.events.map((item, i) => this.normalizeJSON(item, i));
            if (json.logs && Array.isArray(json.logs)) return json.logs.map((item, i) => this.normalizeJSON(item, i));
            return [this.normalizeJSON(json, 0)];
        } catch(e) { /* not JSON */ }

        // CSV detection
        const firstLine = lines[0];
        if (this.isCSV(firstLine, lines)) {
            return this.parseCSV(lines);
        }

        // Line-by-line parsing
        const events = [];
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            const event = this.parseLine(line, i, filename);
            if (event) events.push(event);
        }
        return events;
    },

    // ── CSV Parser ──
    isCSV(firstLine, lines) {
        const commas = (firstLine.match(/,/g) || []).length;
        if (commas < 2) return false;
        // Check consistency
        const secondLine = lines[1] || "";
        const commas2 = (secondLine.match(/,/g) || []).length;
        return Math.abs(commas - commas2) <= 1;
    },

    parseCSV(lines) {
        const headers = this.splitCSVLine(lines[0]).map(h => h.toLowerCase().trim());
        const events = [];
        for (let i = 1; i < lines.length; i++) {
            const vals = this.splitCSVLine(lines[i]);
            if (vals.length < 2) continue;
            const obj = {};
            headers.forEach((h, idx) => { obj[h] = vals[idx] || ""; });
            events.push(this.normalizeCSVRow(obj, i));
        }
        return events;
    },

    splitCSVLine(line) {
        const result = [];
        let current = "";
        let inQuotes = false;
        for (let i = 0; i < line.length; i++) {
            const ch = line[i];
            if (ch === '"') { inQuotes = !inQuotes; }
            else if (ch === ',' && !inQuotes) { result.push(current.trim()); current = ""; }
            else { current += ch; }
        }
        result.push(current.trim());
        return result;
    },

    normalizeCSVRow(obj, idx) {
        const ts = obj.timestamp || obj.time || obj.date || obj.datetime || obj["@timestamp"] || obj.event_time || "";
        const severity = this.detectSeverity(obj.severity || obj.level || obj.priority || obj.risk || JSON.stringify(obj));
        const srcIP = obj.source_ip || obj.src_ip || obj.srcip || obj.src || obj.source_address || obj.client_ip || "";
        const dstIP = obj.dest_ip || obj.dst_ip || obj.dstip || obj.dst || obj.dest_address || obj.destination_ip || obj.server_ip || "";

        return {
            id: `EVT-${String(idx).padStart(5, "0")}`,
            timestamp: this.parseTimestamp(ts),
            event_type: obj.event_type || obj.type || obj.action || obj.event || obj.category || "Log Entry",
            severity: severity,
            source: obj.source || obj.log_source || obj.device || obj.hostname || obj.host || "CSV Import",
            source_ip: this.cleanIP(srcIP),
            dest_ip: this.cleanIP(dstIP),
            status: obj.status || obj.result || "open",
            risk_score: this.severityToScore(severity),
            message: obj.message || obj.msg || obj.description || obj.details || "",
            raw: JSON.stringify(obj),
        };
    },

    // ── JSON normalizer ──
    normalizeJSON(obj, idx) {
        const ts = obj.timestamp || obj.time || obj.date || obj.datetime || obj["@timestamp"] || obj.event_time || "";
        const msg = obj.message || obj.msg || obj.description || obj.details || obj.log || "";
        const severity = this.detectSeverity(obj.severity || obj.level || obj.priority || msg);
        const srcIP = obj.source_ip || obj.src_ip || obj.srcip || obj.src || obj.source_address || obj.client_ip || "";
        const dstIP = obj.dest_ip || obj.dst_ip || obj.dstip || obj.dst || obj.dest_address || obj.destination_ip || "";

        return {
            id: obj.id || `EVT-${String(idx).padStart(5, "0")}`,
            timestamp: this.parseTimestamp(ts),
            event_type: obj.event_type || obj.type || obj.action || obj.event || obj.category || this.classifyMessage(msg),
            severity: severity,
            source: obj.source || obj.log_source || obj.device || obj.hostname || obj.host || obj.program || "JSON Import",
            source_ip: this.cleanIP(srcIP),
            dest_ip: this.cleanIP(dstIP),
            status: obj.status || obj.result || "open",
            risk_score: obj.risk_score || this.severityToScore(severity),
            message: msg,
            raw: JSON.stringify(obj),
        };
    },

    // ── Line parsers for various log formats ──
    parseLine(line, idx, filename) {
        // Try syslog: "Jan  1 00:00:00 hostname program[pid]: message"
        let m = line.match(/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$/);
        if (m) return this.buildEvent(idx, m[1], m[2], m[3], m[5]);

        // Apache/Nginx combined: "ip - - [date] "request" status size"
        m = line.match(/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)/);
        if (m) return this.buildWebEvent(idx, m[1], m[2], m[3], m[4], m[5]);

        // ISO timestamp: "2024-01-15T10:30:00Z some message"
        m = line.match(/^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)\s+(.*)$/);
        if (m) return this.buildGenericEvent(idx, m[1], m[2], filename);

        // Windows-style: "Date,Time,Source,EventID,Level,Message" (tab separated)
        m = line.match(/^(\d{1,2}\/\d{1,2}\/\d{4})\s+(\d{1,2}:\d{2}:\d{2}\s*[AP]?M?)\s+(.*)$/);
        if (m) return this.buildGenericEvent(idx, `${m[1]} ${m[2]}`, m[3], filename);

        // Firewall style: "action src=x dst=y proto=z"
        if (line.match(/(?:src|dst|proto|action)=/i)) {
            return this.buildFirewallEvent(idx, line);
        }

        // Generic: just treat the whole line as a message
        return this.buildGenericEvent(idx, "", line, filename);
    },

    buildEvent(idx, ts, hostname, program, message) {
        const severity = this.detectSeverity(message);
        const ips = this.extractIPs(message);
        return {
            id: `EVT-${String(idx).padStart(5, "0")}`,
            timestamp: this.parseTimestamp(ts),
            event_type: this.classifyMessage(message),
            severity: severity,
            source: `${hostname}/${program}`,
            source_ip: ips[0] || "",
            dest_ip: ips[1] || "",
            status: "open",
            risk_score: this.severityToScore(severity),
            message: message,
            raw: `${ts} ${hostname} ${program}: ${message}`,
        };
    },

    buildWebEvent(idx, ip, ts, request, status, size) {
        const code = parseInt(status);
        let severity = "info";
        let eventType = "HTTP Request";
        if (code >= 500) { severity = "high"; eventType = "Server Error"; }
        else if (code === 403) { severity = "medium"; eventType = "Forbidden Access"; }
        else if (code === 401) { severity = "medium"; eventType = "Unauthorized Access"; }
        else if (code === 404) { severity = "low"; eventType = "Not Found"; }
        else if (code >= 400) { severity = "low"; eventType = "Client Error"; }

        // Detect attack patterns
        const reqLower = request.toLowerCase();
        if (reqLower.includes("union") || reqLower.includes("select") || reqLower.includes("drop")) {
            severity = "critical"; eventType = "SQL Injection Attempt";
        } else if (reqLower.includes("<script") || reqLower.includes("onerror") || reqLower.includes("javascript:")) {
            severity = "critical"; eventType = "XSS Attempt";
        } else if (reqLower.includes("../") || reqLower.includes("etc/passwd") || reqLower.includes("..\\")) {
            severity = "high"; eventType = "Directory Traversal";
        } else if (reqLower.includes("wp-admin") || reqLower.includes("phpmyadmin") || reqLower.includes(".env")) {
            severity = "medium"; eventType = "Reconnaissance Scan";
        }

        return {
            id: `EVT-${String(idx).padStart(5, "0")}`,
            timestamp: this.parseTimestamp(ts),
            event_type: eventType,
            severity: severity,
            source: "Web Server",
            source_ip: ip,
            dest_ip: "",
            status: "open",
            risk_score: this.severityToScore(severity),
            message: `${request} -> ${status} (${size}B)`,
            raw: `${ip} [${ts}] "${request}" ${status} ${size}`,
        };
    },

    buildFirewallEvent(idx, line) {
        const srcMatch = line.match(/src=(\S+)/i);
        const dstMatch = line.match(/dst=(\S+)/i);
        const actionMatch = line.match(/(?:action=|^)(ALLOW|DENY|DROP|BLOCK|ACCEPT|REJECT)/i);
        const protoMatch = line.match(/proto=(\S+)/i);

        const action = actionMatch ? actionMatch[1].toUpperCase() : "UNKNOWN";
        let severity = "low";
        let eventType = "Firewall Event";

        if (action === "DENY" || action === "DROP" || action === "BLOCK" || action === "REJECT") {
            severity = "medium"; eventType = "Blocked Connection";
        }

        const tsMatch = line.match(/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/);

        return {
            id: `EVT-${String(idx).padStart(5, "0")}`,
            timestamp: tsMatch ? this.parseTimestamp(tsMatch[1]) : new Date().toISOString(),
            event_type: eventType,
            severity: severity,
            source: "Firewall",
            source_ip: srcMatch ? srcMatch[1] : "",
            dest_ip: dstMatch ? dstMatch[1] : "",
            status: "open",
            risk_score: this.severityToScore(severity),
            message: `${action} ${protoMatch ? protoMatch[1] : ""} ${srcMatch ? srcMatch[1] : ""} -> ${dstMatch ? dstMatch[1] : ""}`.trim(),
            raw: line,
        };
    },

    buildGenericEvent(idx, ts, message, filename) {
        const severity = this.detectSeverity(message);
        const ips = this.extractIPs(message);
        return {
            id: `EVT-${String(idx).padStart(5, "0")}`,
            timestamp: ts ? this.parseTimestamp(ts) : new Date().toISOString(),
            event_type: this.classifyMessage(message),
            severity: severity,
            source: filename || "Log File",
            source_ip: ips[0] || "",
            dest_ip: ips[1] || "",
            status: "open",
            risk_score: this.severityToScore(severity),
            message: message.substring(0, 500),
            raw: message,
        };
    },

    // ── Utilities ──
    detectSeverity(text) {
        if (!text) return "info";
        const t = text.toLowerCase();
        if (t.match(/\b(critical|crit|emergency|emerg|fatal|panic|exploit|breach|exfiltrat|ransomware|rootkit)\b/)) return "critical";
        if (t.match(/\b(error|err|high|alert|fail|denied|attack|malware|intrusion|unauthorized|forbidden|escalat)\b/)) return "high";
        if (t.match(/\b(warn|warning|medium|suspicious|anomal|unusual|blocked|reject)\b/)) return "medium";
        if (t.match(/\b(notice|low|info|debug|success|accept|allow|normal)\b/)) return "low";
        return "info";
    },

    classifyMessage(msg) {
        if (!msg) return "Log Entry";
        const t = msg.toLowerCase();
        if (t.match(/\b(login|logon|auth|sign.?in|sshd|session opened)\b/) && t.match(/\b(fail|invalid|error|denied|wrong)\b/)) return "Failed Login";
        if (t.match(/\b(login|logon|auth|sign.?in|session opened|accepted)\b/)) return "Authentication";
        if (t.match(/\b(logout|logoff|sign.?out|session closed)\b/)) return "Logout";
        if (t.match(/\b(brute|multiple.*fail|repeated.*fail)\b/)) return "Brute Force Attempt";
        if (t.match(/\b(scan|nmap|probe|recon)\b/)) return "Port Scan";
        if (t.match(/\b(malware|virus|trojan|worm|infected)\b/)) return "Malware Detected";
        if (t.match(/\b(sql.*inject|union.*select|xp_cmdshell)\b/)) return "SQL Injection";
        if (t.match(/\b(xss|cross.?site|<script|javascript:)\b/)) return "XSS Attack";
        if (t.match(/\b(phish|spoof|impersonat)\b/)) return "Phishing";
        if (t.match(/\b(ddos|flood|dos|syn.?flood)\b/)) return "DDoS Attack";
        if (t.match(/\b(exfiltrat|data.?leak|unauthorized.*transfer)\b/)) return "Data Exfiltration";
        if (t.match(/\b(escalat|privilege|sudo|root)\b/)) return "Privilege Escalation";
        if (t.match(/\b(c2|beacon|command.?and.?control|callback)\b/)) return "C2 Communication";
        if (t.match(/\b(firewall|iptables|ufw|blocked|dropped|denied)\b/)) return "Firewall Event";
        if (t.match(/\b(dns|resolve|lookup|nslookup)\b/)) return "DNS Event";
        if (t.match(/\b(error|err|exception|fault)\b/)) return "System Error";
        if (t.match(/\b(start|stop|restart|reboot|shutdown)\b/)) return "Service Event";
        return "Log Entry";
    },

    extractIPs(text) {
        const ips = text.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g) || [];
        return [...new Set(ips)];
    },

    cleanIP(val) {
        if (!val) return "";
        const m = val.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
        return m ? m[1] : val.trim();
    },

    parseTimestamp(ts) {
        if (!ts) return new Date().toISOString();
        // Try direct parse
        const d = new Date(ts);
        if (!isNaN(d.getTime())) return d.toISOString();
        // Syslog-style "Jan  1 00:00:00" — assume current year
        const syslog = ts.match(/^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})$/);
        if (syslog) {
            const year = new Date().getFullYear();
            const d2 = new Date(`${syslog[1]} ${syslog[2]} ${year} ${syslog[3]}`);
            if (!isNaN(d2.getTime())) return d2.toISOString();
        }
        // Apache-style "01/Jan/2024:10:30:00 +0000"
        const apache = ts.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})/);
        if (apache) {
            const d3 = new Date(`${apache[2]} ${apache[1]} ${apache[3]} ${apache[4]}`);
            if (!isNaN(d3.getTime())) return d3.toISOString();
        }
        return new Date().toISOString();
    },

    severityToScore(severity) {
        const map = { critical: 90, high: 70, medium: 45, low: 20, info: 5 };
        return map[severity] || 10;
    },
};

// ── Shared Data Store (persists across pages via sessionStorage) ──
const DataStore = {
    KEY: "sentinelops_events",
    FILES_KEY: "sentinelops_files",

    save(events) {
        try {
            sessionStorage.setItem(this.KEY, JSON.stringify(events));
        } catch(e) {
            console.warn("Storage full, truncating to 5000 events");
            sessionStorage.setItem(this.KEY, JSON.stringify(events.slice(0, 5000)));
        }
    },

    load() {
        try {
            const data = sessionStorage.getItem(this.KEY);
            return data ? JSON.parse(data) : [];
        } catch(e) { return []; }
    },

    saveFiles(files) {
        sessionStorage.setItem(this.FILES_KEY, JSON.stringify(files));
    },

    loadFiles() {
        try {
            const data = sessionStorage.getItem(this.FILES_KEY);
            return data ? JSON.parse(data) : [];
        } catch(e) { return []; }
    },

    addEvents(newEvents) {
        const existing = this.load();
        // De-duplicate by raw content
        const existingRaws = new Set(existing.map(e => e.raw));
        const unique = newEvents.filter(e => !existingRaws.has(e.raw));
        const combined = [...existing, ...unique].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        // Re-index
        combined.forEach((e, i) => e.id = `EVT-${String(i + 1).padStart(5, "0")}`);
        this.save(combined);
        return combined;
    },

    clear() {
        sessionStorage.removeItem(this.KEY);
        sessionStorage.removeItem(this.FILES_KEY);
    },

    getSummary() {
        const events = this.load();
        if (!events.length) return null;
        const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        const sourceCounts = {};
        const typeCounts = {};
        const ipCounts = {};
        const hourCounts = {};

        events.forEach(e => {
            severityCounts[e.severity] = (severityCounts[e.severity] || 0) + 1;
            sourceCounts[e.source] = (sourceCounts[e.source] || 0) + 1;
            typeCounts[e.event_type] = (typeCounts[e.event_type] || 0) + 1;
            if (e.source_ip) ipCounts[e.source_ip] = (ipCounts[e.source_ip] || 0) + 1;
            const hour = new Date(e.timestamp).getHours();
            hourCounts[hour] = (hourCounts[hour] || 0) + 1;
        });

        return {
            total: events.length,
            severityCounts,
            sourceCounts,
            typeCounts,
            ipCounts,
            hourCounts,
            topSources: this._topN(sourceCounts, 10),
            topTypes: this._topN(typeCounts, 10),
            topIPs: this._topN(ipCounts, 10),
            avgRisk: Math.round(events.reduce((s, e) => s + (e.risk_score || 0), 0) / events.length),
        };
    },

    _topN(obj, n) {
        return Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, n).map(([name, count]) => ({ name, count }));
    },
};
