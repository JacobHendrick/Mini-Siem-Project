/* Shared UI components - generates sidebar and common elements without emojis */

function renderSidebar(activePage) {
    const pages = [
        { section: "Main", items: [
            { id: "dashboard", label: "Dashboard", href: "index.html", icon: "D" },
            { id: "alerts", label: "Alerts", href: "alerts.html", icon: "A" },
        ]},
        { section: "Intelligence", items: [
            { id: "threatmap", label: "Threat Map", href: "threatmap.html", icon: "T" },
            { id: "analytics", label: "Analytics", href: "analytics.html", icon: "G" },
        ]},
        { section: "System", items: [
            { id: "settings", label: "Settings", href: "settings.html", icon: "S" },
            { id: "auditlog", label: "Audit Log", href: "auditlog.html", icon: "L" },
        ]},
    ];

    const eventCount = DataStore.load().length;
    const critCount = DataStore.load().filter(e => e.severity === "critical" || e.severity === "high").length;

    let nav = "";
    pages.forEach(section => {
        nav += `<div class="nav-section-title">${section.section}</div>`;
        section.items.forEach(item => {
            const isActive = item.id === activePage;
            const badge = item.id === "alerts" && critCount > 0 ? `<span class="badge">${critCount}</span>` : "";
            nav += `<a class="nav-item ${isActive ? 'active' : ''}" href="${item.href}">
                <span class="icon">${item.icon}</span> ${item.label}${badge}
            </a>`;
        });
    });

    return `
    <aside class="sidebar">
        <div class="sidebar-brand">
            <div class="brand-icon">SO</div>
            <div>
                <h1>SentinelOps</h1>
                <span>SIEM Platform</span>
            </div>
        </div>
        <nav class="sidebar-nav">${nav}</nav>
        <div class="sidebar-footer">
            <div class="system-status">
                <div class="status-dot"></div>
                <span>${eventCount > 0 ? eventCount + " events loaded" : "No data loaded"}</span>
            </div>
        </div>
    </aside>`;
}

/* File upload handler */
function setupUploadZone(zoneId, onFilesLoaded) {
    const zone = document.getElementById(zoneId);
    if (!zone) return;

    const input = document.createElement("input");
    input.type = "file";
    input.multiple = true;
    input.accept = ".log,.txt,.csv,.json,.syslog,.evtx";
    input.style.display = "none";
    zone.appendChild(input);

    zone.addEventListener("click", () => input.click());
    zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("dragover"); });
    zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
    zone.addEventListener("drop", e => {
        e.preventDefault();
        zone.classList.remove("dragover");
        handleFiles(e.dataTransfer.files, onFilesLoaded);
    });
    input.addEventListener("change", () => {
        handleFiles(input.files, onFilesLoaded);
        input.value = "";
    });
}

function handleFiles(fileList, callback) {
    const files = Array.from(fileList);
    let processed = 0;
    let allEvents = [];
    const fileInfo = DataStore.loadFiles();

    files.forEach(file => {
        const reader = new FileReader();
        reader.onload = (e) => {
            const text = e.target.result;
            const events = LogParser.parseFile(text, file.name);
            allEvents = allEvents.concat(events);

            fileInfo.push({ name: file.name, size: file.size, lines: events.length, time: new Date().toISOString() });

            processed++;
            if (processed === files.length) {
                const combined = DataStore.addEvents(allEvents);
                DataStore.saveFiles(fileInfo);
                if (callback) callback(combined, fileInfo);
            }
        };
        reader.readAsText(file);
    });
}

/* Utility functions */
function timeAgo(iso) {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return mins + "m ago";
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + "h ago";
    return Math.floor(hrs / 24) + "d ago";
}

function formatTime(iso) {
    return new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function getRiskClass(score) {
    if (score >= 75) return "critical";
    if (score >= 50) return "high";
    if (score >= 25) return "medium";
    return "low";
}

function downloadFile(content, filename, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
}
