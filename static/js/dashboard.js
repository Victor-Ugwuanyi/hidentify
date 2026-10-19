/* HIDENTIFY frontend controller */
const HIDENTIFY = (function () {
    const socket = io();
    let charts = {};

    function fmtTime(iso) {
        const d = typeof iso === "number" ? new Date(iso * 1000) : new Date(iso);
        return d.toLocaleTimeString();
    }

    function severityBadge(sev) {
        return `<span class="badge badge-${sev}">${sev}</span>`;
    }

    function showToast(alert) {
        const container = document.getElementById("toast-container");
        if (!container) return;
        const el = document.createElement("div");
        el.className = "toast";
        el.style.borderLeftColor = {
            critical: "#f43f5e", high: "#fb923c", medium: "#facc15", low: "#60a5fa",
        }[alert.severity] || "#60a5fa";
        el.innerHTML = `<strong>${alert.type} (${alert.severity})</strong><span>${alert.description}</span>`;
        container.appendChild(el);
        setTimeout(() => el.remove(), 6000);
    }

    function refreshCapturePill() {
        fetch("/api/status").then(r => r.json()).then(status => {
            const pill = document.getElementById("global-capture-pill");
            const label = document.getElementById("global-capture-label");
            if (!pill) return;
            if (status.capturing) {
                pill.className = "capture-pill on";
                label.textContent = "Capturing: " + (status.interface || "default");
            } else {
                pill.className = "capture-pill off";
                label.textContent = "Idle";
            }
            const kpiAlerts = document.getElementById("kpi-alerts");
            if (kpiAlerts) kpiAlerts.textContent = status.total_alerts;
            const kpiBlocked = document.getElementById("kpi-blocked");
            if (kpiBlocked) kpiBlocked.textContent = status.blocked_ips;

            const startBtn = document.getElementById("btn-start-capture");
            const stopBtn = document.getElementById("btn-stop-capture");
            if (startBtn && stopBtn) {
                startBtn.style.display = status.capturing ? "none" : "inline-block";
                stopBtn.style.display = status.capturing ? "inline-block" : "none";
            }
        });
    }

    function wireCaptureControls() {
        const startBtn = document.getElementById("btn-start-capture");
        const stopBtn = document.getElementById("btn-stop-capture");
        const ifaceSelect = document.getElementById("iface-select");
        if (!startBtn) return;

        fetch("/api/interfaces").then(r => r.json()).then(data => {
            if (!data.scapy_available) {
                ifaceSelect.innerHTML = `<option value="">scapy/npcap not available</option>`;
                startBtn.disabled = true;
                return;
            }
            ifaceSelect.innerHTML = data.interfaces.map(i => `<option value="${i}">${i}</option>`).join("");

            // If a capture is already running, reflect its real interface in the
            // dropdown instead of defaulting to the first option, and lock the
            // dropdown so it can't be changed mid-capture (switching interfaces
            // without stopping first isn't supported).
            fetch("/api/status").then(r => r.json()).then(status => {
                if (status.capturing && status.interface) {
                    if (![...ifaceSelect.options].some(o => o.value === status.interface)) {
                        ifaceSelect.insertAdjacentHTML("afterbegin", `<option value="${status.interface}">${status.interface}</option>`);
                    }
                    ifaceSelect.value = status.interface;
                    ifaceSelect.disabled = true;
                } else {
                    ifaceSelect.disabled = false;
                }
            });
        });

        startBtn.addEventListener("click", () => {
            fetch("/api/capture/start", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ interface: ifaceSelect.value }),
            }).then(r => r.json()).then(res => {
                if (!res.success) alert("Could not start capture: " + res.error);
                refreshCapturePill();
            });
        });

        stopBtn.addEventListener("click", () => {
            fetch("/api/capture/stop", { method: "POST" }).then(() => {
                ifaceSelect.disabled = false;
                refreshCapturePill();
            });
        });
    }

    function threatLevelFromAlerts(alerts) {
        if (alerts.some(a => a.severity === "critical")) return "critical";
        if (alerts.some(a => a.severity === "high")) return "high";
        if (alerts.some(a => a.severity === "medium")) return "medium";
        return "low";
    }

    function renderRecentAlerts(alerts, tbodySelector, full) {
        const tbody = document.querySelector(tbodySelector);
        if (!tbody) return;
        tbody.innerHTML = alerts.map(a => `
            <tr>
                <td class="mono">${fmtTime(a.timestamp)}</td>
                <td>${a.type}</td>
                <td>${severityBadge(a.severity)}</td>
                <td class="mono">${a.src_ip || "-"}</td>
                ${full ? `<td class="mono">${a.dst_ip || "-"}</td><td>${[a.city, a.country].filter(Boolean).join(", ") || "-"}</td>` : ""}
                <td>${a.description}</td>
                ${full ? `<td><button class="btn btn-ghost" onclick="HIDENTIFY.resolveAlert(${a.id}, this)">Resolve</button></td>` : ""}
            </tr>
        `).join("") || `<tr><td colspan="8" class="muted">No alerts yet.</td></tr>`;
    }

    function resolveAlert(id, btn) {
        fetch(`/api/alerts/${id}/resolve`, { method: "POST" }).then(() => {
            btn.closest("tr").style.opacity = 0.4;
            btn.disabled = true;
        });
    }

    // ---------------- Dashboard page ----------------
    function initDashboard() {
        wireCaptureControls();

        charts.traffic = new Chart(document.getElementById("chart-traffic"), {
            type: "line",
            data: { labels: [], datasets: [{ label: "Packets", data: [], borderColor: "#22d3ee", backgroundColor: "rgba(34,211,238,0.1)", fill: true, tension: 0.35 }] },
            options: baseChartOptions(),
        });

        charts.protocol = new Chart(document.getElementById("chart-protocol"), {
            type: "doughnut",
            data: { labels: ["TCP", "UDP", "ICMP", "Other"], datasets: [{ data: [0, 0, 0, 0], backgroundColor: ["#22d3ee", "#34d399", "#facc15", "#8b98ac"] }] },
            options: { plugins: { legend: { labels: { color: "#8b98ac" } } } },
        });

        fetch("/api/alerts?limit=8").then(r => r.json()).then(alerts => {
            renderRecentAlerts(alerts, "#recent-alerts-table tbody", false);
            const level = threatLevelFromAlerts(alerts);
            const el = document.getElementById("kpi-threat");
            el.textContent = level.toUpperCase();
            el.className = "level-" + level;
        });

        socket.on("traffic_update", (d) => {
            pushPoint(charts.traffic, fmtTime(d.timestamp), d.packet_count, 20);
            charts.protocol.data.datasets[0].data = [d.tcp_count, d.udp_count, d.icmp_count, d.other_count];
            charts.protocol.update();
            document.getElementById("kpi-packets").textContent = d.packet_count;
        });

        socket.on("new_alert", (alert) => {
            showToast(alert);
            const kpi = document.getElementById("kpi-alerts");
            if (kpi) kpi.textContent = parseInt(kpi.textContent || "0") + 1;
            fetch("/api/alerts?limit=8").then(r => r.json()).then(alerts => renderRecentAlerts(alerts, "#recent-alerts-table tbody", false));
        });
    }

    // ---------------- Traffic page ----------------
    function initTrafficPage() {
        charts.trafficFull = new Chart(document.getElementById("chart-traffic-full"), {
            type: "line",
            data: { labels: [], datasets: [
                { label: "Packets", data: [], borderColor: "#22d3ee", tension: 0.35 },
                { label: "Bytes (KB)", data: [], borderColor: "#34d399", tension: 0.35 },
            ]},
            options: baseChartOptions(),
        });
        charts.anomaly = new Chart(document.getElementById("chart-anomaly"), {
            type: "line",
            data: { labels: [], datasets: [{ label: "Anomaly Score", data: [], borderColor: "#f43f5e", tension: 0.35 }] },
            options: baseChartOptions(),
        });

        fetch("/api/stats?limit=40").then(r => r.json()).then(rows => {
            rows.forEach(row => addStatsRow(row));
        });

        socket.on("traffic_update", (d) => addStatsRow(d, true));
    }

    function addStatsRow(d, live) {
        const t = fmtTime(d.timestamp);
        pushPoint(charts.trafficFull, t, d.packet_count, 30);
        charts.trafficFull.data.datasets[1].data.push((d.byte_count / 1024).toFixed(1));
        if (charts.trafficFull.data.datasets[1].data.length > 30) charts.trafficFull.data.datasets[1].data.shift();
        charts.trafficFull.update();

        if (d.anomaly_score !== null && d.anomaly_score !== undefined) {
            pushPoint(charts.anomaly, t, d.anomaly_score, 30);
        }

        const tbody = document.querySelector("#window-table tbody");
        if (tbody && live) {
            const row = document.createElement("tr");
            row.innerHTML = `<td class="mono">${t}</td><td>${d.packet_count}</td><td>${d.byte_count}</td><td>${d.tcp_count}</td><td>${d.udp_count}</td><td>${d.icmp_count}</td><td>${d.unique_src}</td>`;
            tbody.prepend(row);
            while (tbody.rows.length > 25) tbody.deleteRow(-1);
        }
    }

    // ---------------- Alerts page ----------------
    function initAlertsPage() {
        function load() {
            const sev = document.getElementById("filter-severity").value;
            const type = document.getElementById("filter-type").value;
            const params = new URLSearchParams();
            if (sev) params.set("severity", sev);
            if (type) params.set("type", type);
            fetch("/api/alerts?" + params.toString()).then(r => r.json()).then(alerts => {
                renderRecentAlerts(alerts, "#alerts-table tbody", true);
            });
        }
        document.getElementById("filter-severity").addEventListener("change", load);
        document.getElementById("filter-type").addEventListener("change", load);
        socket.on("new_alert", load);
        load();
    }

    // ---------------- Blocklist page ----------------
    function initBlocklistPage() {
        function load() {
            fetch("/api/blocklist").then(r => r.json()).then(rows => {
                const tbody = document.querySelector("#blocklist-table tbody");
                tbody.innerHTML = rows.map(r => `
                    <tr>
                        <td class="mono">${r.ip}</td>
                        <td>${r.reason || "-"}</td>
                        <td class="mono">${fmtTime(r.added_at)}</td>
                        <td>${r.enforced ? "✅" : "⚠️ tracked only"}</td>
                        <td><button class="btn btn-ghost" onclick="HIDENTIFY.unblockIp('${r.ip}')">Remove</button></td>
                    </tr>
                `).join("") || `<tr><td colspan="5" class="muted">No blocked IPs.</td></tr>`;
            });
        }
        document.getElementById("block-form").addEventListener("submit", (e) => {
            e.preventDefault();
            const ip = document.getElementById("block-ip").value.trim();
            const reason = document.getElementById("block-reason").value.trim();
            fetch("/api/blocklist/add", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ip, reason }),
            }).then(r => r.json()).then(() => {
                document.getElementById("block-ip").value = "";
                document.getElementById("block-reason").value = "";
                load();
            });
        });
        socket.on("blocklist_update", load);
        load();
        window.HIDENTIFY_unblockIp = unblockIp;
    }

    function unblockIp(ip) {
        fetch("/api/blocklist/remove", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip }),
        }).then(() => document.getElementById("blocklist-table") && HIDENTIFY.initBlocklistPage());
    }

    // ---------------- Settings page ----------------
    function initSettingsPage() {
        document.getElementById("settings-form").addEventListener("submit", (e) => {
            e.preventDefault();
            const form = e.target;
            const data = {};
            new FormData(form).forEach((v, k) => { data[k] = v; });
            ["arp_spoof_enabled", "auto_block_critical", "geoip_enabled", "anomaly_detection_enabled"].forEach(k => {
                data[k] = form.querySelector(`[name="${k}"]`).checked;
            });
            ["port_scan_threshold", "port_scan_window", "syn_flood_threshold", "syn_flood_window",
             "icmp_flood_threshold", "icmp_flood_window", "anomaly_window_seconds", "anomaly_baseline_buckets"].forEach(k => {
                data[k] = parseInt(data[k], 10);
            });
            fetch("/api/settings", {
                method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data),
            }).then(r => r.json()).then(() => alert("Settings saved."));
        });
    }

    function pushPoint(chart, label, value, max) {
        chart.data.labels.push(label);
        chart.data.datasets[0].data.push(value);
        if (chart.data.labels.length > max) {
            chart.data.labels.shift();
            chart.data.datasets[0].data.shift();
        }
        chart.update();
    }

    function baseChartOptions() {
        return {
            responsive: true,
            plugins: { legend: { labels: { color: "#8b98ac" } } },
            scales: {
                x: { ticks: { color: "#8b98ac" }, grid: { color: "rgba(255,255,255,0.04)" } },
                y: { ticks: { color: "#8b98ac" }, grid: { color: "rgba(255,255,255,0.04)" } },
            },
        };
    }

    // Keep the sidebar capture pill live on every page, not just the dashboard.
    refreshCapturePill();
    setInterval(refreshCapturePill, 4000);

    return {
        initDashboard, initTrafficPage, initAlertsPage, initBlocklistPage, initSettingsPage,
        resolveAlert, unblockIp,
    };
})();
