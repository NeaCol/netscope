document.addEventListener("DOMContentLoaded", () => {
  let topologyData = null;
  let selectedNode = null;
  let loadedPackets = [];

  const elementsToAnimate = document.querySelectorAll("[data-animate]");
  elementsToAnimate.forEach((el, index) => {
    setTimeout(() => {
      el.classList.add("is-ready");
    }, index * 80);
  });

  async function loadInterfaces() {
    const tbody = document.getElementById("iface-table-body");
    try {
      const res = await fetch("/api/interfaces");
      const data = await res.json();
      tbody.innerHTML = "";
      if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7">No interfaces detected.</td></tr>';
        return;
      }
      data.forEach((nic) => {
        const tr = document.createElement("tr");
        const isUpStr = nic.is_up ? "ACTIVE" : "DOWN";
        const isDef = nic.is_default ? " (Primary)" : "";
        tr.innerHTML = `
          <td><strong>${escapeHtml(nic.name)}</strong>${isDef}</td>
          <td>${isUpStr}</td>
          <td><code>${escapeHtml(nic.ipv4 || "-")}</code></td>
          <td><code>${escapeHtml(nic.cidr || "-")}</code></td>
          <td><code>${escapeHtml(nic.mac || "-")}</code></td>
          <td>${nic.speed > 0 ? nic.speed + " Mbps" : "-"}</td>
          <td>${nic.mtu || "-"}</td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="7">Error loading interfaces: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  async function loadTopology() {
    const summary = document.getElementById("topology-summary");
    summary.textContent = "Querying routing and subnet graph...";
    try {
      const res = await fetch("/api/topology");
      topologyData = await res.json();
      renderTopology(topologyData);
      summary.textContent = `Subnet ${topologyData.subnet_cidr || "Local"} · ${topologyData.nodes.length} Nodes`;
    } catch (err) {
      summary.textContent = "Failed to load topology";
    }
  }

  function renderTopology(graph) {
    const svg = document.getElementById("topology-svg");
    svg.innerHTML = "";
    if (!graph || !graph.nodes || graph.nodes.length === 0) return;

    const width = 800;
    const height = 520;

    const nodePositions = {};
    const wanNode = graph.nodes.find((n) => n.node_type === "wan") || graph.nodes[0];
    const gwNode = graph.nodes.find((n) => n.node_type === "gateway") || graph.nodes[1];
    const localNode = graph.nodes.find((n) => n.node_type === "local_host");
    const otherHosts = graph.nodes.filter((n) => n !== wanNode && n !== gwNode && n !== localNode);

    if (wanNode) nodePositions[wanNode.id] = { x: width / 2, y: 70, node: wanNode };
    if (gwNode) nodePositions[gwNode.id] = { x: width / 2, y: 200, node: gwNode };

    const hostTierY = 380;
    const allTier2 = [];
    if (localNode) allTier2.push(localNode);
    allTier2.push(...otherHosts);

    const stepX = width / (allTier2.length + 1);
    allTier2.forEach((h, idx) => {
      nodePositions[h.id] = {
        x: stepX * (idx + 1),
        y: hostTierY + ((idx % 2 === 0) ? -20 : 25),
        node: h,
      };
    });

    graph.links.forEach((link) => {
      const p1 = nodePositions[link.source];
      const p2 = nodePositions[link.target];
      if (p1 && p2) {
        const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
        line.setAttribute("x1", p1.x);
        line.setAttribute("y1", p1.y);
        line.setAttribute("x2", p2.x);
        line.setAttribute("y2", p2.y);
        line.setAttribute("stroke", "#cdc3b6");
        line.setAttribute("stroke-width", "2");
        svg.appendChild(line);
      }
    });

    Object.values(nodePositions).forEach((item) => {
      const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
      g.style.cursor = "pointer";

      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("cx", item.x);
      circle.setAttribute("cy", item.y);
      circle.setAttribute("r", item.node.node_type === "gateway" ? "22" : (item.node.node_type === "wan" ? "24" : "18"));

      let fill = "#6b6763";
      if (item.node.node_type === "wan") fill = "#5c6b54";
      if (item.node.node_type === "gateway") fill = "#333231";
      if (item.node.node_type === "local_host") fill = "#4d5a46";

      circle.setAttribute("fill", fill);
      g.appendChild(circle);

      const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
      text.setAttribute("x", item.x);
      text.setAttribute("y", item.y + 34);
      text.setAttribute("text-anchor", "middle");
      text.setAttribute("fill", "#333231");
      text.setAttribute("font-size", "12");
      text.setAttribute("font-weight", "500");
      text.textContent = item.node.ip;
      g.appendChild(text);

      const labelText = document.createElementNS("http://www.w3.org/2000/svg", "text");
      labelText.setAttribute("x", item.x);
      labelText.setAttribute("y", item.y + 48);
      labelText.setAttribute("text-anchor", "middle");
      labelText.setAttribute("fill", "#6b6763");
      labelText.setAttribute("font-size", "11");
      labelText.textContent = item.node.vendor.slice(0, 16);
      g.appendChild(labelText);

      g.addEventListener("click", () => {
        selectNode(item.node);
      });

      svg.appendChild(g);
    });

    if (gwNode) selectNode(gwNode);
  }

  function selectNode(node) {
    selectedNode = node;
    document.getElementById("inspect-label").textContent = node.label || node.id;
    document.getElementById("inspect-ip").textContent = node.ip || "-";
    document.getElementById("inspect-mac").textContent = node.mac || "-";
    document.getElementById("inspect-vendor").textContent = node.vendor || "-";
    document.getElementById("inspect-rtt").textContent = (node.latency_ms || 0).toFixed(1) + " ms";
    document.getElementById("inspect-status").textContent = node.status || "online";
    document.getElementById("inspect-ports-output").textContent = "";
  }

  document.getElementById("btn-scan-selected-node").addEventListener("click", async () => {
    if (!selectedNode || !selectedNode.ip || selectedNode.ip === "0.0.0.0") return;
    const output = document.getElementById("inspect-ports-output");
    output.textContent = `Probing ports on ${selectedNode.ip}...`;
    try {
      const res = await fetch(`/api/ports?host=${encodeURIComponent(selectedNode.ip)}`);
      const ports = await res.json();
      if (!ports || ports.length === 0) {
        output.textContent = "No standard ports open.";
      } else {
        const portList = ports.map((p) => `${p.port}/${p.service}`).join(", ");
        output.textContent = `Open Ports: ${portList}`;
      }
    } catch (err) {
      output.textContent = `Scan failed: ${err.message}`;
    }
  });

  document.getElementById("btn-refresh-topology").addEventListener("click", loadTopology);

  document.getElementById("btn-hero-inspect").addEventListener("click", () => {
    document.getElementById("topology").scrollIntoView({ behavior: "smooth" });
    loadTopology();
  });

  document.getElementById("btn-run-scan").addEventListener("click", async () => {
    const cidrInput = document.getElementById("scan-cidr-input").value.trim();
    const statusText = document.getElementById("scan-status-text");
    const tbody = document.getElementById("discovery-table-body");

    statusText.textContent = "Scanning active devices on subnet...";
    tbody.innerHTML = '<tr><td colspan="6">Executing subnet discovery sweep...</td></tr>';

    try {
      const query = cidrInput ? `?subnet=${encodeURIComponent(cidrInput)}` : "";
      const res = await fetch(`/api/scan${query}`);
      const hosts = await res.json();
      tbody.innerHTML = "";

      if (!hosts || hosts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6">No hosts discovered.</td></tr>';
        statusText.textContent = "Discovery completed (0 hosts)";
        return;
      }

      hosts.forEach((h) => {
        const role = h.is_gateway ? "Gateway" : (h.is_local ? "This Host" : "Host");
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><code>${escapeHtml(h.ip)}</code></td>
          <td>${role}</td>
          <td>${escapeHtml(h.vendor)}</td>
          <td>${escapeHtml(h.hostname || "-")}</td>
          <td><code>${escapeHtml(h.mac || "-")}</code></td>
          <td>${h.response_time_ms.toFixed(1)} ms</td>
        `;
        tbody.appendChild(tr);
      });

      statusText.textContent = `Discovery completed: ${hosts.length} active devices`;
      loadTopology();
    } catch (err) {
      statusText.textContent = "Scan error: " + err.message;
      tbody.innerHTML = `<tr><td colspan="6">Error: ${escapeHtml(err.message)}</td></tr>`;
    }
  });

  document.getElementById("btn-run-dns-bench").addEventListener("click", async () => {
    const domain = document.getElementById("dns-bench-domain").value.trim() || "cloudflare.com";
    const statusText = document.getElementById("dns-bench-status");
    statusText.textContent = `Benchmarking resolvers for ${domain}...`;

    try {
      const res = await fetch(`/api/dns?domain=${encodeURIComponent(domain)}&benchmark=true`);
      const data = await res.json();
      const bench = data.benchmark || [];

      const maxLatency = Math.max(...bench.map((b) => b.latency_ms), 100);

      bench.forEach((b) => {
        let key = "";
        if (b.server === "1.1.1.1") key = "cloudflare";
        else if (b.server === "8.8.8.8") key = "google";
        else if (b.server === "9.9.9.9") key = "quad9";
        else if (b.server === "208.67.222.222") key = "opendns";

        if (key) {
          const valEl = document.getElementById(`bench-${key}-val`);
          const barEl = document.getElementById(`bench-${key}-bar`);
          if (valEl) valEl.textContent = `${b.latency_ms.toFixed(1)} ms`;
          if (barEl) {
            const pct = Math.min(100, Math.max(5, (b.latency_ms / maxLatency) * 100));
            barEl.style.width = `${pct}%`;
          }
        }
      });
      statusText.textContent = `Tested ${bench.length} public resolvers`;
    } catch (err) {
      statusText.textContent = `Benchmark failed: ${err.message}`;
    }
  });

  document.getElementById("btn-resolve-record").addEventListener("click", async () => {
    const domain = document.getElementById("dns-query-domain").value.trim() || "example.com";
    const type = document.getElementById("dns-query-type").value;
    const timing = document.getElementById("dns-query-timing");
    const tbody = document.getElementById("dns-records-table-body");

    timing.textContent = `Querying ${type} for ${domain}...`;
    try {
      const res = await fetch(`/api/dns?domain=${encodeURIComponent(domain)}&type=${type}`);
      const data = await res.json();
      tbody.innerHTML = "";

      if (!data.answers || data.answers.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4">No ${type} records returned. Status: ${data.status}</td></tr>`;
      } else {
        data.answers.forEach((ans) => {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td>${escapeHtml(ans.name)}</td>
            <td><strong>${escapeHtml(ans.record_type)}</strong></td>
            <td>${ans.ttl}</td>
            <td><code>${escapeHtml(ans.data)}</code></td>
          `;
          tbody.appendChild(tr);
        });
      }
      timing.textContent = `Resolved in ${data.response_time_ms.toFixed(1)} ms via ${data.server}`;
    } catch (err) {
      timing.textContent = "Query failed";
      tbody.innerHTML = `<tr><td colspan="4">Error: ${escapeHtml(err.message)}</td></tr>`;
    }
  });

  document.getElementById("btn-run-ping").addEventListener("click", async () => {
    const target = document.getElementById("ping-target-input").value.trim() || "1.1.1.1";
    const statusMsg = document.getElementById("ping-status-msg");
    statusMsg.textContent = `Probing ${target}...`;

    try {
      const res = await fetch(`/api/ping?target=${encodeURIComponent(target)}&count=5`);
      const data = await res.json();

      document.getElementById("stat-avg-rtt").textContent = `${data.avg_ms.toFixed(1)} ms`;
      document.getElementById("stat-jitter").textContent = `${data.jitter_ms.toFixed(1)} ms`;
      document.getElementById("stat-loss").textContent = `${data.packet_loss_pct.toFixed(1)}%`;
      document.getElementById("stat-range").textContent = `${data.min_ms.toFixed(1)} / ${data.max_ms.toFixed(1)} ms`;

      statusMsg.textContent = `Received ${data.received} / ${data.sent} probes`;
    } catch (err) {
      statusMsg.textContent = `Ping failed: ${err.message}`;
    }
  });

  document.getElementById("btn-run-trace").addEventListener("click", async () => {
    const target = document.getElementById("ping-target-input").value.trim() || "1.1.1.1";
    const statusMsg = document.getElementById("ping-status-msg");
    const traceTable = document.getElementById("trace-table");
    const tbody = document.getElementById("trace-table-body");

    statusMsg.textContent = `Tracing hops to ${target}...`;
    traceTable.style.display = "table";
    tbody.innerHTML = '<tr><td colspan="4">Executing traceroute...</td></tr>';

    try {
      const res = await fetch(`/api/trace?target=${encodeURIComponent(target)}&max_hops=15`);
      const hops = await res.json();
      tbody.innerHTML = "";

      hops.forEach((h) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${h.hop}</td>
          <td><code>${escapeHtml(h.ip || "*")}</code></td>
          <td>${h.rtt_ms ? h.rtt_ms.toFixed(1) + " ms" : "*"}</td>
          <td>${escapeHtml(h.status)}</td>
        `;
        tbody.appendChild(tr);
      });
      statusMsg.textContent = `Traced ${hops.length} hops to destination`;
    } catch (err) {
      statusMsg.textContent = `Traceroute error: ${err.message}`;
    }
  });

  document.getElementById("btn-load-sample-pcap").addEventListener("click", async () => {
    const metaText = document.getElementById("pcap-meta-text");
    metaText.textContent = "Loading synthetic educational PCAP capture...";
    try {
      const res = await fetch("/api/sample-pcap");
      const data = await res.json();
      loadedPackets = data.packets || [];
      metaText.textContent = `Loaded ${loadedPackets.length} frames · ${data.report.total_bytes} bytes total`;
      renderPacketPills(loadedPackets);
    } catch (err) {
      metaText.textContent = `Error: ${err.message}`;
    }
  });

  document.getElementById("btn-show-hex-input").addEventListener("click", () => {
    const panel = document.getElementById("hex-input-panel");
    panel.style.display = panel.style.display === "none" ? "block" : "none";
  });

  document.getElementById("btn-decode-raw-hex").addEventListener("click", async () => {
    const hex = document.getElementById("raw-hex-input").value.trim();
    if (!hex) return;
    try {
      const res = await fetch("/api/analyze-packet", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hex_data: hex }),
      });
      const pkt = await res.json();
      loadedPackets = [pkt];
      renderPacketPills(loadedPackets);
    } catch (err) {
      alert("Decode failed: " + err.message);
    }
  });

  function renderPacketPills(packets) {
    const container = document.getElementById("packet-selector-pills");
    container.innerHTML = "";
    packets.forEach((p, idx) => {
      const btn = document.createElement("button");
      btn.className = "button-secondary";
      btn.style.minHeight = "2.2rem";
      btn.style.padding = "0.2rem 0.8rem";
      btn.textContent = `Frame ${idx + 1}: ${p.summary.slice(0, 32)}`;
      btn.addEventListener("click", () => {
        showPacketDetail(p);
      });
      container.appendChild(btn);
    });
    if (packets.length > 0) {
      showPacketDetail(packets[0]);
    }
  }

  function showPacketDetail(pkt) {
    const tree = document.getElementById("dissector-layer-tree");
    const hex = document.getElementById("dissector-hex-dump");
    tree.innerHTML = "";

    const summaryBlock = document.createElement("div");
    summaryBlock.className = "layer-block";
    summaryBlock.innerHTML = `
      <div class="layer-title">${escapeHtml(pkt.summary)}</div>
      <div class="meta-label">Length: ${pkt.length} bytes · Captured at ${pkt.timestamp.toFixed(4)}s</div>
    `;
    tree.appendChild(summaryBlock);

    pkt.layers.forEach((layer) => {
      const block = document.createElement("div");
      block.className = "layer-block";
      let fieldsHtml = "";
      for (const [k, v] of Object.entries(layer.fields)) {
        fieldsHtml += `
          <div class="layer-field-row">
            <span class="layer-field-label">${escapeHtml(k)}:</span>
            <span class="layer-field-val"><code>${escapeHtml(String(v))}</code></span>
          </div>
        `;
      }
      block.innerHTML = `
        <div class="layer-title">${escapeHtml(layer.name)}</div>
        <p class="meta-label" style="margin-bottom: 0.6rem;">${escapeHtml(layer.description)}</p>
        ${fieldsHtml}
      `;
      tree.appendChild(block);
    });

    if (pkt.educational_notes && pkt.educational_notes.length > 0) {
      const notesBlock = document.createElement("div");
      notesBlock.className = "layer-block";
      notesBlock.style.backgroundColor = "var(--surface-alt)";
      notesBlock.innerHTML = `
        <div class="layer-title">Educational Analysis Note</div>
        <p style="font-size: var(--step-small); color: var(--ink);">${escapeHtml(pkt.educational_notes.join(" "))}</p>
      `;
      tree.appendChild(notesBlock);
    }

    hex.textContent = pkt.hex_dump || "// No hex payload";
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  loadInterfaces();
  loadTopology();
});
