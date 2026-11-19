(() => {
  const $ = (id) => document.getElementById(id);

  const ALLOWED_SEVERITY = new Set(["Info", "Warning", "Critical"]);
  const ALLOWED_RISK = new Set(["Low", "Medium", "High", "Critical"]);

  const dropzone = $("dropzone");
  const fileInput = $("fileInput");
  const fileName = $("fileName");
  const logText = $("logText");
  const statusEl = $("status");
  const analyzeBtn = $("analyzeBtn");
  const results = $("results");
  const timeline = $("timeline");

  let selectedFile = null;
  let lastResult = null;

  function setStatus(message, isError = false) {
    statusEl.textContent = message || "";
    statusEl.classList.toggle("error", Boolean(isError));
  }

  function clearFileSelection() {
    selectedFile = null;
    fileInput.value = "";
    fileName.textContent = "";
    fileName.classList.add("hidden");
  }

  function safeToken(value, allowed, fallback) {
    const v = String(value || "").trim();
    return allowed.has(v) ? v : fallback;
  }

  function displayName(name) {
    // Avoid path segments / control characters in UI status text.
    return String(name || "upload.log").replace(/[^\w.\- ()[\]]+/g, "_").slice(0, 120);
  }

  async function loadSample(name) {
    setStatus(`Loading sample: ${name}…`);
    const res = await fetch(`/api/sample?name=${encodeURIComponent(name)}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(typeof err.detail === "string" ? err.detail : "Failed to load sample");
    }
    const data = await res.json();
    clearFileSelection();
    logText.value = data.content;
    setStatus(`Sample "${name}" loaded. Ready to analyze.`);
  }

  function downloadBlob(filename, content, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function toMarkdown(result) {
    const lines = [
      "# Incident Timeline Report",
      "",
      `**Overall risk:** ${result.overall_risk}`,
      `**Lines analyzed:** ${result.lines_analyzed}`,
      `**Suspicious events:** ${result.suspicious_events}`,
      `**Provider:** ${result.provider_used}`,
      "",
      "## Executive Summary",
      "",
      result.summary,
      "",
      "## Timeline",
      "",
    ];

    for (const event of result.timeline || []) {
      lines.push(`### ${event.event_title}`);
      lines.push("");
      lines.push(`- **Timestamp:** ${event.timestamp}`);
      lines.push(`- **Severity:** ${event.severity}`);
      lines.push(`- **Source IP:** ${event.source_ip}`);
      lines.push(`- **Description:** ${event.description}`);
      lines.push("");
    }
    return lines.join("\n");
  }

  function renderResults(data) {
    lastResult = data;
    results.classList.remove("hidden");

    $("statLines").textContent = String(data.lines_analyzed ?? 0);
    $("statEvents").textContent = String(data.suspicious_events ?? (data.timeline || []).length);

    const risk = safeToken(data.overall_risk, ALLOWED_RISK, "Low");
    const riskEl = $("statRisk");
    riskEl.textContent = risk;
    riskEl.className = `value risk-${risk}`;

    $("summaryText").textContent = data.summary || "";
    $("providerUsed").textContent = data.provider_used || "—";

    timeline.replaceChildren();
    const events = Array.isArray(data.timeline) ? data.timeline : [];
    if (!events.length) {
      const empty = document.createElement("p");
      empty.className = "hint";
      empty.textContent = "No suspicious events were identified in this log set.";
      timeline.appendChild(empty);
      return;
    }

    events.forEach((event, index) => {
      const severity = safeToken(event.severity, ALLOWED_SEVERITY, "Info");

      const article = document.createElement("article");
      article.className = `event sev-${severity}`;
      article.style.animationDelay = `${Math.min(index * 0.04, 0.4)}s`;

      const top = document.createElement("div");
      top.className = "event-top";

      const badge = document.createElement("span");
      badge.className = `badge ${severity}`;
      badge.textContent = severity;

      const title = document.createElement("h3");
      title.className = "event-title";
      title.textContent = event.event_title || "Event";

      top.append(badge, title);

      const meta = document.createElement("div");
      meta.className = "event-meta";
      meta.textContent = `${event.timestamp || "N/A"} · ${event.source_ip || "N/A"}`;

      const desc = document.createElement("p");
      desc.className = "event-desc";
      desc.textContent = event.description || "";

      article.append(top, meta, desc);
      timeline.appendChild(article);
    });

    results.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function analyze() {
    const text = logText.value.trim();
    analyzeBtn.disabled = true;
    setStatus("Analyzing logs…");

    try {
      let res;
      if (selectedFile && !text) {
        const form = new FormData();
        form.append("file", selectedFile);
        res = await fetch("/api/analyze/file", { method: "POST", body: form });
      } else if (text) {
        res = await fetch("/api/analyze/text", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text }),
        });
      } else if (selectedFile) {
        const form = new FormData();
        form.append("file", selectedFile);
        res = await fetch("/api/analyze/file", { method: "POST", body: form });
      } else {
        throw new Error("Provide a log file or paste log text first.");
      }

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        const detail = err.detail;
        const message =
          typeof detail === "string"
            ? detail
            : Array.isArray(detail)
              ? detail.map((d) => d.msg).join("; ")
              : "Analysis failed";
        throw new Error(message);
      }

      const data = await res.json();
      renderResults(data);
      setStatus(
        `Done — ${data.suspicious_events} event(s), risk ${data.overall_risk} via ${data.provider_used}.`
      );
    } catch (err) {
      setStatus(err.message || String(err), true);
    } finally {
      analyzeBtn.disabled = false;
    }
  }

  dropzone.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fileInput.click();
    }
  });

  ["dragenter", "dragover"].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", (e) => {
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    selectedFile = file;
    fileName.textContent = displayName(file.name);
    fileName.classList.remove("hidden");
    setStatus(`File selected: ${displayName(file.name)}`);
  });

  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    selectedFile = file;
    fileName.textContent = displayName(file.name);
    fileName.classList.remove("hidden");
    setStatus(`File selected: ${displayName(file.name)}`);
  });

  $("analyzeBtn").addEventListener("click", analyze);
  $("loadSampleBtn").addEventListener("click", () =>
    loadSample("apache").catch((err) => setStatus(err.message, true))
  );
  $("sampleApacheBtn").addEventListener("click", () =>
    loadSample("apache").catch((err) => setStatus(err.message, true))
  );
  $("sampleSshBtn").addEventListener("click", () =>
    loadSample("ssh").catch((err) => setStatus(err.message, true))
  );

  $("clearBtn").addEventListener("click", () => {
    clearFileSelection();
    logText.value = "";
    results.classList.add("hidden");
    lastResult = null;
    setStatus("");
  });

  $("exportJsonBtn").addEventListener("click", () => {
    if (!lastResult) return;
    downloadBlob(
      "incident-timeline.json",
      JSON.stringify(lastResult, null, 2),
      "application/json"
    );
  });

  $("exportMdBtn").addEventListener("click", () => {
    if (!lastResult) return;
    downloadBlob("incident-timeline.md", toMarkdown(lastResult), "text/markdown");
  });
})();
