import {detectIncidents, parseEvents} from "./analyzer.js";

const byId = id => document.getElementById(id);
let currentReport = null;
let selectedSeverity = "all";

function node(tag, className, text) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== undefined) item.textContent = text;
  return item;
}

function render(report) {
  currentReport = report;
  byId("event-count").textContent = report.events.length;
  byId("incident-count").textContent = report.incidents.length;
  byId("source-count").textContent = report.sources;
  byId("failure-count").textContent = report.counts.failure;
  const total = Math.max(1, report.events.length);
  byId("success-bar").style.width = `${report.counts.success / total * 100}%`;
  byId("failure-bar").style.width = `${report.counts.failure / total * 100}%`;
  byId("success-label").textContent = `${report.counts.success} success`;
  byId("failure-label").textContent = `${report.counts.failure} failure`;
  renderIncidents();
  byId("status").textContent = `Analyzed ${report.events.length} local events. No data was uploaded.`;
  byId("export").disabled = false;
}

function renderIncidents() {
  if (!currentReport) return;
  const filtered = currentReport.incidents.filter(item => selectedSeverity === "all" || item.severity === selectedSeverity);
  const items = filtered.map(item => {
    const card = node("article", `incident ${item.severity}`);
    const top = node("div", "incident-top");
    top.append(node("span", `badge ${item.severity}`, item.severity), node("time", "", new Date(item.time).toLocaleString()));
    card.append(top, node("h3", "", item.title), node("p", "", item.detail), node("small", "", `Evidence: ${item.evidence}`));
    return card;
  });
  if (!items.length) items.push(node("p", "empty", "No incidents match this severity filter."));
  byId("incidents").replaceChildren(...items);
  byId("shown-count").textContent = `${filtered.length} shown`;
}

async function loadSynthetic() {
  const response = await fetch("./data/synthetic-auth-events.json");
  render(detectIncidents(parseEvents(await response.text())));
}

byId("load-demo").addEventListener("click", loadSynthetic);
byId("file-input").addEventListener("change", async event => {
  const file = event.target.files[0];
  if (!file) return;
  if (file.size > 2_000_000) { byId("status").textContent = "Choose a JSON or CSV file under 2 MB."; return; }
  try { render(detectIncidents(parseEvents(await file.text()))); }
  catch (error) { byId("status").textContent = error.message; }
});
for (const button of document.querySelectorAll("[data-severity]")) button.addEventListener("click", () => {
  selectedSeverity = button.dataset.severity;
  document.querySelectorAll("[data-severity]").forEach(item => item.classList.toggle("active", item === button));
  renderIncidents();
});
byId("export").addEventListener("click", () => {
  if (!currentReport) return;
  const safeReport = { generated_at: new Date().toISOString(), source: "local browser analysis", counts: currentReport.counts, incidents: currentReport.incidents };
  const url = URL.createObjectURL(new Blob([JSON.stringify(safeReport, null, 2)], {type:"application/json"}));
  const link = document.createElement("a"); link.href = url; link.download = "logsentinel-report.json"; link.click(); URL.revokeObjectURL(url);
});

