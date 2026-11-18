const MINUTE = 60_000;

const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };

function cleanText(value, fallback = "unknown") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

export function normalizeEvent(raw, index = 0) {
  const timestamp = new Date(raw.timestamp);
  if (Number.isNaN(timestamp.getTime())) throw new Error(`Event ${index + 1} has an invalid timestamp.`);
  const outcome = cleanText(raw.outcome).toLowerCase();
  if (!["success", "failure"].includes(outcome)) throw new Error(`Event ${index + 1} must use outcome "success" or "failure".`);
  return {
    id: cleanText(raw.id, `event-${index + 1}`),
    timestamp: timestamp.toISOString(),
    source_ip: cleanText(raw.source_ip),
    username: cleanText(raw.username),
    outcome,
    country: cleanText(raw.country),
    service: cleanText(raw.service, "identity"),
  };
}

function csvRows(text) {
  const lines = text.trim().split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) throw new Error("CSV data needs a header and at least one event.");
  const parseLine = line => {
    const values = [];
    let value = "", quoted = false;
    for (let i = 0; i < line.length; i += 1) {
      const char = line[i];
      if (char === '"' && quoted && line[i + 1] === '"') { value += '"'; i += 1; }
      else if (char === '"') quoted = !quoted;
      else if (char === "," && !quoted) { values.push(value); value = ""; }
      else value += char;
    }
    values.push(value);
    return values;
  };
  const headers = parseLine(lines[0]).map(item => item.trim());
  return lines.slice(1).map(line => Object.fromEntries(headers.map((header, i) => [header, parseLine(line)[i] ?? ""])));
}

export function parseEvents(text) {
  const input = String(text || "").trim();
  if (!input) throw new Error("The selected file is empty.");
  let rows;
  if (input.startsWith("[") || input.startsWith("{")) {
    const parsed = JSON.parse(input);
    rows = Array.isArray(parsed) ? parsed : parsed.events;
  } else rows = csvRows(input);
  if (!Array.isArray(rows)) throw new Error("JSON must be an array or contain an events array.");
  if (rows.length > 10_000) throw new Error("This browser demo accepts at most 10,000 events.");
  return rows.map(normalizeEvent).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
}

function windows(events, spanMinutes) {
  const span = spanMinutes * MINUTE;
  const result = [];
  for (let start = 0, end = 0; start < events.length; start += 1) {
    if (end < start) end = start;
    while (end + 1 < events.length && new Date(events[end + 1].timestamp) - new Date(events[start].timestamp) <= span) end += 1;
    result.push(events.slice(start, end + 1));
  }
  return result;
}

function incident(type, severity, title, detail, evidence, time, key) {
  return { type, severity, title, detail, evidence, time, key };
}

export function detectIncidents(inputEvents) {
  const events = inputEvents.map(normalizeEvent).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  const incidents = [];
  const seen = new Set();
  const add = item => { if (!seen.has(item.key)) { seen.add(item.key); incidents.push(item); } };
  const failures = events.filter(event => event.outcome === "failure");
  const bySource = Map.groupBy ? Map.groupBy(failures, e => e.source_ip) : failures.reduce((map, event) => map.set(event.source_ip, [...(map.get(event.source_ip) || []), event]), new Map());

  for (const [source, sourceFailures] of bySource) {
    for (const group of windows(sourceFailures, 10)) {
      if (group.length >= 5) {
        add(incident("brute_force", "high", "Repeated authentication failures", "At least five failures came from one source within ten minutes.", `${group.length} failures from ${source}; users: ${[...new Set(group.map(e => e.username))].join(", ")}`, group.at(-1).timestamp, `brute:${source}`));
        break;
      }
    }
    for (const group of windows(sourceFailures, 15)) {
      const users = [...new Set(group.map(e => e.username))];
      if (users.length >= 4) {
        add(incident("password_spray", "critical", "Possible password-spray pattern", "One source attempted several usernames in a short period. This pattern needs investigation, but is not proof of an attack.", `${users.length} usernames from ${source}: ${users.join(", ")}`, group.at(-1).timestamp, `spray:${source}`));
        break;
      }
    }
  }

  for (const success of events.filter(event => event.outcome === "success")) {
    const time = new Date(success.timestamp);
    const recent = failures.filter(event => event.source_ip === success.source_ip && event.username === success.username && time - new Date(event.timestamp) >= 0 && time - new Date(event.timestamp) <= 10 * MINUTE);
    if (recent.length >= 4) add(incident("success_after_failures", "critical", "Successful login after repeated failures", "A success followed several failures for the same account and source. Confirm whether this was the account owner.", `${recent.length} prior failures for ${success.username} from ${success.source_ip}`, success.timestamp, `post:${success.id}`));
    const hour = time.getUTCHours();
    if (hour < 6 || hour >= 23) add(incident("off_hours", "low", "Login outside the review window", "The successful login occurred outside 06:00–23:00 UTC. This is context for review, not inherently suspicious.", `${success.username} at ${success.timestamp}`, success.timestamp, `off:${success.id}`));
  }

  const successesByUser = events.filter(e => e.outcome === "success").reduce((map, event) => map.set(event.username, [...(map.get(event.username) || []), event]), new Map());
  for (const [username, successes] of successesByUser) {
    for (let i = 1; i < successes.length; i += 1) {
      const previous = successes[i - 1], current = successes[i];
      const delta = new Date(current.timestamp) - new Date(previous.timestamp);
      if (previous.country !== current.country && delta <= 60 * MINUTE) {
        add(incident("rapid_country_change", "medium", "Rapid country-label change", "Two success events for one account have different country labels within an hour. Geo-IP can be wrong and this does not prove travel.", `${username}: ${previous.country} to ${current.country} in ${Math.round(delta / MINUTE)} minutes`, current.timestamp, `country:${username}:${current.id}`));
      }
    }
  }

  incidents.sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || new Date(b.time) - new Date(a.time));
  const counts = events.reduce((acc, event) => { acc[event.outcome] += 1; return acc; }, { success: 0, failure: 0 });
  return { events, incidents, counts, sources: new Set(events.map(e => e.source_ip)).size };
}

