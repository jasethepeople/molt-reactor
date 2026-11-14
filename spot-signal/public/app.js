const CATEGORY_LABELS = {
  spot: "Useful place",
  full: "At capacity",
  hazard: "Hazard",
  activity: "Time-sensitive condition",
  resource: "Resource"
};
const CATEGORY_COLORS = {
  spot: "#2563eb",
  full: "#8a4b9d",
  hazard: "#bd3c2e",
  activity: "#bd7818",
  resource: "#147451"
};
const form = document.querySelector("#report-form");
const categoryInput = document.querySelector("#category");
const latitudeInput = document.querySelector("#latitude");
const longitudeInput = document.querySelector("#longitude");
const confidenceInput = document.querySelector("#confidence");
const activityOptInRow = document.querySelector("#activity-opt-in-row");
const activityOptIn = document.querySelector("#activity-opt-in");
const reportStatus = document.querySelector("#report-status");
const activityPanel = document.querySelector("#activity-panel");
const activityStatus = document.querySelector("#activity-status");
const reportList = document.querySelector("#reports");
const submitButton = document.querySelector("#submit-report");
let config;
let map;
let pinLayer;
let tileLayer;
let deviceReady = false;
let pendingCoordinates = null;

function status(element, text, kind = "") {
  element.textContent = text;
  element.className = `status ${kind}`.trim();
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    cache: "no-store",
    credentials: "same-origin",
    ...options,
    headers: { "Accept": "application/json", ...(options.headers ?? {}) }
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.message ?? `Request failed (${response.status})`);
  return body;
}

async function solveChallenge(challenge, difficultyBits) {
  return new Promise((resolve, reject) => {
    const worker = new Worker("/pow-worker.js");
    const timeout = setTimeout(() => {
      worker.terminate();
      reject(new Error("Proof-of-work timed out. Please try again."));
    }, 120_000);
    worker.onmessage = event => {
      if (event.data.type === "progress") {
        status(reportStatus, `Preparing a privacy-preserving proof (${event.data.attempts.toLocaleString()} attempts)…`);
        return;
      }
      clearTimeout(timeout);
      worker.terminate();
      if (event.data.type === "solved") resolve(event.data.nonce);
      else reject(new Error(event.data.message ?? "Could not prepare the report"));
    };
    worker.onerror = () => {
      clearTimeout(timeout);
      worker.terminate();
      reject(new Error("Proof-of-work worker failed"));
    };
    worker.postMessage({ challenge, difficultyBits });
  });
}

async function challengeProof() {
  const challenge = await requestJson("/api/challenge");
  const nonce = await solveChallenge(challenge.challenge, challenge.difficultyBits);
  return { challenge: challenge.challenge, nonce };
}

function startMap() {
  map = L.map("map", { scrollWheelZoom: false, zoomControl: true }).setView([39.5, -98.35], 4);
  pinLayer = L.layerGroup().addTo(map);
  document.querySelector("#tile-toggle").addEventListener("click", toggleStreetMap);
  map.on("click", event => {
    const lat = roundInput(event.latlng.lat);
    const lon = roundInput(event.latlng.lng);
    latitudeInput.value = lat;
    longitudeInput.value = lon;
    pendingCoordinates = { latitude: Number(lat), longitude: Number(lon) };
    document.querySelector("#map-help").textContent = `Approximate area selected: ${lat}, ${lon}. The server broadens this location before saving.`;
  });
}

function toggleStreetMap() {
  const button = document.querySelector("#tile-toggle");
  if (tileLayer) {
    map.removeLayer(tileLayer);
    tileLayer = undefined;
    button.textContent = "Load street map";
    button.setAttribute("aria-pressed", "false");
    return;
  }
  tileLayer = L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 18,
    attribution: "© OpenStreetMap contributors"
  }).addTo(map);
  button.textContent = "Hide street map";
  button.setAttribute("aria-pressed", "true");
}

function roundInput(value) {
  return Number(value).toFixed(4);
}

function updateActivityControls() {
  const selectedActivity = categoryInput.value === "activity";
  activityOptInRow.classList.toggle("hidden", !selectedActivity);
  if (!selectedActivity) activityOptIn.checked = false;
}

function renderReports(reports) {
  pinLayer.clearLayers();
  reportList.replaceChildren();
  if (!reports.length) {
    const empty = document.createElement("p");
    empty.className = "helper";
    empty.textContent = "No currently visible reports. Reports expire and are published after a delay.";
    reportList.append(empty);
    return;
  }
  const bounds = [];
  for (const report of reports) {
    const color = CATEGORY_COLORS[report.category] ?? "#52645f";
    const marker = L.circleMarker([report.latitude, report.longitude], {
      radius: 9,
      color,
      fillColor: color,
      fillOpacity: 0.76,
      weight: 2
    }).bindTooltip(`${CATEGORY_LABELS[report.category] ?? "Report"} · approximate area`);
    marker.addTo(pinLayer);
    bounds.push([report.latitude, report.longitude]);
    reportList.append(makeReportCard(report, color));
  }
  if (bounds.length) map.fitBounds(bounds, { padding: [30, 30], maxZoom: 13 });
}

function makeReportCard(report, color) {
  const card = document.createElement("article");
  card.className = "report-card";
  const heading = document.createElement("h3");
  const dot = document.createElement("span");
  dot.className = "category-dot";
  dot.style.backgroundColor = color;
  dot.setAttribute("aria-hidden", "true");
  heading.append(dot, document.createTextNode(CATEGORY_LABELS[report.category] ?? "Report"));
  const date = document.createElement("p");
  date.textContent = `Reported ${report.reportedDay}; expires ${report.expiresDay}.`;
  const confidence = document.createElement("p");
  confidence.textContent = `Community confidence: ${report.confidence}/3.`;
  const voteRow = document.createElement("div");
  voteRow.className = "vote-row";
  voteRow.append(makeVoteButton(report.id, "confirm", "Still useful"), makeVoteButton(report.id, "deny", "No longer accurate"));
  card.append(heading, date, confidence, voteRow);
  return card;
}

function makeVoteButton(reportId, vote, label) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const proof = await challengeProof();
      await requestJson(`/api/reports/${reportId}/votes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ vote, ...proof })
      });
      await refreshReports();
    } catch (error) {
      button.disabled = false;
      status(reportStatus, error.message, "error");
    }
  });
  return button;
}

async function refreshReports() {
  const result = await requestJson("/api/reports");
  renderReports(result.reports);
}

async function initialize() {
  try {
    startMap();
    await requestJson("/api/device");
    deviceReady = true;
    config = await requestJson("/api/config");
    for (const category of config.categories) {
      const option = document.createElement("option");
      option.value = category;
      option.textContent = CATEGORY_LABELS[category];
      categoryInput.append(option);
    }
    categoryInput.addEventListener("change", updateActivityControls);
    updateActivityControls();
    if (config.activityReportsEnabled) activityPanel.classList.remove("hidden");
    await refreshReports();
    document.querySelector("#refresh").addEventListener("click", () => refreshReports().catch(error => status(reportStatus, error.message, "error")));
    document.querySelector("#activity-toggle").addEventListener("click", toggleActivityAlerts);
    form.addEventListener("submit", submitReport);
    if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});
  } catch (error) {
    status(reportStatus, error.message, "error");
    reportList.textContent = "Reports are temporarily unavailable.";
  }
}

async function submitReport(event) {
  event.preventDefault();
  if (!deviceReady) return status(reportStatus, "Device token is not ready. Reload the page and try again.", "error");
  if (categoryInput.value === "activity" && !activityOptIn.checked) {
    return status(reportStatus, "Confirm the activity opt-in before sending a time-sensitive report.", "error");
  }
  submitButton.disabled = true;
  try {
    const proof = await challengeProof();
    const result = await requestJson("/api/reports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        category: categoryInput.value,
        latitude: Number(latitudeInput.value),
        longitude: Number(longitudeInput.value),
        confidence: Number(confidenceInput.value),
        submissionId: crypto.randomUUID(),
        activityOptIn: categoryInput.value === "activity" && activityOptIn.checked,
        ...proof
      })
    });
    status(reportStatus, `Report accepted. It is approximate and expires ${result.report.expiresDay}.`, "success");
    form.reset();
    confidenceInput.value = "2";
    updateActivityControls();
    await refreshReports();
  } catch (error) {
    status(reportStatus, error.message, "error");
  } finally {
    submitButton.disabled = false;
  }
}

async function toggleActivityAlerts() {
  if (!config.activityReportsEnabled) return;
  const button = document.querySelector("#activity-toggle");
  const isEnabled = button.dataset.enabled === "true";
  const point = pendingCoordinates;
  if (!isEnabled && !point) return status(activityStatus, "Choose an approximate alert area by clicking the map first.", "error");
  button.disabled = true;
  try {
    const proof = await challengeProof();
    await requestJson("/api/alerts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        enabled: !isEnabled,
        ...(isEnabled ? {} : {
          latitude: point.latitude,
          longitude: point.longitude,
          radiusMeters: Number(document.querySelector("#activity-radius").value)
        }),
        ...proof
      })
    });
    button.dataset.enabled = String(!isEnabled);
    button.textContent = isEnabled ? "Enable activity view" : "Disable activity view";
    status(activityStatus, isEnabled ? "Activity view disabled." : "Activity view enabled for this browser for up to one day.", "success");
    await refreshReports();
  } catch (error) {
    status(activityStatus, error.message, "error");
  } finally {
    button.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", initialize);
