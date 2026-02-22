function showError(message) {
  const errorDiv = document.getElementById("error");
  if (errorDiv) errorDiv.innerText = message;
}

async function signup() {
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;

  const errorDiv = document.getElementById("error");
  errorDiv.innerText = "";

  // Client-side validation
  if (password.length < 10) {
    errorDiv.innerText = "Password must be at least 10 characters long.";
    return;
  }

  try {
    const res = await fetch("/auth/signup", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (!res.ok) {
      // Handle FastAPI validation errors
      if (Array.isArray(data.detail)) {
        errorDiv.innerText = data.detail.map(e => e.msg).join(", ");
      } else {
        errorDiv.innerText = data.detail || "Signup failed.";
      }
      return;
    }

    alert("Account created successfully!");
    window.location.href = "/login.html";

  } catch (err) {
    errorDiv.innerText = "Network error. Please try again.";
  }
}

async function login() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  try {
    const res = await fetch("/auth/login", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ email, password })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Login failed");
    }

    const data = await res.json();
    localStorage.setItem("access_token", data.access_token);

    window.location.href = "/dashboard.html";
  } catch (err) {
    showError(err.message);
  }
}

function logout() {
  localStorage.removeItem("access_token");
  window.location.href = "/";
}


async function loadMe() {
  const token = localStorage.getItem("access_token");
  if (!token) {
    window.location.href = "/login.html";
    return;
  }

  try {
    const res = await fetch("/api/me", {
      headers: { "Authorization": "Bearer " + token }
    });

    if (!res.ok) throw new Error("Unauthorized");

    const me = await res.json();
    document.getElementById("whoami").innerText =
      `User ID: ${me.user_id} | Role: ${me.role}`;
  } catch (e) {
    localStorage.removeItem("access_token");
    window.location.href = "/login.html";
  }
}


function fmtIso(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch {
    return iso;
  }
}

function severityClass(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  return "low";
}

async function loadAlerts() {
  const status = document.getElementById("status");
  const table = document.getElementById("alertsTable");
  const body = document.getElementById("alertsBody");

  if (!status || !table || !body) return;

  try {
    const res = await fetch("/log/alerts");
    if (!res.ok) throw new Error("Failed to load alerts");

    const alerts = await res.json();

    if (!Array.isArray(alerts) || alerts.length === 0) {
      status.innerText = "No alerts.";
      table.style.display = "none";
      body.innerHTML = "";
      return;
    }

    status.innerText = `Showing latest ${alerts.length} alert(s).`;
    table.style.display = "table";

    body.innerHTML = alerts.map(a => `
      <tr>
        <td class="mono nowrap">${a.id}</td>
        <td class="mono">${a.rule}</td>
        <td><span class="pill ${severityClass(a.severity)}">${a.severity}</span></td>
        <td class="mono nowrap">${a.ip}</td>
        <td class="mono nowrap">${a.count} / ${a.threshold}</td>
        <td class="mono nowrap">${a.window_seconds}s</td>
        <td class="nowrap">${fmtIso(a.first_seen)}</td>
        <td class="nowrap">${fmtIso(a.last_seen)}</td>
        <td class="nowrap">${fmtIso(a.created_at)}</td>

        <!-- Status -->
        <td class="mono nowrap status-col">${a.status}</td>

        <!-- Actions -->
        <td class="actions-col">
          ${
            a.status === "open"
              ? `
                <button class="btn-secondary" onclick="ackAlert(${a.id})">Ack</button>
                <button class="btn-secondary" onclick="closeAlert(${a.id})">Close</button>
              `
              : a.status === "acknowledged"
              ? `
                <button class="btn-secondary" onclick="closeAlert(${a.id})">Close</button>
                <button class="btn-secondary" onclick="reopenAlert(${a.id})">Reopen</button>
              `
              : `
                <button class="btn-secondary" onclick="reopenAlert(${a.id})">Reopen</button>
              `
          }
        </td>

        <td class="mono small meta-col">${a.meta ? JSON.stringify(a.meta) : "{}"}</td>
      </tr>
    `).join("");

  } catch (e) {
    status.innerText = "Error loading alerts. Check /log/alerts and log-service.";
    table.style.display = "none";
    body.innerHTML = "";
  }
}

function refreshAlerts() {
  loadAlerts();
}


function getActor() {
  let actor = localStorage.getItem("actor");
  if (!actor) {
    actor = prompt("Analyst name (for alert actions):", "web-ui") || "web-ui";
    localStorage.setItem("actor", actor);
  }
  return actor;
}

async function patchAlert(id, action) {
  const actor = getActor();
  const res = await fetch(`/log/alerts/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, actor })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Failed to update alert");
  }
  return res.json();
}

async function ackAlert(id) {
  try { 
    await patchAlert(id, "ack"); 
    await loadAlerts(); 
  } catch (e) { 
    alert(e.message); 
  }
}

async function closeAlert(id) {
  try { 
    await patchAlert(id, "close"); 
    await loadAlerts(); 
  } catch (e) { 
    alert(e.message); 
  }
}

async function reopenAlert(id) {
  try { 
    await patchAlert(id, "reopen"); 
    await loadAlerts(); 
  } catch (e) { 
    alert(e.message); 
  }
}
