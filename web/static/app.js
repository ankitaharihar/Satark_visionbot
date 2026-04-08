const form = document.getElementById("scan-form");
const input = document.getElementById("url-input");
const statusNode = document.getElementById("status");
const resultCard = document.getElementById("result-card");
const badge = document.getElementById("badge");
const score = document.getElementById("score");
const domain = document.getElementById("domain");
const reasons = document.getElementById("reasons");
const ai = document.getElementById("ai");
const intel = document.getElementById("intel");
const btn = document.getElementById("scan-btn");

function setStatus(text, isError = false) {
  statusNode.textContent = text;
  statusNode.style.color = isError ? "#dc2626" : "#375a71";
}

function addItems(node, items) {
  node.innerHTML = "";
  const list = items && items.length ? items : ["No details available"];
  for (const item of list) {
    const li = document.createElement("li");
    li.textContent = String(item);
    node.appendChild(li);
  }
}

function setBadge(verdict) {
  const normalized = String(verdict || "SAFE").toLowerCase();
  badge.textContent = String(verdict || "SAFE");
  badge.className = "badge";
  if (normalized === "phishing") badge.classList.add("phishing");
  else if (normalized === "suspicious") badge.classList.add("suspicious");
  else badge.classList.add("safe");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = input.value.trim();
  if (!url) return;

  btn.disabled = true;
  setStatus("Scanning URL...");

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const payload = await res.json();

    if (!res.ok || !payload.ok) {
      throw new Error(payload.error || "Unable to analyze URL");
    }

    const data = payload.data || {};
    const model = data.model_result || {};
    const ti = data.threat_intel || {};

    setBadge(data.final_verdict);
    score.textContent = `Risk: ${data.final_score || 0}%`;
    domain.textContent = `Domain: ${data.domain || "Unknown"}`;

    addItems(reasons, model.reasons || []);
    addItems(ai, [
      `BERT: ${model.ai_label || "N/A"} (${model.ai_confidence ?? "N/A"})`,
      `Zero-shot: ${model.llm_label || "N/A"} (${model.llm_confidence ?? "N/A"})`,
    ]);
    addItems(intel, [
      `Malicious: ${ti.is_malicious ? "Yes" : "No"}`,
      `Sources: ${(ti.sources && ti.sources.length) ? ti.sources.join(", ") : "None"}`,
      `Intel Score: +${ti.risk_score || 0}`,
    ]);

    resultCard.classList.remove("hidden");
    setStatus("Done.");
  } catch (error) {
    setStatus(error.message || "Request failed", true);
  } finally {
    btn.disabled = false;
  }
});
