let findings = [];
const $ = id => document.getElementById(id);

async function post(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return r;
}
async function postJson(url, body) {
  const r = await post(url, body);
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || "Request failed");
  return data;
}
function setStatus(id, msg, isError) { const el = $(id); el.textContent = msg; el.classList.toggle("error", !!isError); }

// Always use textContent so scan or API data can never inject HTML.
function renderFindings() {
  const body = $("findings-body"); body.innerHTML = "";
  findings.forEach(f => {
    const tr = document.createElement("tr");
    ["source", "item", "detail", "score"].forEach(k => { const td = document.createElement("td"); td.textContent = f[k] ?? ""; tr.appendChild(td); });
    const sev = document.createElement("td"); sev.textContent = f.severity; sev.className = "sev " + f.severity; tr.appendChild(sev);
    body.appendChild(tr);
  });
  $("empty").style.display = findings.length ? "none" : "block";
}

$("cve-btn").onclick = async () => {
  const btn = $("cve-btn"); btn.disabled = true; setStatus("cve-status", "Querying NVD. This can take several seconds...");
  try {
    const { results } = await postJson("/api/cve", { software: $("software").value, version: $("version").value });
    results.forEach(c => findings.push({ source: "NVD", item: c.id, detail: c.description, score: c.score ?? "n/a", severity: c.severity }));
    setStatus("cve-status", results.length ? `${results.length} CVEs added (keyword match, may include false positives).` : "No CVEs found for that search.");
    renderFindings();
  } catch (e) { setStatus("cve-status", e.message, true); }
  btn.disabled = false;
};

$("scan-btn").onclick = async () => {
  const btn = $("scan-btn"); btn.disabled = true; setStatus("scan-status", "Scanning. This can take up to a few minutes...");
  const out = $("scan-results"); out.innerHTML = "";
  try {
    const { hosts } = await postJson("/api/scan", { target: $("target").value, authorized: $("authorized").checked });
    setStatus("scan-status", `${hosts.length} host(s) up.`);
    hosts.forEach(h => {
      const box = document.createElement("div"); box.className = "host";
      const title = document.createElement("strong"); title.textContent = h.address; box.appendChild(title);
      h.ports.forEach(p => {
        findings.push({ source: "nmap", item: `${h.address}:${p.port}/${p.protocol}`,
          detail: `Open port. Service: ${p.service} ${p.product} ${p.version}`.trim(), score: "n/a", severity: "Unknown" });
        const line = document.createElement("div");
        line.textContent = `${p.port}/${p.protocol} ${p.service} ${p.product} ${p.version}`;
        if (p.product) {
          const b = document.createElement("button"); b.textContent = "Fill lookup";
          b.onclick = () => { $("software").value = p.product; $("version").value = p.version; window.scrollTo({ top: 0, behavior: "smooth" }); };
          line.appendChild(b);
        }
        box.appendChild(line);
      });
      out.appendChild(box);
    });
    renderFindings();
  } catch (e) { setStatus("scan-status", e.message, true); }
  btn.disabled = false;
};

async function download(kind) {
  if (!findings.length) return alert("Add some findings first.");
  const r = await post("/api/report/" + kind, { findings });
  const blob = await r.blob(); const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = "security_report." + kind; a.click(); URL.revokeObjectURL(a.href);
}
$("csv-btn").onclick = () => download("csv");
$("pdf-btn").onclick = () => download("pdf");
$("clear-btn").onclick = () => { findings = []; renderFindings(); };
renderFindings();
