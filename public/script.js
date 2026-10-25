const form = document.getElementById("form");
const out = document.getElementById("output");
const btn = document.getElementById("run");
const toolSel = document.getElementById("tool");
const portsRow = document.getElementById("portsRow");

toolSel.addEventListener("change", () => {
  portsRow.classList.toggle("hidden", toolSel.value !== "scan");
});

function line(text, cls) {
  const span = document.createElement("span");
  if (cls) span.className = cls;
  span.textContent = text + "\n";
  out.appendChild(span);
  out.scrollTop = out.scrollHeight;
}

function render(tool, d) {
  if (d.error) return line("[ERROR] " + d.error, "err");

  if (tool === "scan") {
    line(`[+] Target   : ${d.target} (${d.ip})`, "info");
    line(`[+] Scanned  : ${d.scanned} port dalam ${d.duration}s`, "info");
    if (!d.open.length) return line("[-] Tidak ada port terbuka.", "err");
    line("\nPORT      STATE   SERVICE");
    d.open.forEach(p =>
      line(`${String(p.port).padEnd(9)} ${p.state.padEnd(7)} ${p.service}`, "ok"));
  } else if (tool === "headers") {
    line(`[+] URL    : ${d.url}`, "info");
    line(`[+] Status : ${d.status}`, "info");
    line(`[+] Score  : ${d.security_score}\n`, "info");
    d.security_checks.forEach(c =>
      line(`${c.present ? "[ OK ]" : "[MISS]"} ${c.header}${c.value ? " : " + c.value : ""}`,
           c.present ? "ok" : "err"));
    line("\n--- ALL HEADERS ---", "info");
    Object.entries(d.all_headers).forEach(([k, v]) => line(`${k}: ${v}`));
  } else if (tool === "whois_lookup") {
    line(`[+] Whois: ${d.domain}\n`, "info");
    Object.entries(d.data).forEach(([k, v]) =>
      line(`${k}: ${Array.isArray(v) ? v.join(", ") : v}`, "ok"));
  } else if (tool === "dns_lookup") {
    line(`[+] Host : ${d.host}`, "info");
    d.ipv4.forEach(ip => line(`A     : ${ip}`, "ok"));
    d.ipv6.forEach(ip => line(`AAAA  : ${ip}`, "ok"));
    if (d.reverse_dns) line(`PTR   : ${d.reverse_dns}`, "ok");
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const tool = toolSel.value;
  const target = document.getElementById("target").value.trim();
  const ports = document.getElementById("ports").value.trim();

  const params = new URLSearchParams({ target });
  if (tool === "scan" && ports) params.set("ports", ports);

  out.textContent = "";
  line(`$ ${tool} ${target}`, "info");
  line("[*] Menjalankan, tunggu...");
  btn.disabled = true;
  btn.textContent = "⏳ RUNNING...";

  try {
    const res = await fetch(`/api/${tool}?${params}`);
    const data = await res.json();
    render(tool, data);
  } catch (err) {
    line("[ERROR] Gagal menghubungi server: " + err.message, "err");
  } finally {
    btn.disabled = false;
    btn.textContent = "▶ EXECUTE";
  }
});
