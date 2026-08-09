const state = { config: null, services: [], scan: null };
const $ = (selector) => document.querySelector(selector);

function applyTheme(theme, persist = true) {
  const selected = theme === "light" ? "light" : "tech";
  document.documentElement.dataset.theme = selected;
  document.querySelectorAll("[data-theme-option]").forEach((button) => {
    const active = button.dataset.themeOption === selected;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  if (persist) localStorage.setItem("findai-theme", selected);
}

function accessKey() { return localStorage.getItem("findai-key") || ""; }
function headers(extra = {}) {
  const key = accessKey();
  return { "Content-Type": "application/json", ...(key ? { "X-FindAI-Key": key } : {}), ...extra };
}
async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: headers(options.headers || {}) });
  let payload = null;
  try { payload = await response.json(); } catch (_) { payload = {}; }
  if (!response.ok) {
    const message = payload.detail || payload?.error?.message || `HTTP ${response.status}`;
    throw new Error(response.status === 401 ? "需要正确的 FindAI 访问密钥" : message);
  }
  return payload;
}
function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[char]));
}
function notify(message, error = false) {
  const node = $("#notice");
  node.textContent = message;
  node.className = `notice${error ? " error" : ""}`;
  window.setTimeout(() => node.classList.add("hidden"), 5000);
}
function parsePorts(value) {
  const result = new Set();
  value.split(",").map((item) => item.trim()).filter(Boolean).forEach((item) => {
    if (item.includes("-")) {
      const [start, end] = item.split("-", 2).map(Number);
      if (!Number.isInteger(start) || !Number.isInteger(end) || start > end || end - start > 1000) throw new Error(`无效端口范围：${item}`);
      for (let port = start; port <= end; port += 1) result.add(port);
    } else {
      const port = Number(item);
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`无效端口：${item}`);
      result.add(port);
    }
  });
  return [...result].sort((a, b) => a - b);
}
async function copyText(value) {
  await navigator.clipboard.writeText(value);
  notify("已复制到剪贴板");
}

function renderScan(scan) {
  const previousStatus = state.scan?.status;
  state.scan = scan;
  const progress = scan.progress || 0;
  $("#metric-progress").textContent = `${progress}%`;
  $("#scan-progress-bar").style.width = `${progress}%`;
  $("#scan-count").textContent = `${scan.scanned || 0} / ${scan.total || 0}`;
  $("#open-count").textContent = scan.open_ports || 0;
  $("#found-count").textContent = scan.discovered || 0;
  $("#scan-caption").textContent = scan.status === "running" ? "正在探测" : scan.status === "completed" ? "最近一次完成" : "等待扫描";
  const pill = $("#scan-status");
  const labels = { idle: "空闲", running: "扫描中", completed: "已完成", failed: "失败", cancelled: "已取消" };
  pill.textContent = labels[scan.status] || scan.status;
  pill.className = `status-pill ${scan.status}`;
  $("#start-scan").disabled = scan.status === "running";

  const feedback = $("#scan-feedback");
  const feedbackIcon = $("#scan-feedback-icon");
  const feedbackTitle = $("#scan-feedback-title");
  const feedbackText = $("#scan-feedback-text");
  if (scan.status === "running" || scan.status === "idle") {
    feedback.className = "scan-feedback hidden";
  } else if (scan.status === "completed") {
    const found = scan.discovered || 0;
    feedback.className = `scan-feedback${found ? "" : " empty"}`;
    feedbackIcon.textContent = found ? "✓" : "i";
    feedbackTitle.textContent = found ? `扫描完成，发现 ${found} 个模型服务` : "扫描完成，未发现兼容服务";
    feedbackText.textContent = `共检查 ${scan.scanned || 0} 个目标，发现 ${scan.open_ports || 0} 个开放端口。${found ? "结果已更新到下方列表。" : "可检查端口、网段或服务鉴权配置。"}`;
    if (previousStatus === "running") {
      notify(found ? `扫描完成：发现 ${found} 个模型服务` : "扫描完成：未发现兼容模型服务");
      const results = $(".services-section");
      results.classList.add("result-highlight");
      window.setTimeout(() => results.classList.remove("result-highlight"), 3500);
    }
  } else if (scan.status === "failed") {
    feedback.className = "scan-feedback error";
    feedbackIcon.textContent = "!";
    feedbackTitle.textContent = "扫描失败";
    feedbackText.textContent = scan.error || "请查看后台日志获取具体原因。";
    if (previousStatus === "running") notify(`扫描失败：${feedbackText.textContent}`, true);
  } else {
    feedback.className = "scan-feedback empty";
    feedbackIcon.textContent = "i";
    feedbackTitle.textContent = "扫描已取消";
    feedbackText.textContent = "本次扫描没有完整执行。";
  }
}

function renderServices(services) {
  state.services = services;
  const online = services.filter((item) => item.status === "online");
  const modelCount = online.reduce((count, item) => count + item.models.length, 0);
  $("#metric-services").textContent = services.length;
  $("#metric-models").textContent = modelCount;
  $("#metric-online").textContent = services.length ? `${Math.round(online.length / services.length * 100)}%` : "—";
  if (!services.length) {
    $("#services").innerHTML = '<div class="empty-state"><span class="empty-radar"></span><h3>还没有发现模型服务</h3><p>配置网段后开始扫描，或手工添加一个已知地址。</p></div>';
    return;
  }
  $("#services").innerHTML = services.map((service) => {
    const models = service.routed_models.length
      ? service.routed_models.map((model) => `<span class="model-chip" title="${escapeHtml(model)}">${escapeHtml(model)}<button data-copy="${escapeHtml(model)}">复制</button></span>`).join("")
      : `<span class="model-chip">${service.auth_required ? "需要 API Key 后读取模型" : "未上报模型"}</span>`;
    const latency = service.latency_ms == null ? "—" : `${Math.round(service.latency_ms)} ms`;
    return `<article class="service-card">
      <div class="service-main"><span class="node-icon"></span><div><h3>${escapeHtml(service.name)}</h3><code>${escapeHtml(service.base_url)}</code></div></div>
      <div class="service-meta"><span>状态 / 协议</span><strong><i class="${service.status === "online" ? "online-dot" : "offline-dot"}"></i>${service.status === "online" ? "在线" : "离线"} · ${escapeHtml(service.api_kind)}</strong></div>
      <div class="model-summary"><span>模型 / 延迟</span><strong>${service.models.length} 个 · ${latency}</strong></div>
      <div class="card-actions">
        ${service.auth_required || !service.credential_loaded ? `<button class="button ghost" data-credential="${service.id}">密钥</button>` : ""}
        <button class="button ghost" data-probe="${service.id}">复检</button>
      </div>
      <div class="models-detail">${models}</div>
    </article>`;
  }).join("");
}

async function refreshAll() {
  try {
    const [config, services, scan] = await Promise.all([api("/api/config"), api("/api/services"), api("/api/scan")]);
    state.config = config;
    $("#gateway-url").textContent = config.gateway_base_url;
    if (!$("#scan-cidrs").value) $("#scan-cidrs").value = config.scan_cidrs.join(",");
    if (!$("#scan-ports").value) $("#scan-ports").value = config.scan_ports.join(",");
    renderServices(services.data);
    renderScan(scan);
  } catch (error) { notify(error.message, true); }
}

$("#save-key").addEventListener("click", () => {
  localStorage.setItem("findai-key", $("#gateway-key").value.trim());
  refreshAll();
});
document.querySelectorAll("[data-theme-option]").forEach((button) => {
  button.addEventListener("click", () => applyTheme(button.dataset.themeOption));
});
applyTheme(document.documentElement.dataset.theme, false);
$("#gateway-key").value = accessKey();
$("#start-scan").addEventListener("click", async () => {
  try {
    const cidrs = $("#scan-cidrs").value.split(",").map((item) => item.trim()).filter(Boolean);
    const ports = parsePorts($("#scan-ports").value);
    renderScan(await api("/api/scan", { method: "POST", body: JSON.stringify({ cidrs, ports, schemes: ["http"] }) }));
  } catch (error) { notify(error.message, true); }
});
$("#add-manual").addEventListener("click", async () => {
  try {
    const base_url = $("#manual-url").value.trim();
    if (!base_url) throw new Error("请填写服务根地址");
    const api_key = $("#manual-key").value.trim() || null;
    await api("/api/services/manual", { method: "POST", body: JSON.stringify({ base_url, api_key }) });
    $("#manual-key").value = "";
    notify("服务已验证并加入注册表");
    await refreshAll();
  } catch (error) { notify(error.message, true); }
});
$("#refresh").addEventListener("click", refreshAll);
document.addEventListener("click", async (event) => {
  const copyTarget = event.target.closest("[data-copy-target]");
  const copyValue = event.target.closest("[data-copy]");
  const probe = event.target.closest("[data-probe]");
  const credential = event.target.closest("[data-credential]");
  try {
    if (copyTarget) await copyText($(`#${copyTarget.dataset.copyTarget}`).textContent);
    if (copyValue) await copyText(copyValue.dataset.copy);
    if (probe) {
      await api(`/api/services/${probe.dataset.probe}/probe`, { method: "POST", body: "{}" });
      notify("节点复检完成"); await refreshAll();
    }
    if (credential) {
      const apiKey = window.prompt("输入该上游服务的 API Key。密钥只保存在本进程内存中：");
      if (apiKey) {
        await api(`/api/services/${credential.dataset.credential}/credential`, { method: "PUT", body: JSON.stringify({ api_key: apiKey }) });
        notify("密钥已加载，模型清单已刷新"); await refreshAll();
      }
    }
  } catch (error) { notify(error.message, true); }
});

refreshAll();
window.setInterval(async () => {
  try {
    const wasRunning = state.scan?.status === "running";
    const scan = await api("/api/scan");
    renderScan(scan);
    if (scan.status === "running" || wasRunning) {
      const services = await api("/api/services");
      renderServices(services.data);
    }
  } catch (_) { /* keep the dashboard quiet between explicit retries */ }
}, 1800);
