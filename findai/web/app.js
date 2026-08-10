const state = {
  config: null,
  services: [],
  scan: null,
};
const $ = (selector) => document.querySelector(selector);
let noticeTimer = null;
let scanPollTimer = null;
let pollBusy = false;
const serviceReveal = {
  visibleIds: new Set(),
  queuedIds: new Set(),
  queue: [],
  timer: null,
};
const prefersReducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches || false;

function emptyScanState() {
  return {
    status: "idle",
    cidrs: [],
    ports: [],
    total: 0,
    scanned: 0,
    open_ports: 0,
    discovered: 0,
    progress: 0,
    logs: [],
  };
}

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

const ACCESS_KEYS_STORAGE = "findai-access-keys";
const ACTIVE_ACCESS_KEY_STORAGE = "findai-active-key";
const LEGACY_ACCESS_KEY_STORAGE = "findai-key";

function createAccessKeyId() {
  return `key-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function loadAccessKeyring() {
  const keys = [];
  let legacyKey = "";
  let storedActiveId = null;
  try {
    const parsed = JSON.parse(localStorage.getItem(ACCESS_KEYS_STORAGE) || "[]");
    if (Array.isArray(parsed)) {
      parsed.forEach((item, index) => {
        if (!item || typeof item.value !== "string" || !item.value.trim()) return;
        const rawId = typeof item.id === "string" ? item.id : "";
        keys.push({
          id: /^[a-zA-Z0-9_-]{1,80}$/.test(rawId) ? rawId : createAccessKeyId(),
          name: typeof item.name === "string" && item.name.trim() ? item.name.trim().slice(0, 60) : `密钥 ${index + 1}`,
          value: item.value.trim().slice(0, 4096),
        });
      });
    }
    legacyKey = (localStorage.getItem(LEGACY_ACCESS_KEY_STORAGE) || "").trim();
    storedActiveId = localStorage.getItem(ACTIVE_ACCESS_KEY_STORAGE);
  } catch (_) {}

  if (!keys.length && legacyKey) {
    keys.push({ id: "legacy", name: "原有密钥", value: legacyKey.slice(0, 4096) });
  }
  let activeId = "";
  if (storedActiveId === null) {
    activeId = keys.find((item) => item.value === legacyKey)?.id || keys[0]?.id || "";
  } else if (keys.some((item) => item.id === storedActiveId)) {
    activeId = storedActiveId;
  }
  return { keys, activeId };
}

const initialKeyring = loadAccessKeyring();
let accessKeys = initialKeyring.keys;
let activeAccessKeyId = initialKeyring.activeId;

function activeAccessKey() {
  return accessKeys.find((item) => item.id === activeAccessKeyId) || null;
}

function accessKey() {
  return activeAccessKey()?.value || "";
}

function persistAccessKeyring() {
  localStorage.setItem(ACCESS_KEYS_STORAGE, JSON.stringify(accessKeys));
  localStorage.setItem(ACTIVE_ACCESS_KEY_STORAGE, activeAccessKeyId);
  const current = accessKey();
  if (current) localStorage.setItem(LEGACY_ACCESS_KEY_STORAGE, current);
  else localStorage.removeItem(LEGACY_ACCESS_KEY_STORAGE);
}

function maskAccessKey(value) {
  const suffix = value.slice(-4);
  return `${"•".repeat(Math.min(8, Math.max(4, value.length - suffix.length)))}${suffix}`;
}

function updateKeyIndicator() {
  const button = $("#open-key");
  if (!button) return;
  const current = activeAccessKey();
  button.classList.toggle("has-key", Boolean(current));
  button.title = current ? `常用密钥：${current.name}（FindAI 使用中）` : "常用密钥";
}

function renderAccessKeys() {
  const list = $("#saved-keys");
  if (!list) return;
  if (!accessKeys.length) {
    list.innerHTML = '<div class="key-empty">尚未保存常用密钥。保存后既可用于 FindAI 访问，也可为上游模型服务快速填充。</div>';
  } else {
    list.innerHTML = accessKeys.map((item) => {
      const active = item.id === activeAccessKeyId;
      return `<div class="key-item${active ? " active" : ""}">
        <div class="key-item-copy"><strong>${escapeHtml(item.name)}</strong><code>${escapeHtml(maskAccessKey(item.value))}</code></div>
        <div class="key-item-actions">
          ${active ? '<span class="key-active">FindAI 使用中</span>' : `<button class="button ghost" type="button" data-use-key="${escapeHtml(item.id)}">用于 FindAI</button>`}
          <button class="button danger-ghost" type="button" data-delete-key="${escapeHtml(item.id)}">删除</button>
        </div>
      </div>`;
    }).join("");
  }
  $("#clear-active-key").disabled = !activeAccessKey();
  updateKeyIndicator();
  renderCredentialKeyOptions();
}

function renderCredentialKeyOptions() {
  const select = $("#credential-saved-key");
  if (!select) return;
  const previous = select.value;
  const prompt = accessKeys.length ? "手工输入上游密钥" : "暂无常用密钥，请手工输入";
  select.innerHTML = `<option value="">${prompt}</option>${accessKeys.map((item) => (
    `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name)} · ${escapeHtml(maskAccessKey(item.value))}</option>`
  )).join("")}`;
  select.disabled = !accessKeys.length;
  if (accessKeys.some((item) => item.id === previous)) select.value = previous;
}

function headers(extra = {}) {
  const key = accessKey();
  return { "Content-Type": "application/json", ...(key ? { "X-FindAI-Key": key } : {}), ...extra };
}
async function api(path, options = {}) {
  const response = await fetch(path, {
    cache: "no-store",
    ...options,
    headers: headers(options.headers || {}),
  });
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
  if (typeof node.showPopover === "function" && !node.matches(":popover-open")) {
    node.showPopover();
  }
  if (noticeTimer) window.clearTimeout(noticeTimer);
  noticeTimer = window.setTimeout(() => {
    if (typeof node.hidePopover === "function" && node.matches(":popover-open")) {
      node.hidePopover();
    }
    node.classList.add("hidden");
  }, 5000);
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
function normalizeCidrs(value) {
  return value.split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => item.includes("/") ? item : `${item}/32`);
}
async function copyText(value) {
  await navigator.clipboard.writeText(value);
  notify("已复制到剪贴板");
}

const scanTimeFormatter = new Intl.DateTimeFormat("zh-CN", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

function renderScanEvents(logs = []) {
  const compactNode = $("#scan-events");
  const fullNode = $("#scan-log-dialog-events");
  $("#scan-log-count").textContent = logs.length > 99 ? "99+" : String(logs.length);
  if (!logs.length) {
    compactNode.innerHTML = '<li class="muted"><span>开始扫描后，这里显示最新一条日志。</span></li>';
    fullNode.innerHTML = '<li class="muted"><span>开始扫描后，这里会实时显示本次扫描的完整日志。</span></li>';
    return;
  }
  const latest = logs[logs.length - 1];
  compactNode.innerHTML = `<li class="${escapeHtml(latest.level || "info")}" title="${escapeHtml(latest.message || "")}"><time>${escapeHtml(scanTimeFormatter.format(new Date((latest.timestamp || 0) * 1000)))}</time><span>${escapeHtml(latest.message || "")}</span></li>`;
  fullNode.innerHTML = logs.slice().reverse().map((entry) => (
    `<li class="${escapeHtml(entry.level || "info")}"><time>${escapeHtml(scanTimeFormatter.format(new Date((entry.timestamp || 0) * 1000)))}</time><span>${escapeHtml(entry.message || "")}</span></li>`
  )).join("");
}

function renderScan(scan) {
  const previousScan = state.scan;
  const previousStatus = previousScan?.status;
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
  $("#clear-services").disabled = scan.status === "running";
  renderScanEvents(scan.logs || []);

  const scanned = scan.scanned || 0;
  const total = scan.total || 0;
  if (scan.status === "running") {
    $("#scan-live-summary").textContent = `已检查 ${scanned}/${total} · 开放 ${scan.open_ports || 0} · 服务 ${scan.discovered || 0}`;
  } else if (scan.status === "completed") {
    $("#scan-live-summary").textContent = `扫描完成 · 检查 ${scanned} · 发现服务 ${scan.discovered || 0}`;
  } else if (scan.status === "failed") {
    $("#scan-live-summary").textContent = "扫描失败";
  } else if (scan.status === "cancelled") {
    $("#scan-live-summary").textContent = "扫描已取消";
  } else {
    $("#scan-live-summary").textContent = "尚未开始扫描";
  }
  $("#scan-log-dialog-summary").textContent = $("#scan-live-summary").textContent;

  if (scan.status === "completed" && previousStatus === "running") {
    const found = scan.discovered || 0;
    notify(found ? `扫描完成：发现 ${found} 个模型服务` : "扫描完成：未发现兼容模型服务");
    const results = $(".services-section");
    results.classList.add("result-highlight");
    window.setTimeout(() => results.classList.remove("result-highlight"), 3500);
  } else if (scan.status === "failed" && previousStatus === "running") {
    notify(`扫描失败：${scan.error || "请查看完整扫描日志"}`, true);
  } else if (scan.status === "cancelled" && previousStatus === "running") {
    notify("扫描已取消", true);
  }
}

function renderServiceMetrics(services) {
  const online = services.filter((item) => item.status === "online");
  const modelCount = online.reduce((count, item) => count + item.models.length, 0);
  $("#metric-services").textContent = services.length;
  $("#metric-models").textContent = modelCount;
  $("#metric-online").textContent = services.length ? `${Math.round(online.length / services.length * 100)}%` : "—";
}

function renderServiceCards(services, enteringId = "") {
  if (!services.length) {
    $("#services").innerHTML = '<div class="empty-state"><span class="empty-radar"></span><h3>还没有发现模型服务</h3><p>配置网段后开始扫描，或手工添加一个已知地址。</p></div>';
    return;
  }
  $("#services").innerHTML = services.map((service) => {
    const models = service.routed_models.length
      ? service.routed_models.map((model) => `<span class="model-chip" title="${escapeHtml(model)}">${escapeHtml(model)}<button data-copy="${escapeHtml(model)}">复制</button></span>`).join("")
      : `<span class="model-chip">${service.auth_required ? "需要 API Key 后读取模型" : "未上报模型"}</span>`;
    const latency = service.latency_ms == null ? "—" : `${Math.round(service.latency_ms)} ms`;
    return `<article class="service-card${service.id === enteringId ? " entering" : ""}">
      <div class="service-main"><span class="node-icon"></span><div><h3>${escapeHtml(service.name)}</h3><code>${escapeHtml(service.base_url)}</code></div></div>
      <div class="service-meta"><span>状态 / 协议</span><strong><i class="${service.status === "online" ? "online-dot" : "offline-dot"}"></i>${service.status === "online" ? "在线" : "离线"} · ${escapeHtml(service.api_kind)}</strong></div>
      <div class="model-summary"><span>模型 / 延迟</span><strong>${service.models.length} 个 · ${latency}</strong></div>
      <div class="card-actions">
        <button class="button ghost" data-credential="${service.id}">${service.credential_loaded ? "更换密钥" : "密钥"}</button>
        <button class="button ghost" data-probe="${service.id}">复检</button>
      </div>
      <div class="models-detail">${models}</div>
    </article>`;
  }).join("");
}

function stopServiceReveal(clearQueue = false) {
  if (serviceReveal.timer) window.clearTimeout(serviceReveal.timer);
  serviceReveal.timer = null;
  if (clearQueue) {
    serviceReveal.queue = [];
    serviceReveal.queuedIds.clear();
  }
}

function serviceRevealDelay() {
  if (serviceReveal.queue.length > 24) return 70;
  if (serviceReveal.queue.length > 12) return 90;
  if (serviceReveal.queue.length > 5) return 120;
  return 170;
}

function revealNextService() {
  serviceReveal.timer = null;
  let serviceId = "";
  while (serviceReveal.queue.length && !serviceId) {
    const candidate = serviceReveal.queue.shift();
    serviceReveal.queuedIds.delete(candidate);
    if (state.services.some((service) => service.id === candidate)) serviceId = candidate;
  }
  if (!serviceId) return;
  serviceReveal.visibleIds.add(serviceId);
  renderServiceCards(
    state.services.filter((service) => serviceReveal.visibleIds.has(service.id)),
    serviceId,
  );
  if (serviceReveal.queue.length) {
    serviceReveal.timer = window.setTimeout(revealNextService, serviceRevealDelay());
  }
}

function renderServices(services, { animateNew = false } = {}) {
  state.services = services;
  renderServiceMetrics(services);
  const availableIds = new Set(services.map((service) => service.id));
  serviceReveal.visibleIds = new Set([...serviceReveal.visibleIds].filter((id) => availableIds.has(id)));
  serviceReveal.queue = serviceReveal.queue.filter((id) => availableIds.has(id));
  serviceReveal.queuedIds = new Set(serviceReveal.queue);

  if (!animateNew || prefersReducedMotion) {
    stopServiceReveal(true);
    serviceReveal.visibleIds = availableIds;
    renderServiceCards(services);
    return;
  }

  services.forEach((service) => {
    if (!serviceReveal.visibleIds.has(service.id) && !serviceReveal.queuedIds.has(service.id)) {
      serviceReveal.queue.push(service.id);
      serviceReveal.queuedIds.add(service.id);
    }
  });
  renderServiceCards(services.filter((service) => serviceReveal.visibleIds.has(service.id)));
  if (!serviceReveal.timer && serviceReveal.queue.length) revealNextService();
}

async function refreshServices({ animateNew = false } = {}) {
  try {
    const services = await api("/api/services");
    renderServices(services.data, { animateNew });
  } catch (error) { notify(error.message, true); }
}

function stopScanPolling() {
  if (scanPollTimer) window.clearTimeout(scanPollTimer);
  scanPollTimer = null;
}

function scheduleScanPoll(delay = 900) {
  stopScanPolling();
  scanPollTimer = window.setTimeout(() => {
    scanPollTimer = null;
    pollScan();
  }, delay);
}

async function pollScan() {
  if (pollBusy || state.scan?.status !== "running") return;
  pollBusy = true;
  try {
    const scan = await api("/api/scan");
    const wasRunning = state.scan?.status === "running";
    renderScan(scan);
    if (scan.status === "running" || wasRunning) {
      await refreshServices({ animateNew: true });
    }
    if (scan.status === "running") scheduleScanPoll();
  } catch (_) {
    if (state.scan?.status === "running") scheduleScanPoll(1800);
  } finally {
    pollBusy = false;
  }
}

async function initializeDashboard() {
  stopScanPolling();
  try {
    const [config, services, scan] = await Promise.all([api("/api/config"), api("/api/services"), api("/api/scan")]);
    state.config = config;
    $("#gateway-url").textContent = config.gateway_base_url;
    if (!$("#scan-cidrs").value) $("#scan-cidrs").value = normalizeCidrs(config.scan_cidrs.join(",")).join(",");
    if (!$("#scan-ports").value) $("#scan-ports").value = config.scan_ports.join(",");
    renderServices(services.data);
    state.scan = null;
    if (scan.status === "running") {
      renderScan(scan);
      scheduleScanPoll();
    } else {
      // A page reload starts with a clean transient scan view. Registered
      // services remain intact, while the previous scan's progress/log cache
      // is intentionally not replayed.
      renderScan(emptyScanState());
    }
  } catch (error) { notify(error.message, true); }
}

async function saveCommonKey(activateForFindAI) {
  try {
    const value = $("#gateway-key").value.trim();
    const requestedName = $("#gateway-key-name").value.trim();
    if (!value) throw new Error("请填写要保存的密钥");
    const existing = accessKeys.find((item) => item.value === value);
    if (existing) {
      if (requestedName) existing.name = requestedName.slice(0, 60);
      if (activateForFindAI) activeAccessKeyId = existing.id;
    } else {
      const item = {
        id: createAccessKeyId(),
        name: requestedName.slice(0, 60) || `密钥 ${accessKeys.length + 1}`,
        value: value.slice(0, 4096),
      };
      accessKeys.push(item);
      if (activateForFindAI) activeAccessKeyId = item.id;
    }
    persistAccessKeyring();
    $("#gateway-key-name").value = "";
    $("#gateway-key").value = "";
    renderAccessKeys();
    notify(activateForFindAI ? "密钥已保存并用于 FindAI 访问" : "常用密钥已保存");
    if (activateForFindAI) await initializeDashboard();
  } catch (error) { notify(error.message, true); }
}
$("#save-key").addEventListener("click", () => saveCommonKey(true));
$("#save-key-only").addEventListener("click", () => saveCommonKey(false));
document.querySelectorAll("[data-theme-option]").forEach((button) => {
  button.addEventListener("click", () => applyTheme(button.dataset.themeOption));
});
applyTheme(document.documentElement.dataset.theme, false);
try { persistAccessKeyring(); } catch (_) {}
renderAccessKeys();
$("#scan-cidrs").addEventListener("blur", () => {
  const cidrs = normalizeCidrs($("#scan-cidrs").value);
  if (cidrs.length) $("#scan-cidrs").value = cidrs.join(",");
});
$("#start-scan").addEventListener("click", async () => {
  try {
    const cidrs = normalizeCidrs($("#scan-cidrs").value);
    $("#scan-cidrs").value = cidrs.join(",");
    const ports = parsePorts($("#scan-ports").value);
    const scan = await api("/api/scan", { method: "POST", body: JSON.stringify({ cidrs, ports, schemes: ["http"] }) });
    renderScan(scan);
    if (scan.status === "running") scheduleScanPoll();
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
    $("#manual-dialog").close();
    await refreshServices();
  } catch (error) { notify(error.message, true); }
});
$("#refresh").addEventListener("click", () => refreshServices({ animateNew: state.scan?.status === "running" }));
$("#clear-services").addEventListener("click", async () => {
  try {
    if (state.scan?.status === "running") throw new Error("扫描进行中，暂时不能清空列表");
    if (!state.services.length) return notify("服务列表已经是空的");
    if (!window.confirm(`确定清空当前 ${state.services.length} 个模型服务吗？`)) return;
    const result = await api("/api/services", { method: "DELETE" });
    renderServices([]);
    notify(`已清空 ${result.deleted || 0} 个模型服务`);
  } catch (error) { notify(error.message, true); }
});

const manualDialog = $("#manual-dialog");
const keyDialog = $("#key-dialog");
const credentialDialog = $("#credential-dialog");
const scanLogDialog = $("#scan-log-dialog");
let credentialServiceId = "";
$("#open-manual").addEventListener("click", () => {
  $("#open-manual").setAttribute("aria-expanded", "true");
  manualDialog.showModal();
  window.setTimeout(() => $("#manual-url").focus(), 0);
});
$("#close-manual").addEventListener("click", () => manualDialog.close());
manualDialog.addEventListener("close", () => $("#open-manual").setAttribute("aria-expanded", "false"));
manualDialog.addEventListener("click", (event) => {
  if (event.target === manualDialog) manualDialog.close();
});
$("#open-key").addEventListener("click", () => {
  $("#gateway-key-name").value = "";
  $("#gateway-key").value = "";
  renderAccessKeys();
  keyDialog.showModal();
  window.setTimeout(() => $("#gateway-key-name").focus(), 0);
});
$("#close-key").addEventListener("click", () => keyDialog.close());
keyDialog.addEventListener("click", (event) => {
  if (event.target === keyDialog) keyDialog.close();
});
function openCredentialDialog(serviceId) {
  const service = state.services.find((item) => item.id === serviceId);
  if (!service) throw new Error("找不到要填写密钥的模型服务");
  credentialServiceId = serviceId;
  $("#credential-service-summary").textContent = `${service.name} · ${service.base_url}`;
  renderCredentialKeyOptions();
  $("#credential-saved-key").value = "";
  $("#credential-key").value = "";
  credentialDialog.showModal();
  window.setTimeout(() => {
    if (accessKeys.length) $("#credential-saved-key").focus();
    else $("#credential-key").focus();
  }, 0);
}
function closeCredentialDialog() {
  credentialDialog.close();
  credentialServiceId = "";
  $("#credential-saved-key").value = "";
  $("#credential-key").value = "";
}
$("#credential-saved-key").addEventListener("change", (event) => {
  const selected = accessKeys.find((item) => item.id === event.target.value);
  $("#credential-key").value = selected?.value || "";
});
$("#apply-credential").addEventListener("click", async () => {
  try {
    if (!credentialServiceId) throw new Error("未选择模型服务");
    const apiKey = $("#credential-key").value.trim();
    if (!apiKey) throw new Error("请选择常用密钥或手工输入上游 API Key");
    await api(`/api/services/${credentialServiceId}/credential`, {
      method: "PUT",
      body: JSON.stringify({ api_key: apiKey }),
    });
    closeCredentialDialog();
    notify("上游密钥已加载，模型清单已刷新");
    await refreshServices();
  } catch (error) { notify(error.message, true); }
});
$("#close-credential").addEventListener("click", closeCredentialDialog);
credentialDialog.addEventListener("close", () => {
  credentialServiceId = "";
  $("#credential-saved-key").value = "";
  $("#credential-key").value = "";
});
credentialDialog.addEventListener("click", (event) => {
  if (event.target === credentialDialog) closeCredentialDialog();
});
$("#clear-active-key").addEventListener("click", async () => {
  try {
    activeAccessKeyId = "";
    persistAccessKeyring();
    renderAccessKeys();
    notify("FindAI 请求将不再携带访问密钥");
    await initializeDashboard();
  } catch (error) { notify(error.message, true); }
});
$("#saved-keys").addEventListener("click", async (event) => {
  const useButton = event.target.closest("[data-use-key]");
  const deleteButton = event.target.closest("[data-delete-key]");
  try {
    if (useButton) {
      const selected = accessKeys.find((item) => item.id === useButton.dataset.useKey);
      if (!selected) return;
      activeAccessKeyId = selected.id;
      persistAccessKeyring();
      renderAccessKeys();
      notify(`已切换到“${selected.name}”`);
      await initializeDashboard();
    }
    if (deleteButton) {
      const selected = accessKeys.find((item) => item.id === deleteButton.dataset.deleteKey);
      if (!selected || !window.confirm(`确定删除已保存的“${selected.name}”吗？`)) return;
      const wasActive = selected.id === activeAccessKeyId;
      accessKeys = accessKeys.filter((item) => item.id !== selected.id);
      if (wasActive) activeAccessKeyId = "";
      persistAccessKeyring();
      renderAccessKeys();
      notify(`已删除“${selected.name}”`);
      if (wasActive) await initializeDashboard();
    }
  } catch (error) { notify(error.message, true); }
});
$("#open-scan-log").addEventListener("click", () => scanLogDialog.showModal());
$("#close-scan-log").addEventListener("click", () => scanLogDialog.close());
scanLogDialog.addEventListener("click", (event) => {
  if (event.target === scanLogDialog) scanLogDialog.close();
});
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
      notify("节点复检完成"); await refreshServices();
    }
    if (credential) {
      openCredentialDialog(credential.dataset.credential);
    }
  } catch (error) { notify(error.message, true); }
});

initializeDashboard();
