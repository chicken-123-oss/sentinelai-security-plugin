const I18N = {
  en: {
    brandTitle: "Threat Monitoring Console",
    loginTitle: "Advanced CAPTCHA Login",
    loginSubtitle: "Password authentication is paired with a time-limited math challenge and nonce proof.",
    email: "Email",
    password: "Password",
    captcha: "CAPTCHA",
    signIn: "Sign In",
    signOut: "Sign Out",
    navOverview: "Monitor",
    navIncidents: "Incidents",
    navVisitors: "Visitors",
    navContent: "Content",
    navModels: "Models",
    navAgent: "AI Chat",
    navAccount: "Account",
    navAudit: "Audit",
    overviewTitle: "Real-Time Monitored Data",
    overviewCopy: "Incidents, event content, model status, and visitor records update automatically.",
    liveIncidents: "Live Incident List",
    visitorRecords: "Visitor Records",
    refresh: "Refresh",
    incidentCenter: "Incident Center",
    monitoredContent: "Monitored Content",
    eventPriorityIndex: "Event Priority Index",
    eventIndexHint: "Events are grouped by day and score level; duplicate identical accesses are collapsed.",
    uniqueAccesses: "Unique Accesses",
    duplicatesCollapsed: "Duplicates Collapsed",
    attackerInput: "Attacker Input",
    fullEvent: "Full Event",
    firstSeen: "First Seen",
    priorityCritical: "P0 Critical",
    priorityHigh: "P1 High",
    priorityMedium: "P2 Medium",
    priorityLow: "P3 Low",
    modelAccess: "Large Model API Access",
    modelHint: "Choose any provider independently; store secret references, not raw keys.",
    saveModel: "Save Model",
    agentConversation: "Connected AI Conversation",
    agentConversationHint: "Talk directly with the active model provider using current monitored context.",
    connectedAgent: "Managed-Site Context",
    agentChatPlaceholder: "Ask the connected AI about incidents, visitors, model access, or status",
    sendMessage: "Send",
    noAgents: "No managed-site context available.",
    lastSeen: "Last seen",
    policyVersion: "Policy",
    user: "You",
    agent: "AI",
    passwordChange: "Password Change",
    currentPassword: "Current Password",
    newPassword: "New Password",
    changePassword: "Change Password",
    auditLogs: "Audit Logs",
    saved: "Saved",
    activated: "Model activated",
    passwordChanged: "Password changed",
    chooseCaptcha: "Choose the CAPTCHA answer",
    noData: "No data.",
    approve: "Approve",
    reject: "Reject",
    run: "Run",
    trust: "Trust",
    active: "ACTIVE",
    activate: "Activate"
  },
  "zh-CN": {
    brandTitle: "威胁监控控制台",
    loginTitle: "高级验证码登录",
    loginSubtitle: "密码认证叠加限时数学挑战与 nonce 证明，降低自动化撞库风险。",
    email: "邮箱",
    password: "密码",
    captcha: "验证码",
    signIn: "登录",
    signOut: "退出",
    navOverview: "监控",
    navIncidents: "事件",
    navVisitors: "访客",
    navContent: "内容",
    navModels: "模型",
    navAgent: "AI 对话",
    navAccount: "账户",
    navAudit: "审计",
    overviewTitle: "实时监控数据",
    overviewCopy: "事件、拦截内容、模型状态与访客记录会自动刷新。",
    liveIncidents: "实时事件列表",
    visitorRecords: "访客记录",
    refresh: "刷新",
    incidentCenter: "事件中心",
    monitoredContent: "监控内容",
    eventPriorityIndex: "事件优先级索引",
    eventIndexHint: "事件按日期和评分等级分组；相同访问会合并去重。",
    uniqueAccesses: "去重访问",
    duplicatesCollapsed: "已合并重复",
    attackerInput: "攻击者输入内容",
    fullEvent: "完整事件",
    firstSeen: "首次出现",
    priorityCritical: "P0 严重",
    priorityHigh: "P1 高危",
    priorityMedium: "P2 中危",
    priorityLow: "P3 低危",
    modelAccess: "大模型 API 接入",
    modelHint: "用户可自主选择大模型供应商；保存密钥引用而非明文密钥。",
    saveModel: "保存模型",
    agentConversation: "连接 AI 对话",
    agentConversationHint: "直接与当前启用的大模型对话，并自动携带监控上下文。",
    connectedAgent: "托管站点上下文",
    agentChatPlaceholder: "询问连接 AI 的事件、访客、模型接入或运行状态",
    sendMessage: "发送",
    noAgents: "暂无托管站点上下文。",
    lastSeen: "最后心跳",
    policyVersion: "策略",
    user: "你",
    agent: "AI",
    passwordChange: "修改密码",
    currentPassword: "当前密码",
    newPassword: "新密码",
    changePassword: "确认修改",
    auditLogs: "审计日志",
    saved: "已保存",
    activated: "模型已启用",
    passwordChanged: "密码已修改",
    chooseCaptcha: "请选择验证码答案",
    noData: "暂无数据。",
    approve: "批准",
    reject: "拒绝",
    run: "执行",
    trust: "信任分",
    active: "启用中",
    activate: "启用"
  }
};

const state = {
  token: sessionStorage.getItem("sentinelai_token") || localStorage.getItem("sentinelai_token") || "",
  lang: localStorage.getItem("sentinelai_lang") || "en",
  captcha: null,
  incidents: [],
  events: [],
  eventIndex: null,
  missionTheme: null,
  visitors: [],
  providers: [],
  agents: [],
  agentMessages: [],
  audit: [],
  selectedIncidentId: "",
  selectedAgentId: "",
  status: null,
  liveTimer: null
};

const PROVIDER_PRESETS = {
  offline_heuristic: {
    name: "Offline Heuristic Analyzer",
    endpoint: "",
    model: "sentinelai-offline-v1",
    secretRef: ""
  },
  deepseek: {
    name: "DeepSeek Security Analyzer",
    endpoint: "https://api.deepseek.com",
    model: "deepseek-v4-flash",
    secretRef: "DEEPSEEK_API_KEY"
  },
  glm: {
    name: "Zhipu GLM Security Analyzer",
    endpoint: "https://open.bigmodel.cn/api/paas/v4/",
    model: "glm-5",
    secretRef: "ZAI_API_KEY"
  },
  kimi: {
    name: "Kimi Security Analyzer",
    endpoint: "https://api.moonshot.ai/v1",
    model: "kimi-k2.6",
    secretRef: "MOONSHOT_API_KEY"
  },
  ollama: {
    name: "Local Ollama Analyzer",
    endpoint: "http://127.0.0.1:11434",
    model: "llama3",
    secretRef: ""
  }
};

if (state.token) {
  sessionStorage.setItem("sentinelai_token", state.token);
  localStorage.removeItem("sentinelai_token");
}

const els = {
  loginPanel: document.getElementById("loginPanel"),
  appShell: document.getElementById("appShell"),
  loginForm: document.getElementById("loginForm"),
  email: document.getElementById("email"),
  password: document.getElementById("password"),
  captchaQuestion: document.getElementById("captchaQuestion"),
  captchaProof: document.getElementById("captchaProof"),
  captchaChoices: document.getElementById("captchaChoices"),
  captchaAnswer: document.getElementById("captchaAnswer"),
  refreshCaptchaBtn: document.getElementById("refreshCaptchaBtn"),
  statusStrip: document.getElementById("statusStrip"),
  metrics: document.getElementById("metrics"),
  missionMap: document.getElementById("missionMap"),
  liveIncidentList: document.getElementById("liveIncidentList"),
  liveVisitorList: document.getElementById("liveVisitorList"),
  incidentList: document.getElementById("incidentList"),
  incidentDetail: document.getElementById("incidentDetail"),
  visitorList: document.getElementById("visitorList"),
  eventContentList: document.getElementById("eventContentList"),
  providerList: document.getElementById("providerList"),
  providerForm: document.getElementById("providerForm"),
  providerName: document.getElementById("providerName"),
  providerType: document.getElementById("providerType"),
  providerEndpoint: document.getElementById("providerEndpoint"),
  providerModel: document.getElementById("providerModel"),
  providerSecretRef: document.getElementById("providerSecretRef"),
  agentSelect: document.getElementById("agentSelect"),
  agentStatusList: document.getElementById("agentStatusList"),
  agentChatLog: document.getElementById("agentChatLog"),
  agentChatForm: document.getElementById("agentChatForm"),
  agentChatInput: document.getElementById("agentChatInput"),
  passwordForm: document.getElementById("passwordForm"),
  currentPassword: document.getElementById("currentPassword"),
  newPassword: document.getElementById("newPassword"),
  auditList: document.getElementById("auditList"),
  toast: document.getElementById("toast")
};

document.querySelectorAll(".tab[data-tab]").forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.tab));
});
document.querySelectorAll("[data-jump-tab]").forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.jumpTab));
});
document.querySelectorAll("[data-lang]").forEach((button) => {
  button.addEventListener("click", () => setLanguage(button.dataset.lang));
});
document.getElementById("refreshBtn").addEventListener("click", () => loadAll());
els.refreshCaptchaBtn.addEventListener("click", () => loadCaptcha());
document.getElementById("logoutBtn").addEventListener("click", () => {
  state.token = "";
  sessionStorage.removeItem("sentinelai_token");
  localStorage.removeItem("sentinelai_token");
  stopLivePolling();
  showLogin();
  loadCaptcha();
});

els.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!els.captchaAnswer.value) {
    notify(t("chooseCaptcha"));
    return;
  }
  try {
    const response = await api("/api/v1/auth/login", {
      method: "POST",
      body: {
        email: els.email.value,
        password: els.password.value,
        captchaId: state.captcha?.challengeId,
        captchaAnswer: els.captchaAnswer.value
      },
      auth: false
    });
    state.token = response.token;
    sessionStorage.setItem("sentinelai_token", state.token);
    localStorage.removeItem("sentinelai_token");
    showApp();
    await loadAll();
    startLivePolling();
  } catch (error) {
    notify(error.message);
    await loadCaptcha();
  }
});

els.providerForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/v1/providers", {
      method: "POST",
      body: {
        name: els.providerName.value,
        providerType: els.providerType.value,
        endpoint: els.providerEndpoint.value,
        model: els.providerModel.value,
        apiKeySecretRef: els.providerSecretRef.value,
        supportsStructuredOutput: true,
        supportsToolCalling: els.providerType.value !== "offline_heuristic",
        enabled: true
      }
    });
    notify(t("saved"));
    await loadProviders();
    await loadLive();
  } catch (error) {
    notify(error.message);
  }
});
els.providerType.addEventListener("change", () => applyProviderPreset(els.providerType.value));

els.passwordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/v1/auth/change-password", {
      method: "POST",
      body: {
        currentPassword: els.currentPassword.value,
        newPassword: els.newPassword.value
      }
    });
    els.currentPassword.value = "";
    els.newPassword.value = "";
    notify(t("passwordChanged"));
  } catch (error) {
    notify(error.message);
  }
});

els.agentSelect.addEventListener("change", async () => {
  state.selectedAgentId = els.agentSelect.value;
  await loadAgentMessages();
  renderAgentChat();
});

els.agentChatForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await sendAgentMessage();
});

init();

async function init() {
  setLanguage(state.lang);
  await loadMissionTheme();
  await loadStatus();
  await loadCaptcha();
  if (state.token) {
    showApp();
    await loadAll();
    startLivePolling();
  } else {
    showLogin();
  }
}

function setLanguage(lang) {
  state.lang = lang === "zh-CN" ? "zh-CN" : "en";
  localStorage.setItem("sentinelai_lang", state.lang);
  document.documentElement.lang = state.lang;
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    node.textContent = t(node.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
    node.setAttribute("placeholder", t(node.dataset.i18nPlaceholder));
  });
  document.querySelectorAll("[data-lang]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.lang === state.lang);
  });
  renderAll();
}

function t(key) {
  return I18N[state.lang][key] || I18N.en[key] || key;
}

function showLogin() {
  els.loginPanel.classList.remove("is-hidden");
  els.appShell.classList.add("is-hidden");
}

function showApp() {
  els.loginPanel.classList.add("is-hidden");
  els.appShell.classList.remove("is-hidden");
}

function activateTab(name) {
  document.querySelectorAll(".tab[data-tab]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.tab === name);
  });
  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("is-active", view.id === `${name}View`);
  });
}

async function loadCaptcha() {
  state.captcha = await api("/api/v1/auth/captcha", { auth: false });
  els.captchaQuestion.textContent = state.captcha.question;
  els.captchaProof.textContent = `proof ${state.captcha.proof} / ${state.captcha.mode}`;
  els.captchaAnswer.value = "";
  els.captchaChoices.innerHTML = state.captcha.choices.map((choice) => `
    <button type="button" data-choice="${escapeHtml(choice)}">${escapeHtml(choice)}</button>
  `).join("");
  els.captchaChoices.querySelectorAll("[data-choice]").forEach((button) => {
    button.addEventListener("click", () => {
      els.captchaAnswer.value = button.dataset.choice;
      els.captchaChoices.querySelectorAll("button").forEach((item) => item.classList.toggle("is-active", item === button));
    });
  });
}

async function loadMissionTheme() {
  try {
    state.missionTheme = await api("/static/mission-map.json", { auth: false });
  } catch (error) {
    state.missionTheme = fallbackMissionTheme();
  }
}

async function loadAll() {
  await Promise.all([loadStatus(), loadIncidents(), loadProviders(), loadAgents(), loadAudit(), loadVisitors(), loadEvents()]);
  await loadAgentMessages();
  renderAll();
}

async function loadLive() {
  if (!state.token) return;
  const response = await api("/api/v1/monitor/live");
  state.status = response.status;
  state.incidents = response.incidents || [];
  state.events = response.events || [];
  state.eventIndex = response.eventIndex || state.eventIndex;
  state.visitors = response.visitors || [];
  state.agents = response.agents || state.agents || [];
  if ((!state.selectedAgentId || !state.agents.some((agent) => agent.id === state.selectedAgentId)) && state.agents.length > 0) {
    state.selectedAgentId = state.agents[0].id;
  }
  state.audit = response.audit || [];
  if (!state.providers.length && response.activeProvider) {
    state.providers = [response.activeProvider];
  }
  renderAll();
}

async function loadStatus() {
  state.status = await api("/api/v1/status", { auth: false });
  els.statusStrip.textContent = state.status.ok ? `ONLINE // ${state.status.version}` : "OFFLINE";
}

async function loadIncidents() {
  const response = await api("/api/v1/incidents?limit=50");
  state.incidents = response.items || [];
  if (!state.selectedIncidentId && state.incidents.length > 0) {
    state.selectedIncidentId = state.incidents[0].id;
  }
  if (state.selectedIncidentId) {
    await selectIncident(state.selectedIncidentId, false);
  }
}

async function loadProviders() {
  const response = await api("/api/v1/providers");
  state.providers = response.items || [];
}

async function loadAgents() {
  const response = await api("/api/v1/agents");
  state.agents = response.items || [];
  if ((!state.selectedAgentId || !state.agents.some((agent) => agent.id === state.selectedAgentId)) && state.agents.length > 0) {
    state.selectedAgentId = state.agents[0].id;
  }
}

async function loadAgentMessages() {
  if (!state.selectedAgentId) {
    state.agentMessages = [];
    return;
  }
  const response = await api(`/api/v1/ai/chat?agentId=${encodeURIComponent(state.selectedAgentId)}`);
  state.agentMessages = response.items || [];
}

async function loadAudit() {
  const response = await api("/api/v1/audit-logs?limit=80");
  state.audit = response.items || [];
}

async function loadVisitors() {
  const response = await api("/api/v1/visitors?limit=100");
  state.visitors = response.items || [];
}

async function loadEvents() {
  const response = await api("/api/v1/events/index?limit=160");
  state.eventIndex = response;
  state.events = response.items || [];
}

function startLivePolling() {
  stopLivePolling();
  state.liveTimer = window.setInterval(() => loadLive().catch((error) => notify(error.message)), 5000);
}

function stopLivePolling() {
  if (state.liveTimer) {
    window.clearInterval(state.liveTimer);
    state.liveTimer = null;
  }
}

function renderAll() {
  renderMissionMap();
  renderOverview();
  renderIncidents();
  renderVisitors();
  renderEvents();
  renderProviders();
  renderAgentChat();
  renderAudit();
}

function renderMissionMap() {
  if (!els.missionMap || !state.missionTheme) return;
  const nodes = state.missionTheme.nodes || [];
  const beams = state.missionTheme.beams || [];
  const nodeById = Object.fromEntries(nodes.map((node) => [node.id, node]));

  els.missionMap.innerHTML = `
    <div class="map-core" aria-hidden="true">
      <span class="core-chair"></span>
      <span class="core-stone core-stone-a"></span>
      <span class="core-stone core-stone-b"></span>
      <span class="core-ring"></span>
    </div>
    <svg class="map-links" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
      ${beams.map((beam) => renderBeam(beam, nodeById)).join("")}
    </svg>
    ${nodes.map((node) => renderMissionNode(node)).join("")}
  `;
  els.missionMap.querySelectorAll("[data-map-tab]").forEach((button) => {
    button.addEventListener("click", () => activateTab(button.dataset.mapTab));
  });
}

function renderBeam(beam, nodeById) {
  const from = nodeById[beam.from];
  const to = nodeById[beam.to];
  if (!from || !to) return "";
  const color = beam.tone === "lime" ? "#b9f21d" : "rgba(244, 248, 244, 0.78)";
  return `<line x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}" stroke="${color}" stroke-width="${beam.tone === "lime" ? 0.36 : 0.22}" vector-effect="non-scaling-stroke" />`;
}

function renderMissionNode(node) {
  const value = missionValue(node);
  const total = Math.max(Number(node.total || 1), value);
  const capped = Math.min(value, total);
  const label = state.lang === "zh-CN" ? node.labelZh : node.labelEn;
  const prefix = state.lang === "zh-CN" ? node.prefixZh : node.prefixEn;
  const active = document.querySelector(`.tab.is-active[data-tab="${node.tab}"]`) ? "is-current" : "";
  const completed = value > 0 ? "is-unlocked" : "";
  return `
    <button class="mission-node ${active} ${completed} tone-${escapeHtml(node.tone || "white")}" data-node-id="${escapeHtml(node.id)}" data-map-tab="${escapeHtml(node.tab)}">
      <span class="node-score"><strong>${escapeHtml(capped)}</strong>/<small>${escapeHtml(total)}</small></span>
      <span class="node-copy">
        <span>${escapeHtml(prefix || "")}</span>
        <strong>${escapeHtml(label || node.id)}</strong>
        <i></i>
      </span>
    </button>
  `;
}

function missionValue(node) {
  const counts = state.status?.counts || {};
  const activeProvider = state.providers.find((provider) => provider.active) || state.providers[0];
  const values = {
    agents: state.agents.length || counts.agents || 0,
    incidents: counts.incidents || state.incidents.length || 0,
    visitors: counts.visitors || state.visitors.length || 0,
    events: state.eventIndex?.uniqueEventCount || counts.events || state.events.length || 0,
    providers: activeProvider ? 1 : (counts.providers || state.providers.length || 0),
    agentMessages: counts.agentMessages || state.agentMessages.length || 0
  };
  return Number(values[node.metric] || 0);
}

function fallbackMissionTheme() {
  return {
    nodes: [
      { id: "overview", tab: "overview", labelEn: "REMAINS", labelZh: "留存", prefixEn: "Unlocked", prefixZh: "已解锁", metric: "agents", total: 4, x: 47, y: 40, tone: "white" },
      { id: "incidents", tab: "incidents", labelEn: "PREPARATIONS", labelZh: "前序", prefixEn: "Completed", prefixZh: "已完成", metric: "incidents", total: 5, x: 65, y: 48, tone: "white" },
      { id: "visitors", tab: "visitors", labelEn: "ELSEWHERE", labelZh: "别处", prefixEn: "Completed", prefixZh: "已完成", metric: "visitors", total: 25, x: 25, y: 60, tone: "lime" },
      { id: "content", tab: "content", labelEn: "MEMORIES", labelZh: "记忆", prefixEn: "Completed", prefixZh: "已完成", metric: "events", total: 5, x: 45, y: 76, tone: "lime" },
      { id: "providers", tab: "providers", labelEn: "INTERFACE", labelZh: "接口", prefixEn: "Active", prefixZh: "已启用", metric: "providers", total: 3, x: 72, y: 70, tone: "white" },
      { id: "agent", tab: "agent", labelEn: "INTELLIGENCE", labelZh: "智能", prefixEn: "Linked", prefixZh: "已连接", metric: "agentMessages", total: 8, x: 55, y: 43, tone: "lime" }
    ],
    beams: [
      { from: "visitors", to: "content", tone: "lime" },
      { from: "content", to: "agent", tone: "lime" },
      { from: "agent", to: "incidents", tone: "white" },
      { from: "overview", to: "agent", tone: "white" },
      { from: "agent", to: "providers", tone: "white" }
    ]
  };
}

function renderOverview() {
  if (!els.metrics) return;
  const counts = state.status?.counts || {};
  const critical = state.incidents.filter((item) => item.severity === "critical").length;
  const waiting = state.incidents.filter((item) => item.status === "needs_approval" || item.status === "containment_recommended").length;
  const activeProvider = state.providers.find((provider) => provider.active) || state.providers[0];
  els.metrics.innerHTML = [
    metric("Incidents", counts.incidents || 0),
    metric("Critical", critical),
    metric("Visitors", counts.visitors || state.visitors.length || 0),
    metric("Model", activeProvider ? activeProvider.model : "offline")
  ].join("");
  els.liveIncidentList.innerHTML = renderIncidentRows(state.incidents.slice(0, 8), "compact");
  els.liveVisitorList.innerHTML = renderVisitorRows(state.visitors.slice(0, 8), true);
  const waitingBadge = waiting > 0 ? `${waiting} ${state.lang === "zh-CN" ? "待处理" : "waiting"}` : "clear";
  els.statusStrip.textContent = `ONLINE // ${waitingBadge}`;
}

function metric(label, value) {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value))}</strong></div>`;
}

function renderIncidents() {
  els.incidentList.innerHTML = renderIncidentRows(state.incidents, "full");
  els.incidentList.querySelectorAll(".incident-row").forEach((row) => {
    row.addEventListener("click", () => selectIncident(row.dataset.id));
  });
}

function renderIncidentRows(items, mode) {
  if (!items.length) return `<p class="muted">${t("noData")}</p>`;
  return items.map((incident) => `
    <article class="incident-row ${incident.id === state.selectedIncidentId ? "is-active" : ""}" data-id="${incident.id || ""}">
      <div class="badge-line">
        <span class="badge severity-${incident.severity}">${escapeHtml(incident.severity)}</span>
        <span class="badge severity-${incident.status}">${escapeHtml(incident.status)}</span>
      </div>
      <h4>${escapeHtml(incident.title)}</h4>
      <p>${escapeHtml(incident.summary || "")}</p>
      <p>${t("trust")} ${escapeHtml(String(incident.trustScore))} / ${escapeHtml(incident.createdAt || "")}</p>
    </article>
  `).join("");
}

async function selectIncident(id, rerender = true) {
  state.selectedIncidentId = id;
  if (rerender) renderIncidents();
  const incident = await api(`/api/v1/incidents/${id}`);
  els.incidentDetail.innerHTML = `
    <div class="stack-row">
      <div class="badge-line">
        <span class="badge severity-${incident.severity}">${escapeHtml(incident.severity)}</span>
        <span class="badge severity-${incident.status}">${escapeHtml(incident.status)}</span>
        <span class="badge">${t("trust")} ${incident.trustScore}</span>
      </div>
      <h3>${escapeHtml(incident.title)}</h3>
      <p class="muted">${escapeHtml(incident.summary)}</p>
      <div class="badge-line">
        <button class="primary-action" data-action="approve" data-id="${incident.id}">${t("approve")}</button>
        <button data-action="reject" data-id="${incident.id}">${t("reject")}</button>
      </div>
    </div>
    <h3>:// ACTIONS</h3>
    <div>${renderActions(incident.actionRuns || [])}</div>
    <h3>:// ANALYSIS</h3>
    <pre class="object-view">${escapeHtml(JSON.stringify(incident.analysis, null, 2))}</pre>
    <h3>:// EVIDENCE</h3>
    <pre class="object-view">${escapeHtml(JSON.stringify(incident.event, null, 2))}</pre>
  `;
  els.incidentDetail.querySelectorAll("button[data-action]").forEach((button) => {
    button.addEventListener("click", () => handleIncidentCommand(button.dataset.action, button.dataset.id));
  });
  els.incidentDetail.querySelectorAll("button[data-run]").forEach((button) => {
    button.addEventListener("click", () => executeRun(button.dataset.run));
  });
}

function renderActions(actionRuns) {
  if (!actionRuns.length) return `<p class="muted">${t("noData")}</p>`;
  return actionRuns.map((run) => `
    <div class="action-row">
      <div>
        <strong>${escapeHtml(run.actionId)}</strong>
        <p class="muted">${escapeHtml(JSON.stringify(run.parameters))}</p>
      </div>
      <div class="badge-line">
        <span class="badge severity-${run.status}">${escapeHtml(run.status)}</span>
        <button data-run="${run.id}">${t("run")}</button>
      </div>
    </div>
  `).join("");
}

function renderVisitors() {
  els.visitorList.innerHTML = renderVisitorRows(state.visitors, false);
}

function renderVisitorRows(items, compact) {
  if (!items.length) return `<p class="muted">${t("noData")}</p>`;
  return items.map((visitor) => `
    <div class="${compact ? "stack-row" : "table-row"}">
      <strong>${escapeHtml(visitor.ip)}</strong>
      <span>${escapeHtml(visitor.method)} ${escapeHtml(visitor.path)}</span>
      <span class="muted">${escapeHtml(visitor.lastSeen || visitor.createdAt)} / x${escapeHtml(visitor.visitCount || 1)}</span>
      ${compact ? "" : `<span class="muted">${escapeHtml(visitor.userAgent)}</span>`}
    </div>
  `).join("");
}

function renderEvents() {
  const index = state.eventIndex || { items: state.events, days: [], priorityCounts: {}, uniqueEventCount: state.events.length, duplicatesCollapsed: 0 };
  const days = index.days && index.days.length ? index.days : [{ day: "recent", count: state.events.length, items: state.events }];
  if (!state.events.length) {
    els.eventContentList.innerHTML = `<p class="muted">${t("noData")}</p>`;
    return;
  }
  els.eventContentList.innerHTML = `
    <section class="event-index-summary">
      <div>
        <p class="eyebrow">:// ${t("eventPriorityIndex")}</p>
        <p class="muted">${t("eventIndexHint")}</p>
      </div>
      <div class="priority-metrics">
        ${priorityMetric("critical", index.priorityCounts?.critical || 0)}
        ${priorityMetric("high", index.priorityCounts?.high || 0)}
        ${priorityMetric("medium", index.priorityCounts?.medium || 0)}
        ${priorityMetric("low", index.priorityCounts?.low || 0)}
      </div>
      <div class="badge-line">
        <span class="badge">${t("uniqueAccesses")} ${escapeHtml(index.uniqueEventCount || state.events.length)}</span>
        <span class="badge">${t("duplicatesCollapsed")} ${escapeHtml(index.duplicatesCollapsed || 0)}</span>
      </div>
    </section>
    ${days.map((day) => `
      <section class="day-section">
        <div class="day-header">
          <h3>${escapeHtml(day.day)}</h3>
          <span class="badge">${escapeHtml(day.count || day.items.length)}</span>
        </div>
        ${(day.items || []).map((event) => renderEventCard(event)).join("")}
      </section>
    `).join("")}
  `;
}

function priorityMetric(level, count) {
  return `
    <div class="priority-pill priority-${level}">
      <span>${escapeHtml(priorityLabel(level))}</span>
      <strong>${escapeHtml(count)}</strong>
    </div>
  `;
}

function priorityLabel(level) {
  return {
    critical: t("priorityCritical"),
    high: t("priorityHigh"),
    medium: t("priorityMedium"),
    low: t("priorityLow")
  }[level] || level;
}

function renderEventCard(event) {
  const priority = event.priority || {};
  const attackerInput = event.attackerInput || { summary: "", fields: {} };
  return `
    <article class="content-row event-card">
      <div>
        <div class="badge-line">
          <span class="badge severity-${escapeHtml(priority.level || event.severityHint)}">${escapeHtml(priority.label || event.severityHint)}</span>
          <span class="badge severity-${escapeHtml(event.score?.severity || event.severityHint)}">${escapeHtml(event.score?.severity || event.severityHint)}</span>
          ${event.duplicateCount > 1 ? `<span class="badge">x${escapeHtml(event.duplicateCount)}</span>` : ""}
        </div>
        <h3>${escapeHtml(event.category)}</h3>
        <p class="muted">${escapeHtml(event.source)} / ${escapeHtml(event.receivedAt)}</p>
        <p class="muted">${t("trust")} ${escapeHtml(event.score?.trustScore ?? "")} / risk ${escapeHtml(event.score?.riskScore ?? "")}</p>
        <p class="muted">${t("firstSeen")} ${escapeHtml(event.firstSeen || event.receivedAt)} / ${t("lastSeen")} ${escapeHtml(event.lastSeen || event.receivedAt)}</p>
      </div>
      <div class="event-detail-stack">
        <section class="attacker-input">
          <strong>${t("attackerInput")}</strong>
          <p>${escapeHtml(attackerInput.summary || t("noData"))}</p>
          <pre class="object-view">${escapeHtml(JSON.stringify(attackerInput.fields || {}, null, 2))}</pre>
        </section>
        <details>
          <summary>${t("fullEvent")}</summary>
          <pre class="object-view">${escapeHtml(JSON.stringify({
            actor: event.actor,
            asset: event.asset,
            labels: event.labels,
            payload: event.redactedPayload,
            score: event.score,
            priority: event.priority
          }, null, 2))}</pre>
        </details>
      </div>
    </article>
  `;
}

function renderProviders() {
  if (!state.providers.length) {
    els.providerList.innerHTML = `<p class="muted">${t("noData")}</p>`;
    return;
  }
  els.providerList.innerHTML = state.providers.map((provider) => `
    <div class="provider-row">
      <div>
        <div class="badge-line">
          <strong>${escapeHtml(provider.name)}</strong>
          ${provider.active ? `<span class="badge severity-ready">${t("active")}</span>` : ""}
        </div>
        <p class="muted">${escapeHtml(provider.providerType)} / ${escapeHtml(provider.model)} / ${escapeHtml(provider.endpoint || "local")}</p>
        <p class="muted">${escapeHtml(provider.apiKeySecretRef || "no secret reference")}</p>
      </div>
      <button data-provider="${provider.id}">${t("activate")}</button>
    </div>
  `).join("");
  els.providerList.querySelectorAll("[data-provider]").forEach((button) => {
    button.addEventListener("click", () => activateProvider(button.dataset.provider));
  });
}

function applyProviderPreset(providerType) {
  const preset = PROVIDER_PRESETS[providerType];
  if (!preset) return;
  els.providerName.value = preset.name;
  els.providerEndpoint.value = preset.endpoint;
  els.providerModel.value = preset.model;
  els.providerSecretRef.value = preset.secretRef;
}

function renderAgentChat() {
  if (!els.agentSelect) return;
  if (!state.agents.length) {
    els.agentSelect.innerHTML = "";
    els.agentStatusList.innerHTML = `<p class="muted">${t("noAgents")}</p>`;
    els.agentChatLog.innerHTML = `<p class="muted">${t("noAgents")}</p>`;
    return;
  }

  els.agentSelect.innerHTML = state.agents.map((agent) => `
    <option value="${escapeHtml(agent.id)}">${escapeHtml(agent.name)} / ${escapeHtml(agent.status)}</option>
  `).join("");
  els.agentSelect.value = state.selectedAgentId || state.agents[0].id;

  els.agentStatusList.innerHTML = state.agents.map((agent) => `
    <div class="agent-row ${agent.id === state.selectedAgentId ? "is-active" : ""}">
      <div>
        <div class="badge-line">
          <strong>${escapeHtml(agent.name)}</strong>
          <span class="badge severity-${agent.status}">${escapeHtml(agent.status)}</span>
        </div>
        <p class="muted">${t("policyVersion")} ${escapeHtml(agent.policyVersion)} / ${t("lastSeen")} ${escapeHtml(agent.lastSeen)}</p>
      </div>
    </div>
  `).join("");

  if (!state.agentMessages.length) {
    els.agentChatLog.innerHTML = `<p class="muted">${t("noData")}</p>`;
    return;
  }
  els.agentChatLog.innerHTML = state.agentMessages.map((message) => `
    <article class="chat-message chat-message-${escapeHtml(message.role)}">
      <div class="badge-line">
        <strong>${message.role === "user" ? t("user") : t("agent")}</strong>
        <span class="muted">${escapeHtml(message.createdAt)}</span>
      </div>
      <p>${escapeHtml(message.message)}</p>
    </article>
  `).join("");
  els.agentChatLog.scrollTop = els.agentChatLog.scrollHeight;
}

function renderAudit() {
  if (!state.audit.length) {
    els.auditList.innerHTML = `<p class="muted">${t("noData")}</p>`;
    return;
  }
  els.auditList.innerHTML = state.audit.map((entry) => `
    <div class="table-row">
      <strong>${escapeHtml(entry.action)}</strong>
      <span>${escapeHtml(entry.actor)} -> ${escapeHtml(entry.target)}</span>
      <span class="muted">${escapeHtml(entry.createdAt)}</span>
    </div>
  `).join("");
}

async function sendAgentMessage() {
  const message = els.agentChatInput.value.trim();
  if (!message) {
    notify(t("agentChatPlaceholder"));
    return;
  }
  if (!state.selectedAgentId && state.agents.length > 0) {
    state.selectedAgentId = state.agents[0].id;
  }
  try {
    const response = await api("/api/v1/ai/chat", {
      method: "POST",
      body: {
        agentId: state.selectedAgentId,
        message
      }
    });
    state.agentMessages = response.items || [];
    els.agentChatInput.value = "";
    renderAgentChat();
  } catch (error) {
    notify(error.message);
  }
}

async function handleIncidentCommand(action, incidentId) {
  try {
    if (action === "approve") {
      await api(`/api/v1/incidents/${incidentId}/approve`, { method: "POST", body: {} });
    }
    if (action === "reject") {
      await api(`/api/v1/incidents/${incidentId}/reject`, { method: "POST", body: { reason: "dashboard decision" } });
    }
    await loadAll();
  } catch (error) {
    notify(error.message);
  }
}

async function executeRun(actionRunId) {
  try {
    await api(`/api/v1/action-runs/${actionRunId}/execute`, { method: "POST", body: {} });
    notify("OK");
    await loadAll();
  } catch (error) {
    notify(error.message);
  }
}

async function activateProvider(providerId) {
  try {
    await api(`/api/v1/providers/${providerId}/activate`, { method: "POST", body: {} });
    notify(t("activated"));
    await loadProviders();
    renderProviders();
  } catch (error) {
    notify(error.message);
  }
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json" };
  if (options.auth !== false) {
    headers.Authorization = `Bearer ${state.token}`;
  }
  const response = await fetch(path, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const data = response.status === 204 ? {} : await response.json();
  if (!response.ok) {
    const zhMessage = [data.messageZh, data.detailsZh, data.hintZh].filter(Boolean).join(" ");
    throw new Error((state.lang === "zh-CN" && zhMessage) ? zhMessage : (data.error || `HTTP ${response.status}`));
  }
  return data;
}

function notify(message) {
  els.toast.textContent = message;
  els.toast.classList.add("is-visible");
  window.setTimeout(() => els.toast.classList.remove("is-visible"), 3600);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
