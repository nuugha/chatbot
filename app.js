const svg = document.getElementById('networkCanvas');
const state = {
  running: false,
  speed: 1,
  selectedScenario: null,
  packets: [],
  alerts: [],
  pipeline: [],
  metrics: { flows: 0, anomaly: 0, confidence: 0 },
};

const devices = [
  { id: 'internet', label: 'Internet/Kali', x: 120, y: 120, zone: 'internet', type: 'cloud' },
  { id: 'fw', label: 'Firewall', x: 360, y: 230, zone: 'dmz', type: 'security' },
  { id: 'dmzsw', label: 'DMZ Switch', x: 580, y: 210, zone: 'dmz', type: 'switch' },
  { id: 'web', label: 'Web Server', x: 790, y: 125, zone: 'dmz', type: 'server' },
  { id: 'ftp', label: 'FTP Server', x: 790, y: 240, zone: 'dmz', type: 'server' },
  { id: 'core', label: 'Core Switch', x: 560, y: 430, zone: 'lan', type: 'switch' },
  { id: 'dc', label: 'AD/DC', x: 820, y: 410, zone: 'lan', type: 'server' },
  { id: 'win1', label: 'Win-Client-01', x: 790, y: 560, zone: 'lan', type: 'workstation' },
  { id: 'win2', label: 'Win-Client-02', x: 930, y: 590, zone: 'lan', type: 'workstation' },
  { id: 'ids', label: 'IDS Sensor', x: 1110, y: 380, zone: 'monitor', type: 'ids' },
  { id: 'siem', label: 'SOC Console', x: 1300, y: 420, zone: 'monitor', type: 'monitor' },
];

const byId = Object.fromEntries(devices.map((d) => [d.id, d]));
const links = [
  ['internet', 'fw', 'Gi0/0', 'Gi0/1', 'normal'],
  ['fw', 'dmzsw', 'Gi0/2', 'Gi0/24', 'normal'],
  ['dmzsw', 'web', 'Fa0/1', 'Eth0', 'normal'],
  ['dmzsw', 'ftp', 'Fa0/2', 'Eth0', 'normal'],
  ['fw', 'core', 'Gi0/3', 'Gi1/0/1', 'normal'],
  ['core', 'dc', 'Fa0/1', 'Eth0', 'normal'],
  ['core', 'win1', 'Fa0/2', 'Eth0', 'normal'],
  ['core', 'win2', 'Fa0/3', 'Eth0', 'normal'],
  ['core', 'ids', 'SPAN1', 'MON0', 'log'],
  ['ids', 'siem', 'E1', 'E1', 'log'],
];

const scenarios = [
  ['ftp_bruteforce', 'FTP Bruteforce', 'Repeated login attempts from Kali to FTP service in DMZ.', ['internet', 'fw', 'dmzsw', 'ftp']],
  ['ssh_bruteforce', 'SSH Bruteforce', 'High-volume SSH auth attempts to Linux host.', ['internet', 'fw', 'dmzsw', 'web']],
  ['dos_hulk', 'DoS Hulk', 'Burst flood saturates firewall and target web server.', ['internet', 'fw', 'dmzsw', 'web']],
  ['slowloris', 'Slowloris', 'Long-lived partial requests to exhaust server sockets.', ['internet', 'fw', 'dmzsw', 'web']],
  ['heartleech', 'Heartleech', 'Memory-leak style exploitation pattern over TLS.', ['internet', 'fw', 'dmzsw', 'web']],
  ['dvwa_xss', 'DVWA XSS', 'Web payload delivery and browser callback pattern.', ['internet', 'fw', 'dmzsw', 'web', 'win1']],
  ['ddos_portscan', 'DDoS + PortScan', 'Parallel service scan with flood stream.', ['internet', 'fw', 'dmzsw', 'web']],
  ['botnet_c2', 'Botnet C2', 'Internal host beaconing to C2 over suspicious intervals.', ['win2', 'core', 'fw', 'internet']],
  ['infiltration', 'Infiltration', 'Multi-stage lateral movement across LAN and AD.', ['internet', 'fw', 'core', 'win1', 'dc']],
].map(([id, name, desc, path]) => ({ id, name, desc, path }));

const zoneColors = { internet: '#6aa4ff', dmz: '#58efff', lan: '#5dfd9d', monitor: '#ffb45e' };
const linkColors = { normal: '#5dfd9d', attack: '#ff5c8f', anomaly: '#ffb45e', log: '#6aa4ff' };

const el = {
  status: document.getElementById('simulationStatus'),
  flows: document.getElementById('flowsMetric'),
  anomaly: document.getElementById('anomalyMetric'),
  confidence: document.getElementById('confidenceMetric'),
  speed: document.getElementById('speed'),
  start: document.getElementById('startBtn'),
  stop: document.getElementById('stopBtn'),
  reset: document.getElementById('resetBtn'),
  scenarioButtons: document.getElementById('scenarioButtons'),
  scenarioDesc: document.getElementById('scenarioDescription'),
  pipeline: document.getElementById('pipelineLog'),
  alerts: document.getElementById('alertFeed'),
};

function create(tag, attrs = {}) {
  const n = document.createElementNS('http://www.w3.org/2000/svg', tag);
  Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
  return n;
}

function drawTopology() {
  svg.innerHTML = '';
  ['internet', 'dmz', 'lan', 'monitor'].forEach((zone, i) => {
    const x = 30 + i * 390;
    const rect = create('rect', { x, y: 40, width: 350, height: 790, rx: 18, fill: 'rgba(11,18,36,0.45)', stroke: zoneColors[zone], 'stroke-opacity': '.35' });
    svg.append(rect);
    const t = create('text', { x: x + 16, y: 70, fill: zoneColors[zone], 'font-size': '16', 'font-family': 'monospace' });
    t.textContent = `${zone.toUpperCase()} ZONE`;
    svg.append(t);
  });

  links.forEach(([a, b, pa, pb, kind]) => {
    const p1 = byId[a], p2 = byId[b];
    const line = create('line', { x1: p1.x, y1: p1.y, x2: p2.x, y2: p2.y, stroke: linkColors[kind], 'stroke-opacity': '.5', 'stroke-width': '3' });
    svg.append(line);

    const label = create('text', { x: (p1.x + p2.x) / 2, y: (p1.y + p2.y) / 2 - 10, fill: '#85a6cf', 'font-size': '10' });
    label.textContent = `${pa} ↔ ${pb}`;
    svg.append(label);
  });

  devices.forEach((d) => {
    const g = create('g', { transform: `translate(${d.x},${d.y})` });
    const body = create('rect', { x: -55, y: -30, width: 110, height: 60, rx: 12, fill: '#0e1b35', stroke: zoneColors[d.zone], 'stroke-width': '1.5' });
    const led = create('circle', { cx: 45, cy: -19, r: 4, fill: '#5dfd9d' });
    const type = create('text', { x: -48, y: -12, fill: '#6aa4ff', 'font-size': '10' }); type.textContent = d.type.toUpperCase();
    const lbl = create('text', { x: -48, y: 9, fill: '#d8ecff', 'font-size': '12' }); lbl.textContent = d.label;
    g.append(body, led, type, lbl);
    svg.append(g);
  });
}

function emitPipeline(step, confidence = state.metrics.confidence) {
  state.pipeline.unshift({ step, ts: new Date().toLocaleTimeString(), confidence });
  state.pipeline = state.pipeline.slice(0, 12);
  el.pipeline.innerHTML = state.pipeline.map((p) => `<li>${p.ts} · ${p.step} <strong>${Math.round(p.confidence)}%</strong></li>`).join('');
}

function pushAlert(severity, title, detail) {
  state.alerts.unshift({ severity, title, detail, ts: new Date().toLocaleTimeString() });
  state.alerts = state.alerts.slice(0, 20);
  el.alerts.innerHTML = state.alerts.map((a) => `<li class="alert-${a.severity}"><strong>${a.severity.toUpperCase()}</strong> ${a.ts}<br/>${a.title}<br/><span style="color:#85a6cf">${a.detail}</span></li>`).join('');
}

function spawnPackets(path, isAttack = true) {
  for (let i = 0; i < 10; i++) {
    state.packets.push({ path, progress: -i * 0.09, speed: (0.0025 + Math.random() * 0.0035) * state.speed, attack: isAttack });
  }
}

function lerp(a, b, t) { return a + (b - a) * t; }
function pointOnPath(path, t) {
  const segments = path.length - 1;
  const idx = Math.min(Math.floor(t * segments), segments - 1);
  const lt = (t * segments) - idx;
  const p1 = byId[path[idx]], p2 = byId[path[idx + 1]];
  return { x: lerp(p1.x, p2.x, lt), y: lerp(p1.y, p2.y, lt) };
}

function drawPackets() {
  svg.querySelectorAll('.packet').forEach((p) => p.remove());
  state.packets.forEach((p) => {
    if (p.progress < 0) return;
    const pos = pointOnPath(p.path, Math.min(1, p.progress));
    const c = create('circle', {
      class: 'packet', cx: pos.x, cy: pos.y, r: 4.5,
      fill: p.attack ? '#ff5c8f' : '#6aa4ff',
      'fill-opacity': '.9',
    });
    svg.append(c);
  });
}

function tick() {
  if (!state.running) return;
  state.packets.forEach((p) => (p.progress += p.speed));
  const arrived = state.packets.filter((p) => p.progress >= 1).length;
  state.packets = state.packets.filter((p) => p.progress < 1.15);
  if (arrived > 0) {
    state.metrics.flows += arrived * 3;
    state.metrics.anomaly = Math.min(100, state.metrics.anomaly + arrived * 0.8);
    state.metrics.confidence = Math.min(99, state.metrics.confidence + arrived * 0.55);
    emitPipeline('CICFlowMeter transformed packet stream to flow records', state.metrics.confidence);
    emitPipeline('Layer1 anomaly score crossed threshold, escalating to classification', state.metrics.confidence);
    emitPipeline('Layer2 inferred attack signature family and confidence', state.metrics.confidence);
    if (Math.random() > 0.55) pushAlert('high', `Threat detected: ${state.selectedScenario.name}`, 'MITRE ATT&CK mapped · correlation with Windows EventID 4625');
  }
  el.flows.textContent = String(Math.round(state.metrics.flows));
  el.anomaly.textContent = `${Math.round(state.metrics.anomaly)}%`;
  el.confidence.textContent = `${Math.round(state.metrics.confidence)}%`;
  drawPackets();
  requestAnimationFrame(tick);
}

function runScenario() {
  if (!state.selectedScenario) return;
  state.running = true;
  el.status.textContent = `Running · ${state.selectedScenario.name}`;
  emitPipeline(`Scenario initialized: ${state.selectedScenario.name}`);
  const basePath = state.selectedScenario.path;
  spawnPackets(basePath, true);
  spawnPackets(['core', 'ids', 'siem'], false);
  const periodic = setInterval(() => {
    if (!state.running) return clearInterval(periodic);
    spawnPackets(basePath, true);
    spawnPackets(['win1', 'core', 'ids', 'siem'], false);
    emitPipeline('Windows EVTX parsed and correlated with network telemetry', state.metrics.confidence);
    if (state.metrics.confidence > 82) pushAlert('med', 'Correlation escalation', 'Network + endpoint evidence linked by IP/timestamp proximity');
  }, 1400 / state.speed);
  tick();
}

function stopScenario() { state.running = false; el.status.textContent = 'Stopped'; }
function resetScenario() {
  state.running = false;
  state.packets = [];
  state.alerts = [];
  state.pipeline = [];
  state.metrics = { flows: 0, anomaly: 0, confidence: 0 };
  el.status.textContent = 'Idle';
  el.alerts.innerHTML = '';
  el.pipeline.innerHTML = '';
  el.flows.textContent = '0';
  el.anomaly.textContent = '0%';
  el.confidence.textContent = '0%';
  drawTopology();
}

function renderScenarioButtons() {
  el.scenarioButtons.innerHTML = '';
  scenarios.forEach((s) => {
    const b = document.createElement('button');
    b.className = 'scenario-btn';
    b.textContent = s.name;
    b.onclick = () => {
      state.selectedScenario = s;
      [...el.scenarioButtons.children].forEach((c) => c.classList.remove('active'));
      b.classList.add('active');
      el.scenarioDesc.textContent = s.desc;
      emitPipeline(`Scenario selected: ${s.name}`);
    };
    el.scenarioButtons.append(b);
  });
}

el.speed.oninput = (e) => { state.speed = Number(e.target.value); };
el.start.onclick = runScenario;
el.stop.onclick = stopScenario;
el.reset.onclick = resetScenario;

drawTopology();
renderScenarioButtons();
emitPipeline('Dashboard initialized. Awaiting operator action.', 0);
