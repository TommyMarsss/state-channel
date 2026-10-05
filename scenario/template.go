package scenario

// pageTemplate 是回放页的完整模板。/*__DATA__*/ 会被事件 JSON 替换。
// 全部样式与脚本内联，不引用任何外部资源。
const pageTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>状态通道交互回放</title>
<style>
  :root {
    --bg: #0f1420; --panel: #1a2130; --panel2: #212a3d; --line: #2e3a52;
    --text: #e6ebf4; --dim: #93a0b8; --accent: #5b9dff;
    --ok: #3fb96f; --warn: #e0a93e; --bad: #e05e5e; --good: #4fc3a1; --settle: #9a7ff0;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, "PingFang SC", "Helvetica Neue", sans-serif; padding: 24px 16px 64px; }
  main { max-width: 960px; margin: 0 auto; }
  h1 { font-size: 22px; }
  .sub { color: var(--dim); font-size: 13px; margin-top: 6px; }
  .controls { display: flex; align-items: center; gap: 10px; margin: 20px 0 14px; flex-wrap: wrap; }
  button { background: var(--panel2); color: var(--text); border: 1px solid var(--line); border-radius: 8px; padding: 8px 16px; font-size: 14px; cursor: pointer; }
  button:hover:not(:disabled) { border-color: var(--accent); }
  button:disabled { opacity: 0.35; cursor: default; }
  #step-label { color: var(--dim); font-size: 13px; min-width: 90px; text-align: center; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 18px 20px; }
  #event-card { border-left: 5px solid var(--accent); transition: border-color .2s; }
  #event-card.k-open { border-left-color: var(--accent); }
  #event-card.k-update { border-left-color: var(--ok); }
  #event-card.k-dispute { border-left-color: var(--warn); }
  #event-card.k-challenge { border-left-color: var(--good); }
  #event-card.k-settle { border-left-color: var(--settle); }
  #event-card.k-bad { border-left-color: var(--bad); background: #241a20; }
  .badge { display: inline-block; font-size: 12px; padding: 2px 10px; border-radius: 20px; margin-right: 8px; vertical-align: middle; }
  .b-open { background: #1d2f4d; color: var(--accent); }
  .b-update { background: #14301f; color: var(--ok); }
  .b-dispute { background: #33270f; color: var(--warn); }
  .b-challenge { background: #0f2f28; color: var(--good); }
  .b-settle { background: #2a2145; color: var(--settle); }
  .b-bad { background: #3a1c1c; color: var(--bad); }
  .ev-title { font-size: 17px; font-weight: 600; margin: 10px 0 8px; }
  .ev-note { color: var(--dim); font-size: 13.5px; line-height: 1.7; }
  .ev-meta { margin-top: 12px; display: flex; gap: 18px; flex-wrap: wrap; font-size: 13px; color: var(--dim); }
  .ev-meta b { color: var(--text); font-weight: 600; }
  .sig { font-size: 12px; padding: 2px 8px; border-radius: 4px; }
  .sig.ok { background: #14301f; color: var(--ok); }
  .sig.no { background: #3a1c1c; color: var(--bad); }
  .panels { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin-top: 14px; }
  @media (max-width: 720px) { .panels { grid-template-columns: 1fr; } }
  .panel h3 { font-size: 13px; color: var(--dim); font-weight: 600; margin-bottom: 10px; }
  .panel .ver { font-size: 24px; font-weight: 700; }
  .bar { height: 10px; border-radius: 5px; overflow: hidden; display: flex; margin: 10px 0 6px; background: var(--panel2); }
  .bar .a { background: var(--accent); }
  .bar .b { background: var(--good); }
  .bal { font-size: 12.5px; color: var(--dim); display: flex; justify-content: space-between; }
  .chain-status { font-size: 15px; font-weight: 600; }
  .chain-status.dispute { color: var(--warn); }
  .chain-status.settled { color: var(--settle); }
  .chain-status.idle { color: var(--ok); }
  .chain-detail { font-size: 12.5px; color: var(--dim); margin-top: 8px; line-height: 1.8; }
  #timeline { margin-top: 22px; }
  #timeline h2 { font-size: 14px; color: var(--dim); margin-bottom: 10px; }
  .tl-item { display: flex; gap: 10px; align-items: baseline; padding: 7px 10px; border-radius: 8px; cursor: pointer; font-size: 13px; border: 1px solid transparent; }
  .tl-item:hover { background: var(--panel); }
  .tl-item.current { background: var(--panel); border-color: var(--line); }
  .tl-seq { color: var(--dim); width: 22px; text-align: right; flex: none; }
  .tl-dot { width: 8px; height: 8px; border-radius: 50%; flex: none; align-self: center; }
  .d-open { background: var(--accent); } .d-update { background: var(--ok); }
  .d-dispute { background: var(--warn); } .d-challenge { background: var(--good); }
  .d-settle { background: var(--settle); } .d-bad { background: var(--bad); }
  .tl-title { flex: 1; }
  .tl-clock { color: var(--dim); font-size: 12px; }
</style>
</head>
<body>
<main>
  <h1>双方链下状态通道 · 交互回放</h1>
  <p class="sub">链下交换双签状态更新账本（版本号严格递增），争议时才上链仲裁：更高版本的双签状态胜出，争议期内的欺诈证明可推翻旧状态，过期反驳与伪造签名一律拒绝。</p>

  <div class="controls">
    <button id="btn-prev">&larr; 上一步</button>
    <span id="step-label"></span>
    <button id="btn-next">下一步 &rarr;</button>
    <button id="btn-play">&#9654; 播放</button>
  </div>

  <div class="card" id="event-card">
    <div><span class="badge" id="ev-badge"></span><span id="ev-actor" style="color:var(--dim);font-size:13px"></span></div>
    <div class="ev-title" id="ev-title"></div>
    <div class="ev-note" id="ev-note"></div>
    <div class="ev-meta" id="ev-meta"></div>
  </div>

  <div class="panels">
    <div class="card panel" id="panel-alice"></div>
    <div class="card panel" id="panel-chain"></div>
    <div class="card panel" id="panel-bob"></div>
  </div>

  <div id="timeline"><h2>事件时间线（点击跳转）</h2><div id="tl-list"></div></div>
</main>

<script>
const EVENTS = /*__DATA__*/;
const KIND_LABEL = {
  "open": "开通通道", "update": "链下更新", "dispute": "链上争议",
  "challenge": "欺诈证明", "settle": "链上结算",
  "replay-rejected": "重放被拒", "forgery-rejected": "伪造被拒", "challenge-rejected": "过期反驳被拒"
};
const BAD_KINDS = ["replay-rejected", "forgery-rejected", "challenge-rejected"];
let cur = 0, timer = null;

function kindClass(k) { return BAD_KINDS.indexOf(k) >= 0 ? "bad" : k; }
function el(id) { return document.getElementById(id); }
function esc(s) { const d = document.createElement("div"); d.textContent = s; return d.innerHTML; }

function sigBadge(name, ok) {
  return '<span class="sig ' + (ok ? "ok" : "no") + '">' + name + " 签名 " + (ok ? "✓" : "✗ 无效") + "</span>";
}

function partyPanel(id, title, held, color) {
  const total = held.balanceA + held.balanceB || 1;
  const wa = (held.balanceA / total * 100).toFixed(1);
  const wb = (held.balanceB / total * 100).toFixed(1);
  el(id).innerHTML =
    "<h3>" + title + "</h3>" +
    '<div class="ver">v' + held.version + "</div>" +
    '<div class="bar"><div class="a" style="width:' + wa + '%"></div><div class="b" style="width:' + wb + '%"></div></div>' +
    '<div class="bal"><span>Alice: ' + held.balanceA + "</span><span>Bob: " + held.balanceB + "</span></div>";
}

function chainPanel(c) {
  let cls = "idle", status = "无争议（链下运行中）", detail = "链上合约空闲，双方继续链下交换签名状态。";
  if (c.status === "争议中") {
    cls = "dispute"; status = "争议中";
    detail = "候选结算状态：<b>v" + c.candidateVersion + " (" + c.candidateBalA + "/" + c.candidateBalB + ")</b><br>" +
             "争议期截止：<b>" + esc(c.deadline) + "</b><br>期内可提交更高版本的双签状态反驳。";
  } else if (c.status === "已结算") {
    cls = "settled"; status = "已结算";
    detail = "最终账本版本：<b>v" + c.finalVersion + "</b><br>通道关闭，资金按最终账本分配。";
  }
  el("panel-chain").innerHTML =
    "<h3>链上仲裁器</h3>" +
    '<div class="chain-status ' + cls + '">' + status + "</div>" +
    '<div class="chain-detail">' + detail + "</div>";
}

function render() {
  const ev = EVENTS[cur];
  const kc = kindClass(ev.kind);
  el("event-card").className = "card k-" + kc;
  el("ev-badge").className = "badge b-" + kc;
  el("ev-badge").textContent = KIND_LABEL[ev.kind] || ev.kind;
  el("ev-actor").textContent = "发起方：" + ev.actor + "　·　" + ev.clock;
  el("ev-title").textContent = ev.title;
  el("ev-note").textContent = ev.note;

  let meta = "";
  if (ev.version >= 0) {
    meta += "<span>涉及状态：<b>v" + ev.version + " (" + ev.balanceA + "/" + ev.balanceB + ")</b></span>";
    meta += "<span>" + sigBadge("Alice", ev.sigAOK) + " " + sigBadge("Bob", ev.sigBOK) + "</span>";
  }
  el("ev-meta").innerHTML = meta;

  partyPanel("panel-alice", "Alice 持有的最新双签状态", ev.alice);
  partyPanel("panel-bob", "Bob 持有的最新双签状态", ev.bob);
  chainPanel(ev.chain);

  el("step-label").textContent = (cur + 1) + " / " + EVENTS.length;
  el("btn-prev").disabled = cur === 0;
  el("btn-next").disabled = cur === EVENTS.length - 1;

  const items = document.querySelectorAll(".tl-item");
  items.forEach(function(it, i) { it.classList.toggle("current", i === cur); });
  const curItem = items[cur];
  if (curItem) curItem.scrollIntoView({ block: "nearest" });
}

function buildTimeline() {
  const list = el("tl-list");
  EVENTS.forEach(function(ev, i) {
    const div = document.createElement("div");
    div.className = "tl-item";
    div.innerHTML = '<span class="tl-seq">' + (i + 1) + "</span>" +
      '<span class="tl-dot d-' + kindClass(ev.kind) + '"></span>' +
      '<span class="tl-title">' + esc(ev.title) + "</span>" +
      '<span class="tl-clock">' + esc(ev.clock) + "</span>";
    div.addEventListener("click", function() { stop(); cur = i; render(); });
    list.appendChild(div);
  });
}

function next() { if (cur < EVENTS.length - 1) { cur++; render(); } else { stop(); } }
function prev() { if (cur > 0) { cur--; render(); } }
function stop() { if (timer) { clearInterval(timer); timer = null; el("btn-play").innerHTML = "&#9654; 播放"; } }

el("btn-next").addEventListener("click", function() { stop(); next(); });
el("btn-prev").addEventListener("click", function() { stop(); prev(); });
el("btn-play").addEventListener("click", function() {
  if (timer) { stop(); return; }
  if (cur === EVENTS.length - 1) { cur = 0; render(); }
  el("btn-play").innerHTML = "&#10074;&#10074; 暂停";
  timer = setInterval(next, 2200);
});
document.addEventListener("keydown", function(e) {
  if (e.key === "ArrowRight") { stop(); next(); }
  if (e.key === "ArrowLeft") { stop(); prev(); }
});

buildTimeline();
render();
</script>
</body>
</html>
`
