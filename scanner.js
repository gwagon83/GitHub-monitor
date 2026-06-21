require("dotenv").config();

const axios = require("axios");
const pool = require("./db");
const sendTelegram = require("./telegram");

// =========================
// CONFIG
// =========================

const ALERT_THRESHOLD = 25;
const HIGH_CONFIDENCE_THRESHOLD = 35;

const MAX_FILE_SIZE = 800000;
const BASE_SLEEP = 4000;

const SEARCH_COOLDOWN = 15 * 1000; // per keyword throttle
const ALERT_COOLDOWN = 6 * 60 * 60 * 1000;

// =========================
// STATE
// =========================

const processedUrls = new Set();
const repoCache = new Map();
const alertedRepos = new Map();

// 🔥 NEW: search rate-limit + duplication control
const keywordLastRun = new Map();
const keywordCursorCache = new Map();

// =========================
// HELPERS
// =========================

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function buildRepoUrl(repoName) {
  return `https://github.com/${repoName}`;
}

function getRiskBadge(score) {
  if (score >= 35) return "🔴 CONFIRMED DRAINER";
  if (score >= 25) return "🟠 HIGH RISK";
  if (score >= 15) return "🟡 SUSPICIOUS";
  return "🟢 LOW RISK";
}

// =========================
// KEYWORDS
// =========================

const KEYWORDS = [...new Set([
  "wallet drainer",
  "crypto drainer",
  "wallet connect phishing",
  "seed phrase",
  "recovery phrase",
  "import wallet",
  "restore wallet",
  "connect wallet",
  "claim airdrop",
  "walletconnect",
  "wagmi",
  "setapprovalforall",
  "permit2",
  "personal_sign"
])];

// =========================
// PATTERNS
// =========================

const SECRET_PATTERNS = [
  { name: "Seed Phrase", regex: /(seed phrase|recovery phrase|mnemonic)/gi, severity: "critical" },
  { name: "Wallet Input Theft", regex: /(enter|input|paste).{0,40}(seed|phrase)/gi, severity: "critical" },
  { name: "Approval Abuse", regex: /setApprovalForAll|increaseAllowance/gi, severity: "high" },
  { name: "Signature Abuse", regex: /eth_signTypedData|personal_sign/gi, severity: "medium" },
  { name: "Drain Logic", regex: /(drain wallet|sweep wallet|transfer all balance)/gi, severity: "critical" },
  { name: "Webhook Exfiltration", regex: /discord|telegram\.org\/bot|webhook/i, severity: "critical" }
];

// =========================
// BEHAVIOR PATTERNS
// =========================

const BEHAVIOR_PATTERNS = [
  { regex: /(approve|setApprovalForAll).{0,80}(transfer|drain|sweep)/gi, weight: 12 },
  { regex: /(sign|signature).{0,80}(claim|verify|reward|airdrop)/gi, weight: 10 },
  { regex: /(connect wallet).{0,50}(claim|mint|verify)/gi, weight: 9 },
  { regex: /(transferFrom|send max|drain wallet)/gi, weight: 15 }
];

// =========================
// NOISE FILTER
// =========================

function shouldSkipFile(item) {
  const path = (item.path || "").toLowerCase();

  return (
    path.endsWith(".md") ||
    path.includes("readme") ||
    path.includes("license") ||
    path.includes("/docs/") ||
    path.includes("/example/") ||
    path.includes(".map") ||
    path.includes("package-lock.json")
  );
}

// =========================
// SIGNAL ENGINE
// =========================

function extractSignals(content) {
  let signalScore = 0;
  let behaviorScore = 0;
  let legitPenalty = 0;

  for (const p of SECRET_PATTERNS) {
    if (p.regex.test(content)) signalScore += 10;
  }

  for (const b of BEHAVIOR_PATTERNS) {
    if (b.regex.test(content)) behaviorScore += b.weight;
  }

  return { signalScore, behaviorScore, legitPenalty };
}

// =========================
// REPO AGGREGATION
// =========================

function updateRepo(repoName, data) {
  if (!repoCache.has(repoName)) {
    repoCache.set(repoName, {
      signalScore: 0,
      behaviorScore: 0,
      legitPenalty: 0,
      files: 0
    });
  }

  const repo = repoCache.get(repoName);

  repo.signalScore += data.signalScore;
  repo.behaviorScore += data.behaviorScore;
  repo.legitPenalty += data.legitPenalty;
  repo.files++;

  repoCache.set(repoName, repo);
}

// =========================
// SCORE
// =========================

function computeRepoScore(repo) {
  return repo.signalScore + repo.behaviorScore * 1.5 - repo.legitPenalty;
}

// =========================
// RATE LIMIT SAFE SEARCH
// =========================

async function searchKeyword(keyword) {
  const now = Date.now();

  // 🔥 per-keyword cooldown
  if (keywordLastRun.has(keyword)) {
    const last = keywordLastRun.get(keyword);
    if (now - last < SEARCH_COOLDOWN) {
      return [];
    }
  }

  keywordLastRun.set(keyword, now);

  const cursor = keywordCursorCache.get(keyword) || 0;

  const url =
    `https://api.github.com/search/code?q=${encodeURIComponent(keyword)}+in:file&per_page=20&page=${cursor + 1}`;

  try {
    const res = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        "User-Agent": "soc-scanner"
      }
    });

    // rotate page cursor (prevents same 30 results loop)
    keywordCursorCache.set(keyword, cursor >= 5 ? 0 : cursor + 1);

    return res.data?.items || [];
  } catch (err) {
    const status = err?.response?.status;

    // 🔥 429 HANDLING
    if (status === 429) {
      const reset = err.response?.headers?.["x-ratelimit-reset"];

      let waitTime = 60 * 1000;

      if (reset) {
        waitTime = Math.max(0, reset * 1000 - Date.now());
      }

      console.log(`⏳ Rate limited. sleeping ${waitTime}ms`);
      await sleep(waitTime);
      return [];
    }

    return [];
  }
}

// =========================
// FETCH FILE
// =========================

async function fetchFile(item) {
  try {
    const url = item.html_url
      .replace("github.com", "raw.githubusercontent.com")
      .replace("/blob/", "/");

    const res = await axios.get(url, {
      maxContentLength: MAX_FILE_SIZE
    });

    return res.data;
  } catch {
    return null;
  }
}

// =========================
// PROCESS
// =========================

async function processKeyword(keyword) {
  const results = await searchKeyword(keyword);

  for (const item of results) {
    try {
      const repoName = item.repository.full_name;
      const hash = `${repoName}:${item.path}`;

      if (processedUrls.has(hash)) continue;
      if (shouldSkipFile(item)) continue;

      const content = await fetchFile(item);
      if (!content) continue;

      const signals = extractSignals(content);

      updateRepo(repoName, signals);

      processedUrls.add(hash);
    } catch (e) {}
  }
}

// =========================
// EVALUATION
// =========================

async function evaluateRepos() {
  const now = Date.now();

  for (const [repoName, repo] of repoCache.entries()) {

    const score = computeRepoScore(repo);
    const repoUrl = buildRepoUrl(repoName);
    const risk = getRiskBadge(score);

    if (alertedRepos.has(repoName)) {
      const last = alertedRepos.get(repoName);
      if (now - last < ALERT_COOLDOWN) {
        continue;
      }
    }

    if (score < ALERT_THRESHOLD) continue;

    alertedRepos.set(repoName, now);

    await pool.query(
      `INSERT INTO findings (keyword, repo_name, file_path, html_url, score, severity)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT DO NOTHING`,
      ["repo-analysis", repoName, null, repoUrl, score, risk]
    );

    await sendTelegram(
`🚨 SOC POLLING INTELLIGENCE CARD

━━━━━━━━━━━━━━━━━━
${risk}
━━━━━━━━━━━━━━━━━━

📦 Repo: ${repoName}
🔗 ${repoUrl}

📊 Score: ${score.toFixed(2)}
📁 Files: ${repo.files}

🧬 Signal: ${repo.signalScore}
⚙️ Behavior: ${repo.behaviorScore}

━━━━━━━━━━━━━━━━━━`
    );

    console.log("🚨 ALERT:", repoName);
  }
}

// =========================
// CYCLE ROTATION FIX
// =========================

async function runCycle() {
  console.log("🔄 Scan cycle started");

  processedUrls.clear();
  repoCache.clear();

  // rotate keyword order each cycle (prevents same results)
  const rotated = KEYWORDS
    .slice(Math.floor(Math.random() * KEYWORDS.length))
    .concat(KEYWORDS.slice(0, Math.floor(Math.random() * KEYWORDS.length)));

  for (const keyword of rotated) {
    await processKeyword(keyword);
    await sleep(BASE_SLEEP + Math.random() * 2000);
  }

  await evaluateRepos();

  console.log("✅ Cycle complete");
}

// =========================
// WORKER
// =========================

async function startWorker() {
  console.log("🚀 SOC Polling Scanner started");

  while (true) {
    try {
      await runCycle();
      await sleep(10 * 60 * 1000);
    } catch (e) {
      console.error("Worker crash:", e.message);
      await sleep(5000);
    }
  }
}

startWorker();
