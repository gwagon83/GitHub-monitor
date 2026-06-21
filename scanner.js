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
const BASE_SLEEP = 3500;

const ALERT_COOLDOWN = 6 * 60 * 60 * 1000;
const REPO_MEMORY_TTL = 45 * 60 * 1000; // 🔥 prevents repeats for 45 min

// =========================
// STATE
// =========================

const processedFiles = new Set();
const repoCache = new Map();
const alertedRepos = new Map();
const repoSeenAt = new Map();

// =========================
// HELPERS
// =========================

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function buildRepoUrl(repo) {
  return `https://github.com/${repo}`;
}

function getRiskBadge(score) {
  if (score >= 35) return "🔴 CONFIRMED DRAINER";
  if (score >= 25) return "🟠 HIGH RISK";
  if (score >= 15) return "🟡 SUSPICIOUS";
  return "🟢 LOW RISK";
}

// =========================
// KEYWORDS BASE
// =========================

const BASE_KEYWORDS = [
  "wallet drainer",
  "crypto drainer",
  "seed phrase",
  "recovery phrase",
  "walletconnect",
  "wagmi",
  "setApprovalForAll",
  "permit2",
  "personal_sign"
];

// =========================
// QUERY MUTATION ENGINE (🔥 FIX #1)
// =========================

function buildQueries() {
  const modifiers = [
    "",
    "language:javascript",
    "language:typescript",
    "extension:js",
    "extension:ts",
    "wallet connect",
    "airdrop claim",
    "mint nft"
  ];

  const queries = [];

  for (const k of BASE_KEYWORDS) {
    for (const m of modifiers) {
      queries.push(`${k} ${m}`.trim());
    }
  }

  return queries;
}

// =========================
// PATTERNS
// =========================

const SECRET_PATTERNS = [
  { regex: /(seed phrase|recovery phrase|mnemonic)/gi, weight: 10 },
  { regex: /(enter|input|paste).{0,40}(seed|phrase)/gi, weight: 12 },
  { regex: /setApprovalForAll|increaseAllowance/gi, weight: 8 },
  { regex: /eth_signTypedData|personal_sign/gi, weight: 6 },
  { regex: /(drain wallet|sweep wallet|transfer all balance)/gi, weight: 15 },
  { regex: /discord|telegram\.org\/bot|webhook/i, weight: 10 }
];

const BEHAVIOR_PATTERNS = [
  { regex: /(approve|setApprovalForAll).{0,80}(drain|transfer)/gi, weight: 12 },
  { regex: /(sign|signature).{0,60}(claim|airdrop|mint)/gi, weight: 10 },
  { regex: /(connect wallet).{0,40}(claim|verify|mint)/gi, weight: 9 }
];

// =========================
// SIGNAL ENGINE
// =========================

function extractSignals(content) {
  let score = 0;
  let behavior = 0;

  for (const p of SECRET_PATTERNS) {
    if (p.regex.test(content)) score += p.weight;
  }

  for (const b of BEHAVIOR_PATTERNS) {
    if (b.regex.test(content)) behavior += b.weight;
  }

  return {
    signalScore: score,
    behaviorScore: behavior,
    legitPenalty: 0
  };
}

// =========================
// REPO STORAGE
// =========================

function updateRepo(repo, data) {
  if (!repoCache.has(repo)) {
    repoCache.set(repo, {
      signalScore: 0,
      behaviorScore: 0,
      files: 0
    });
  }

  const r = repoCache.get(repo);
  r.signalScore += data.signalScore;
  r.behaviorScore += data.behaviorScore;
  r.files += 1;
}

// =========================
// GITHUB SEARCH (FIXED)
// =========================

async function searchGitHub(query) {
  try {
    const url =
      `https://api.github.com/search/code?q=${encodeURIComponent(query)}&per_page=30`;

    const res = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        "User-Agent": "soc-scanner"
      }
    });

    return res.data?.items || [];
  } catch (e) {
    return [];
  }
}

// =========================
// FILE FETCH
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

async function processQuery(query) {
  const results = await searchGitHub(query);

  for (const item of results) {
    const repo = item.repository.full_name;
    const fileKey = `${repo}:${item.path}`;

    if (processedFiles.has(fileKey)) continue;

    // 🔥 repo cooldown filter
    const lastSeen = repoSeenAt.get(repo);
    if (lastSeen && Date.now() - lastSeen < REPO_MEMORY_TTL) continue;

    const content = await fetchFile(item);
    if (!content) continue;

    const signals = extractSignals(content);

    updateRepo(repo, signals);
    processedFiles.add(fileKey);
    repoSeenAt.set(repo, Date.now());
  }
}

// =========================
// EVALUATION
// =========================

async function evaluate() {
  for (const [repo, data] of repoCache.entries()) {

    const score = data.signalScore + data.behaviorScore * 1.5;
    const risk = getRiskBadge(score);
    const url = buildRepoUrl(repo);

    if (score < ALERT_THRESHOLD) continue;

    if (alertedRepos.has(repo)) {
      if (Date.now() - alertedRepos.get(repo) < ALERT_COOLDOWN) continue;
    }

    alertedRepos.set(repo, Date.now());

    await pool.query(
      `INSERT INTO findings (keyword, repo_name, file_path, html_url, score, severity)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT DO NOTHING`,
      ["repo-analysis", repo, null, url, score, risk]
    );

    await sendTelegram(
`🚨 SOC INTELLIGENCE CARD
━━━━━━━━━━━━━━━━━━
${risk}

Repo: ${repo}
${url}

Score: ${score.toFixed(2)}
Files: ${data.files}
Signal: ${data.signalScore}
Behavior: ${data.behaviorScore}
━━━━━━━━━━━━━━━━━━`
    );

    console.log("🚨 ALERT:", repo);
  }
}

// =========================
// CYCLE
// =========================

async function runCycle() {
  console.log("🔄 Scan cycle started");

  const queries = buildQueries();

  processedFiles.clear();
  repoCache.clear();

  // 🔥 shuffle queries every cycle
  for (let i = queries.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [queries[i], queries[j]] = [queries[j], queries[i]];
  }

  for (const q of queries) {
    await processQuery(q);
    await sleep(2500 + Math.random() * 1500);
  }

  await evaluate();

  console.log("✅ Cycle complete");
}

// =========================
// WORKER
// =========================

async function start() {
  console.log("🚀 SOC Polling Scanner started");

  while (true) {
    try {
      await runCycle();
      await sleep(8 * 60 * 1000);
    } catch (e) {
      console.error("Worker crash:", e.message);
      await sleep(5000);
    }
  }
}

start();
