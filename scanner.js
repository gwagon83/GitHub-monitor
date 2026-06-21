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
const BASE_SLEEP = 5000;

const ALERT_COOLDOWN = 6 * 60 * 60 * 1000; // 6 hours

// =========================
// STATE CACHE
// =========================

const processedUrls = new Set();
const repoCache = new Map();
const alertedRepos = new Map(); // 🔥 FIX: prevents repeat alerts across cycles

// =========================
// WEIGHTS
// =========================

const WEIGHTS = {
  low: 1,
  medium: 3,
  high: 7,
  critical: 15,
};

// =========================
// HELPERS
// =========================

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
  "wallet connect scam",
  "seed phrase",
  "recovery phrase",
  "mnemonic phrase",
  "import wallet",
  "restore wallet",
  "connect wallet",
  "wallet verification",
  "claim airdrop",
  "claim rewards",
  "free mint",
  "walletconnect",
  "wagmi",
  "ethers.js",
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
// LEGIT FILTER
// =========================

const LEGIT_CONTEXT = [
  /next\.js|react|vite|nuxt/i,
  /hardhat|foundry|ethers\.js|wagmi/i,
  /openzeppelin|uniswap|aave/i,
  /tutorial|example|template|docs/i
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
    if (p.regex.test(content)) signalScore += WEIGHTS[p.severity] || 0;
  }

  for (const b of BEHAVIOR_PATTERNS) {
    if (b.regex.test(content)) behaviorScore += b.weight;
  }

  for (const l of LEGIT_CONTEXT) {
    if (l.test(content)) legitPenalty += 8;
  }

  return { signalScore, behaviorScore, legitPenalty };
}

// =========================
// REPO AGGREGATOR
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
  repo.files += 1;

  repoCache.set(repoName, repo);
}

// =========================
// SCORE MODEL
// =========================

function computeRepoScore(repo) {
  let score =
    repo.signalScore +
    repo.behaviorScore * 1.5 -
    repo.legitPenalty;

  if (repo.behaviorScore > 20 && repo.signalScore > 10) {
    score += 10;
  }

  return score;
}

// =========================
// GITHUB SEARCH
// =========================

async function searchKeyword(keyword) {
  const url = `https://api.github.com/search/code?q=${encodeURIComponent(keyword)}+in:file&per_page=30&sort=indexed`;

  try {
    const res = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        "User-Agent": "org-scanner"
      }
    });

    return res.data?.items || [];
  } catch {
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

    } catch (err) {
      console.error("Process error:", err.message);
    }
  }
}

// =========================
// SOC ALERT ENGINE (FIXED + NO REPEATS)
// =========================

async function evaluateRepos() {
  const now = Date.now();

  for (const [repoName, repo] of repoCache.entries()) {

    const score = computeRepoScore(repo);
    const risk = getRiskBadge(score);
    const repoUrl = buildRepoUrl(repoName);

    // 🔥 COOLDOWN CHECK (FIX REPEATS)
    if (alertedRepos.has(repoName)) {
      const last = alertedRepos.get(repoName);
      if (now - last < ALERT_COOLDOWN) {
        console.log("⏳ Skipping repeat alert:", repoName);
        continue;
      }
    }

    await pool.query(
      `INSERT INTO findings (keyword, repo_name, file_path, html_url, score, severity)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT DO NOTHING`,
      ["repo-analysis", repoName, null, null, score, risk]
    );

    if (score >= ALERT_THRESHOLD) {

      alertedRepos.set(repoName, now); // 🔥 LOCK ALERT

      await sendTelegram(
`🚨 SOC POLLING INTELLIGENCE CARD

━━━━━━━━━━━━━━━━━━
${risk}
━━━━━━━━━━━━━━━━━━

📦 Repository
${repoName}

🔗 GitHub Link
${repoUrl}

📊 Risk Score: ${score.toFixed(2)}

📁 Files Analyzed: ${repo.files}

🧬 Signal Score: ${repo.signalScore}
⚙️ Behavior Score: ${repo.behaviorScore}
⚠️ Legit Penalty: ${repo.legitPenalty}

━━━━━━━━━━━━━━━━━━
Confidence: ${score >= HIGH_CONFIDENCE_THRESHOLD ? "HIGH" : "MEDIUM"}
Scan Type: Polling Scanner (GitHub Search API)
━━━━━━━━━━━━━━━━━━`
      );

      console.log("🚨 ALERT:", repoName);
    }
  }
}

// =========================
// CYCLE
// =========================

async function runCycle() {
  console.log("🔄 Scan cycle started");

  processedUrls.clear();
  repoCache.clear();

  for (const keyword of KEYWORDS) {
    await processKeyword(keyword);
    await new Promise(r => setTimeout(r, BASE_SLEEP));
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
      console.log("💤 sleeping...");
      await new Promise(r => setTimeout(r, 10 * 60 * 1000));
    } catch (e) {
      console.error("Worker crash:", e.message);
    }
  }
}

startWorker();
