const pool = require("./db");

async function init() {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS findings (
      id SERIAL PRIMARY KEY,
      keyword TEXT NOT NULL,
      repo_name TEXT NOT NULL,
      file_path TEXT NOT NULL,
      html_url TEXT UNIQUE NOT NULL,
      discovered_at TIMESTAMP DEFAULT NOW()
    );
  `);

  console.log("Database ready");
  process.exit();
}

init();
