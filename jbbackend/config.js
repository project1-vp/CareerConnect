const mysql = require("mysql2");

require("dotenv").config();

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect((err) => {
  if (err) {
    console.log("Database connection error:", err);
    return;
  }

  console.log("MySQL Connected");
  db.query(
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS mode VARCHAR(80) DEFAULT NULL AFTER job_type",
    (alterErr) => {
      if (alterErr) {
        console.log("Jobs table migration warning:", alterErr.message || alterErr);
      }
    }
  );
});

module.exports = db;
