// Import mysql2 package
const mysql = require("mysql2");

// Load environment variables
require("dotenv").config();

// Create MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,      // Database host
  user: process.env.DB_USER,      // Database username
  password: process.env.DB_PASSWORD, // Database password
  database: process.env.DB_NAME   // Database name
});

// Connect to database
db.connect(err => {
  if (err) {
    console.log("Database connection error:", err);
  } else {
    console.log("✅ MySQL Connected");
  }
});

// Export connection so other files can use it
module.exports = db;