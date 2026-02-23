require("dotenv").config();

const express = require("express");
const cors = require("cors");

const app = express();

// Enable CORS (frontend can connect)
app.use(cors());

// Enable JSON body
app.use(express.json());

// Use routes
app.use("/api", require("./routes"));

// Start server
app.listen(process.env.PORT, () => {
  console.log(`🚀 Server running on port ${process.env.PORT}`);
});