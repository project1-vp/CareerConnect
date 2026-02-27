require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();

console.log("SERVER LOADED");

app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "storage", "uploads")));

app.use("/api", require("./routes"));

app.get("/", (req, res) => {
  res.send("Backend Working");
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

