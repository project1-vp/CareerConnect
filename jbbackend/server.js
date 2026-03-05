require("dotenv").config();

const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");

const app = express();
const PORT = Number(process.env.PORT || 4000);

const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

app.use("/uploads", express.static(uploadsDir));
app.use("/api", require("./routes"));

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "careerconnect-api", time: new Date().toISOString() });
});

// Return JSON for runtime errors (including multer errors), so frontend gets readable messages.
app.use((err, _req, res, _next) => {
  console.error("API_ERROR:", err && err.message ? err.message : err);

  if (err && err.code === "LIMIT_FILE_SIZE") {
    return res.status(400).json({ message: "File too large. Max allowed is 10MB." });
  }

  if (err && err.message === "Unexpected field") {
    return res.status(400).json({ message: "Invalid upload field." });
  }

  return res.status(500).json({ message: err && err.message ? err.message : "Server error" });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

