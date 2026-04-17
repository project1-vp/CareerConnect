require("./env");

const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");

const app = express();
const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 4000);
const projectRoot = path.join(__dirname, "..");

const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

app.use("/uploads", express.static(uploadsDir));
app.use("/api", require("./routes"));
app.use(express.static(projectRoot));

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "careerconnect-api", time: new Date().toISOString() });
});

app.get("/", (_req, res) => {
  res.sendFile(path.join(projectRoot, "home.html"));
});

app.get("/home", (_req, res) => {
  res.sendFile(path.join(projectRoot, "home.html"));
});

app.get("/login", (_req, res) => {
  res.sendFile(path.join(projectRoot, "login.html"));
});

app.get("/register", (_req, res) => {
  res.sendFile(path.join(projectRoot, "register.html"));
});

app.get("/explore", (_req, res) => {
  res.sendFile(path.join(projectRoot, "explore.html"));
});

app.get("/jobseeker", (_req, res) => {
  res.sendFile(path.join(projectRoot, "jobseeker.html"));
});

app.get("/recruiter", (_req, res) => {
  res.sendFile(path.join(projectRoot, "recruiter.html"));
});

app.get("/admin", (_req, res) => {
  res.sendFile(path.join(projectRoot, "admin.html"));
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

const server = app.listen(PORT, HOST, () => {
  console.log(`Server running locally at http://${HOST}:${PORT}`);
});

server.on("error", (err) => {
  if (err && err.code === "EADDRINUSE") {
    console.error(`Port ${PORT} is already in use. Close the old server, then run again.`);
    return;
  }

  console.error("Server startup error:", err);
});
