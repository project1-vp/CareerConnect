const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const db = require("./config");

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "secretkey";

const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    try {
      fs.mkdirSync(uploadsDir, { recursive: true });
      cb(null, uploadsDir);
    } catch (err) {
      cb(err, uploadsDir);
    }
  },
  filename: (_req, file, cb) => {
    const safe = (file.originalname || "resume").replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, `${Date.now()}_${safe}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }
});

function query(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

function normalizeRole(role = "") {
  const r = String(role).toLowerCase().trim();
  if (r === "jobseeker" || r === "seeker") return "job seeker";
  return r;
}

function auth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (_err) {
    return res.status(401).json({ message: "Unauthorized" });
  }
}

function requireRole(role) {
  return async (req, res, next) => {
    try {
      if (role === "admin" && req.user.id === 0) return next();
      const rows = await query("SELECT id, role FROM users WHERE id=?", [req.user.id]);
      if (!rows.length) return res.status(401).json({ message: "Unauthorized" });
      const userRole = normalizeRole(rows[0].role);
      if (userRole !== normalizeRole(role)) return res.status(403).json({ message: "Forbidden" });
      next();
    } catch (_err) {
      return res.status(500).json({ message: "Server error" });
    }
  };
}

async function findUserForLogin(identifier) {
  const tries = [
    { sql: "SELECT * FROM users WHERE email=? LIMIT 1", params: [identifier] },
    { sql: "SELECT * FROM users WHERE username=? LIMIT 1", params: [identifier] },
    { sql: "SELECT * FROM users WHERE name=? LIMIT 1", params: [identifier] }
  ];

  for (const t of tries) {
    try {
      const rows = await query(t.sql, t.params);
      if (rows.length) return rows[0];
    } catch (err) {
      if (err && err.code !== "ER_BAD_FIELD_ERROR") throw err;
    }
  }

  return null;
}

router.post("/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) {
      return res.status(400).json({ message: "All fields required" });
    }

    const normalizedRole = normalizeRole(role);
    if (!["job seeker", "recruiter"].includes(normalizedRole)) {
      return res.status(400).json({ message: "Invalid role" });
    }

    const existing = await query("SELECT id FROM users WHERE email=?", [String(email).trim()]);
    if (existing.length) return res.status(409).json({ message: "Email already exists" });

    const hashed = await bcrypt.hash(String(password), 10);
    await query(
      "INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)",
      [String(name).trim(), String(email).trim(), hashed, normalizedRole]
    );

    return res.json({ message: "Registration Successful" });
  } catch (err) {
    console.error("REGISTER_ERROR:", err && err.message ? err.message : err);
    return res.status(500).json({ message: "Database error" });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "All fields required" });

    const identifier = String(email).trim();

    if (identifier === "admin" && String(password) === "admin123") {
      const token = jwt.sign({ id: 0, role: "admin" }, JWT_SECRET, { expiresIn: "1d" });
      return res.json({
        message: "Login Successful",
        token,
        role: "admin",
        name: "Admin",
        email: "admin@careerconnect.local"
      });
    }

    const user = await findUserForLogin(identifier);
    if (!user) return res.status(404).json({ message: "User not found" });

    const storedPassword = user.password ?? user.pass ?? user.user_password ?? null;
    if (!storedPassword) return res.status(500).json({ message: "Database error" });

    let ok = false;
    if (typeof storedPassword === "string" && storedPassword.startsWith("$2")) {
      ok = await bcrypt.compare(String(password), storedPassword);
    } else {
      ok = String(password) === String(storedPassword);
    }

    if (!ok) return res.status(401).json({ message: "Invalid password" });

    const role = normalizeRole(user.role || user.user_type || user.usertype || user.type || "job seeker");
    const name = user.name || user.username || user.full_name || (user.email ? String(user.email).split("@")[0] : "User");
    const token = jwt.sign({ id: user.id, role }, JWT_SECRET, { expiresIn: "1d" });

    return res.json({ message: "Login Successful", token, role, name, email: user.email || identifier });
  } catch (err) {
    console.error("LOGIN_ERROR:", err && err.message ? err.message : err);
    return res.status(500).json({ message: "Database error" });
  }
});

router.get("/me", auth, async (req, res) => {
  try {
    if (req.user.id === 0 || req.user.role === "admin") {
      return res.json({ id: 0, name: "Admin", email: "admin@careerconnect.local", role: "admin" });
    }
    const rows = await query("SELECT id,name,email,role FROM users WHERE id=?", [req.user.id]);
    if (!rows.length) return res.status(401).json({ message: "Unauthorized" });
    const u = rows[0];
    return res.json({ ...u, role: normalizeRole(u.role) });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.get("/jobseeker/profile", auth, requireRole("job seeker"), async (req, res) => {
  try {
    const rows = await query(
      "SELECT phone,experience,skills,resume_url,summary,final_year_project,mscit FROM jobseeker_profile WHERE user_id=? LIMIT 1",
      [req.user.id]
    );
    return res.json(rows[0] || {
      phone: "",
      experience: "",
      skills: "",
      resume_url: "",
      summary: "",
      final_year_project: null,
      mscit: null
    });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.put("/jobseeker/profile", auth, requireRole("job seeker"), async (req, res) => {
  try {
    const { phone, experience, skills, resume_url, summary, final_year_project, mscit } = req.body;
    const existing = await query("SELECT id FROM jobseeker_profile WHERE user_id=? LIMIT 1", [req.user.id]);
    if (existing.length) {
      await query(
        `UPDATE jobseeker_profile
         SET phone=?, experience=?, skills=?, resume_url=?, summary=?, final_year_project=?, mscit=?
         WHERE user_id=?`,
        [phone || "", experience || "", skills || "", resume_url || "", summary || "", final_year_project || null, mscit || null, req.user.id]
      );
    } else {
      await query(
        `INSERT INTO jobseeker_profile (user_id,phone,experience,skills,resume_url,summary,final_year_project,mscit)
         VALUES (?,?,?,?,?,?,?,?)`,
        [req.user.id, phone || "", experience || "", skills || "", resume_url || "", summary || "", final_year_project || null, mscit || null]
      );
    }
    return res.json({ message: "Profile saved" });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.post("/jobseeker/upload-resume", auth, requireRole("job seeker"), upload.single("resume"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "No file uploaded" });
    const base = process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 4000}`;
    const resumeUrl = `${base}/uploads/${req.file.filename}`;

    const existing = await query("SELECT id FROM jobseeker_profile WHERE user_id=? LIMIT 1", [req.user.id]);
    if (existing.length) {
      await query("UPDATE jobseeker_profile SET resume_url=? WHERE user_id=?", [resumeUrl, req.user.id]);
    } else {
      // Some existing DB schemas keep profile fields as NOT NULL; provide safe defaults.
      await query(
        `INSERT INTO jobseeker_profile
         (user_id, phone, experience, skills, resume_url, summary, final_year_project, mscit)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [req.user.id, "", "", "", resumeUrl, "", null, null]
      );
    }

    return res.json({ message: "Uploaded", resume_url: resumeUrl });
  } catch (_err) {
    console.error("UPLOAD_RESUME_ERROR:", _err && _err.message ? _err.message : _err);
    return res.status(500).json({ message: "Upload failed" });
  }
});

router.get("/jobs", auth, async (_req, res) => {
  try {
    const rows = await query(
      `SELECT j.id,j.title,j.company,j.job_type,j.salary,j.experience,j.location,j.description,j.status,j.created_at,
              u.name AS recruiter_name
       FROM jobs j
       LEFT JOIN users u ON u.id=j.recruiter_id
       WHERE COALESCE(j.status,'open') <> 'closed'
       ORDER BY j.id DESC`
    );
    return res.json(rows);
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.post("/jobs/:id/apply", auth, requireRole("job seeker"), async (req, res) => {
  try {
    const jobId = Number(req.params.id);
    if (!jobId) return res.status(400).json({ message: "Invalid job id" });

    const exists = await query("SELECT id FROM jobs WHERE id=? LIMIT 1", [jobId]);
    if (!exists.length) return res.status(404).json({ message: "Job not found" });

    const already = await query("SELECT id,status FROM applications WHERE job_id=? AND seeker_id=? LIMIT 1", [jobId, req.user.id]);
    if (already.length && already[0].status !== "Withdrawn") {
      return res.status(409).json({ message: "Already applied" });
    }

    if (already.length) {
      await query("UPDATE applications SET status='Applied', withdrawal_reason=NULL, applied_at=NOW() WHERE id=?", [already[0].id]);
    } else {
      await query("INSERT INTO applications (job_id,seeker_id,status,applied_at) VALUES (?,?, 'Applied', NOW())", [jobId, req.user.id]);
    }

    return res.json({ message: "Application submitted" });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.get("/jobseeker/applications", auth, requireRole("job seeker"), async (req, res) => {
  try {
    const rows = await query(
      `SELECT a.id,a.status,a.withdrawal_reason,a.applied_at,
              j.id AS job_id,j.title,j.company,j.job_type,j.salary,j.experience,j.location
       FROM applications a
       JOIN jobs j ON j.id=a.job_id
       WHERE a.seeker_id=?
       ORDER BY a.applied_at DESC`,
      [req.user.id]
    );
    return res.json(rows);
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.put("/applications/:id/withdraw", auth, requireRole("job seeker"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: "Invalid application id" });
    const reason = (req.body.reason || "").toString().trim();

    const rows = await query("SELECT id FROM applications WHERE id=? AND seeker_id=? LIMIT 1", [id, req.user.id]);
    if (!rows.length) return res.status(404).json({ message: "Application not found" });

    await query("UPDATE applications SET status='Withdrawn', withdrawal_reason=? WHERE id=?", [reason || null, id]);
    return res.json({ message: "Application withdrawn" });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.get("/recruiter/profile", auth, requireRole("recruiter"), async (req, res) => {
  try {
    const rows = await query(
      "SELECT company_name,phone,location,website,about_company FROM recruiter_profile WHERE user_id=? LIMIT 1",
      [req.user.id]
    );
    return res.json(rows[0] || {
      company_name: "",
      phone: "",
      location: "",
      website: "",
      about_company: ""
    });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.put("/recruiter/profile", auth, requireRole("recruiter"), async (req, res) => {
  try {
    const { company_name, phone, location, website, about_company } = req.body;
    const existing = await query("SELECT id FROM recruiter_profile WHERE user_id=? LIMIT 1", [req.user.id]);
    if (existing.length) {
      await query(
        `UPDATE recruiter_profile
         SET company_name=?, phone=?, location=?, website=?, about_company=?
         WHERE user_id=?`,
        [company_name || "", phone || "", location || "", website || "", about_company || "", req.user.id]
      );
    } else {
      await query(
        `INSERT INTO recruiter_profile (user_id,company_name,phone,location,website,about_company)
         VALUES (?,?,?,?,?,?)`,
        [req.user.id, company_name || "", phone || "", location || "", website || "", about_company || ""]
      );
    }
    return res.json({ message: "Profile saved" });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.get("/recruiter/jobs", auth, requireRole("recruiter"), async (req, res) => {
  try {
    const rows = await query("SELECT * FROM jobs WHERE recruiter_id=? ORDER BY id DESC", [req.user.id]);
    return res.json(rows);
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.post("/recruiter/jobs", auth, requireRole("recruiter"), async (req, res) => {
  try {
    const { title, company, job_type, salary, experience, location, description } = req.body;
    if (!title || !company) return res.status(400).json({ message: "Title and company required" });

    await query(
      `INSERT INTO jobs (recruiter_id,title,company,job_type,salary,experience,location,description,status,created_at)
       VALUES (?,?,?,?,?,?,?,?, 'open', NOW())`,
      [req.user.id, title, company, job_type || null, salary || null, experience || null, location || null, description || null]
    );

    return res.json({ message: "Job created" });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.put("/recruiter/jobs/:id", auth, requireRole("recruiter"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: "Invalid job id" });

    const rows = await query("SELECT id FROM jobs WHERE id=? AND recruiter_id=? LIMIT 1", [id, req.user.id]);
    if (!rows.length) return res.status(404).json({ message: "Job not found" });

    const { title, company, job_type, salary, experience, location, description, status } = req.body;

    await query(
      `UPDATE jobs
       SET title=?, company=?, job_type=?, salary=?, experience=?, location=?, description=?, status=?
       WHERE id=? AND recruiter_id=?`,
      [title || "", company || "", job_type || null, salary || null, experience || null, location || null, description || null, status || "open", id, req.user.id]
    );

    return res.json({ message: "Job updated" });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.delete("/recruiter/jobs/:id", auth, requireRole("recruiter"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: "Invalid job id" });

    await query("DELETE FROM jobs WHERE id=? AND recruiter_id=?", [id, req.user.id]);
    return res.json({ message: "Job deleted" });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.get("/recruiter/jobs/:id/applications", auth, requireRole("recruiter"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: "Invalid job id" });

    const own = await query("SELECT id FROM jobs WHERE id=? AND recruiter_id=? LIMIT 1", [id, req.user.id]);
    if (!own.length) return res.status(404).json({ message: "Job not found" });

    const rows = await query(
      `SELECT a.id,a.status,a.applied_at,
              u.id AS seeker_id,u.name,u.email,
              p.phone,p.experience,p.skills,p.resume_url,p.summary
       FROM applications a
       JOIN users u ON u.id=a.seeker_id
       LEFT JOIN jobseeker_profile p ON p.user_id=u.id
       WHERE a.job_id=?
       ORDER BY a.applied_at DESC`,
      [id]
    );

    return res.json(rows);
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.get("/recruiter/candidates/:seekerId/resume", auth, requireRole("recruiter"), async (req, res) => {
  try {
    const seekerId = Number(req.params.seekerId);
    if (!seekerId) return res.status(400).json({ message: "Invalid seeker id" });

    const rows = await query(
      `SELECT p.resume_url, u.name AS seeker_name
       FROM applications a
       JOIN jobs j ON j.id=a.job_id
       JOIN users u ON u.id=a.seeker_id
       LEFT JOIN jobseeker_profile p ON p.user_id=a.seeker_id
       WHERE j.recruiter_id=? AND a.seeker_id=?
       LIMIT 1`,
      [req.user.id, seekerId]
    );

    if (!rows.length) return res.status(404).json({ message: "Candidate not found" });
    const resumeUrl = (rows[0].resume_url || "").toString().trim();
    if (!resumeUrl) return res.status(404).json({ message: "Resume not found" });

    const asDownload = String(req.query.download || "") === "1";
    const setDisposition = (filename) => {
      const safeName = (filename || "resume").replace(/[^a-zA-Z0-9._-]/g, "_");
      res.setHeader("Content-Disposition", `${asDownload ? "attachment" : "inline"}; filename=\"${safeName}\"`);
    };

    // Stored as server uploads URL
    if (resumeUrl.includes("/uploads/")) {
      const filename = decodeURIComponent(resumeUrl.split("/uploads/").pop() || "");
      const filePath = path.join(uploadsDir, path.basename(filename));
      if (!fs.existsSync(filePath)) return res.status(404).json({ message: "Resume file missing" });
      setDisposition(path.basename(filePath));
      return res.sendFile(filePath);
    }

    // Stored as file:/// local URL (legacy records)
    if (resumeUrl.startsWith("file:///")) {
      let localPath = decodeURIComponent(resumeUrl.replace("file:///", ""));
      if (/^[A-Za-z]:/.test(localPath) === false && /^[A-Za-z]:/.test(localPath.slice(1))) {
        localPath = localPath.slice(1);
      }
      if (!fs.existsSync(localPath)) return res.status(404).json({ message: "Resume file missing" });
      setDisposition(path.basename(localPath));
      return res.sendFile(localPath);
    }

    // Remote resume URL fallback
    if (/^https?:\/\//i.test(resumeUrl)) {
      return res.redirect(resumeUrl);
    }

    return res.status(404).json({ message: "Unsupported resume path" });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.get("/admin/stats", auth, requireRole("admin"), async (_req, res) => {
  try {
    const users = await query("SELECT COUNT(*) AS c FROM users");
    const jobs = await query("SELECT COUNT(*) AS c FROM jobs");
    const apps = await query("SELECT COUNT(*) AS c FROM applications");
    const seekers = await query("SELECT COUNT(*) AS c FROM users WHERE LOWER(role) IN ('job seeker','jobseeker','seeker')");
    return res.json({ users: users[0].c, jobs: jobs[0].c, applications: apps[0].c, job_seekers: seekers[0].c });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.get("/admin/users", auth, requireRole("admin"), async (_req, res) => {
  try {
    const rows = await query("SELECT id,name,email,role FROM users ORDER BY id DESC");
    return res.json(rows.map((u) => ({ ...u, role: normalizeRole(u.role) })));
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.get("/admin/jobs", auth, requireRole("admin"), async (_req, res) => {
  try {
    const rows = await query(
      `SELECT j.*,u.name AS recruiter_name,u.email AS recruiter_email
       FROM jobs j
       LEFT JOIN users u ON u.id=j.recruiter_id
       ORDER BY j.id DESC`
    );
    return res.json(rows);
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.get("/admin/applications", auth, requireRole("admin"), async (_req, res) => {
  try {
    const rows = await query(
      `SELECT a.id,a.status,a.withdrawal_reason,a.applied_at,
              j.id AS job_id,j.title,j.company,
              u.id AS seeker_id,u.name AS seeker_name,u.email AS seeker_email
       FROM applications a
       JOIN jobs j ON j.id=a.job_id
       JOIN users u ON u.id=a.seeker_id
       ORDER BY a.applied_at DESC`
    );
    return res.json(rows);
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.delete("/admin/users/:id", auth, requireRole("admin"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: "Invalid user id" });
    if (id === req.user.id) return res.status(400).json({ message: "Cannot delete current admin" });
    await query("DELETE FROM users WHERE id=?", [id]);
    return res.json({ message: "User deleted" });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.delete("/admin/jobs/:id", auth, requireRole("admin"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: "Invalid job id" });
    await query("DELETE FROM jobs WHERE id=?", [id]);
    return res.json({ message: "Job deleted" });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

router.delete("/admin/applications/:id", auth, requireRole("admin"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: "Invalid application id" });
    await query("DELETE FROM applications WHERE id=?", [id]);
    return res.json({ message: "Application deleted" });
  } catch (_err) {
    return res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;

