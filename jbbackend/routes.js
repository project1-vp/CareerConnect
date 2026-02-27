const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./config");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const nodemailer = require("nodemailer");

console.log("ROUTES LOADED");

const JWT_SECRET = process.env.JWT_SECRET || "secretkey";
const MAIL_ENABLED =
  !!process.env.SMTP_HOST &&
  !!process.env.SMTP_PORT &&
  !!process.env.SMTP_USER &&
  !!process.env.SMTP_PASS;

const mailTransporter = MAIL_ENABLED
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT),
      secure: String(process.env.SMTP_SECURE || "false").toLowerCase() === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    })
  : null;

async function sendEmailSafe({ to, subject, text, html }) {
  if (!MAIL_ENABLED || !mailTransporter || !to) return;
  try {
    await mailTransporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to,
      subject,
      text,
      html
    });
  } catch (error) {
    console.error("Email send error:", error.message);
  }
}

const resumesDir = path.join(__dirname, "storage", "uploads", "resumes");
if (!fs.existsSync(resumesDir)) {
  fs.mkdirSync(resumesDir, { recursive: true });
}

const resumeStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, resumesDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, `resume_${Date.now()}${ext}`);
  }
});

const uploadResume = multer({
  storage: resumeStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = [".pdf", ".doc", ".docx"];
    const ext = path.extname(file.originalname || "").toLowerCase();
    if (!allowed.includes(ext)) {
      return cb(new Error("Only PDF, DOC, DOCX files are allowed"));
    }
    cb(null, true);
  }
});

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1d" });
}

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : authHeader;

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

function allowRoles(...allowed) {
  return (req, res, next) => {
    const role = (req.user?.role || "").toLowerCase();
    if (!allowed.includes(role)) {
      return res.status(403).json({ message: "Access denied" });
    }
    next();
  };
}

/* ================= AUTH ================= */

router.post("/register", async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const normalizedRole = role.toLowerCase().trim();

  if (!["recruiter", "job seeker", "jobseeker", "seeker"].includes(normalizedRole)) {
    return res.status(400).json({ message: "Invalid role" });
  }

  const finalRole =
    normalizedRole === "jobseeker" || normalizedRole === "seeker"
      ? "job seeker"
      : normalizedRole;

  db.query("SELECT id FROM users WHERE email=?", [email], async (err, rows) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (rows.length > 0) return res.status(400).json({ message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    db.query(
      "INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)",
      [name, email, hashedPassword, finalRole],
      (insertErr) => {
        if (insertErr) return res.status(500).json({ message: "Database error" });
        res.json({ message: "Registration Successful" });
      }
    );
  });
});

router.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  // Static single admin login
  if (email.toLowerCase() === "admin" && password === "admin123") {
    const token = signToken({ id: 0, role: "admin", email: "admin" });
    return res.json({ message: "Login Successful", token, role: "admin" });
  }

  db.query("SELECT * FROM users WHERE email=?", [email], async (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (result.length === 0) return res.status(404).json({ message: "User not found" });

    const user = result[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid password" });

    const token = signToken({ id: user.id, role: user.role, email: user.email });

    res.json({
      message: "Login Successful",
      token,
      role: user.role
    });
  });
});

router.get("/me", verifyToken, (req, res) => {
  if (req.user.role === "admin") {
    return res.json({ id: 0, name: "Admin", email: "admin", role: "admin" });
  }

  db.query(
    "SELECT id,name,email,role,created_at FROM users WHERE id=?",
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "Database error" });
      if (rows.length === 0) return res.status(404).json({ message: "User not found" });
      res.json(rows[0]);
    }
  );
});

/* ================= RECRUITER ================= */

router.get(
  "/recruiter/profile",
  verifyToken,
  allowRoles("recruiter"),
  (req, res) => {
    db.query(
      "SELECT * FROM recruiter_profile WHERE user_id=?",
      [req.user.id],
      (err, rows) => {
        if (err) return res.status(500).json({ message: "Database error" });
        res.json(rows[0] || {});
      }
    );
  }
);

router.put(
  "/recruiter/profile",
  verifyToken,
  allowRoles("recruiter"),
  (req, res) => {
    const { company_name, phone, location, website, about_company } = req.body;

    db.query(
      "SELECT id FROM recruiter_profile WHERE user_id=?",
      [req.user.id],
      (err, rows) => {
        if (err) return res.status(500).json({ message: "Database error" });

        if (rows.length > 0) {
          db.query(
            `UPDATE recruiter_profile
             SET company_name=?, phone=?, location=?, website=?, about_company=?
             WHERE user_id=?`,
            [company_name, phone, location, website, about_company, req.user.id],
            (updateErr) => {
              if (updateErr) return res.status(500).json({ message: "Database error" });
              res.json({ message: "Recruiter profile updated" });
            }
          );
        } else {
          db.query(
            `INSERT INTO recruiter_profile
             (user_id, company_name, phone, location, website, about_company)
             VALUES (?,?,?,?,?,?)`,
            [req.user.id, company_name, phone, location, website, about_company],
            (insertErr) => {
              if (insertErr) return res.status(500).json({ message: "Database error" });
              res.json({ message: "Recruiter profile created" });
            }
          );
        }
      }
    );
  }
);

router.post("/recruiter/jobs", verifyToken, allowRoles("recruiter"), (req, res) => {
  const { title, company, job_type, salary, experience, location, description } = req.body;

  if (!title || !company) {
    return res.status(400).json({ message: "Title and company are required" });
  }

  db.query(
    `INSERT INTO jobs
     (recruiter_id,title,company,job_type,salary,experience,location,description)
     VALUES (?,?,?,?,?,?,?,?)`,
    [
      req.user.id,
      title,
      company,
      job_type || "Full-Time",
      salary || null,
      experience || null,
      location || null,
      description || null
    ],
    async (err, result) => {
      if (err) return res.status(500).json({ message: "Database error" });

      db.query(
        "SELECT name,email FROM users WHERE id=? LIMIT 1",
        [req.user.id],
        async (_uErr, userRows) => {
          const recruiterName = userRows?.[0]?.name || "Recruiter";
          const recruiterEmail = userRows?.[0]?.email || null;

          await sendEmailSafe({
            to: recruiterEmail,
            subject: "Job Posted Successfully",
            text:
              `Hello ${recruiterName},\n\n` +
              `Your job has been posted successfully.\n\n` +
              `Title: ${title}\nCompany: ${company}\nType: ${job_type || "Full-Time"}\n\n` +
              `Thanks,\nCareerConnect`,
            html:
              `<p>Hello ${recruiterName},</p>` +
              `<p>Your job has been posted successfully.</p>` +
              `<p><b>Title:</b> ${title}<br/><b>Company:</b> ${company}<br/><b>Type:</b> ${job_type || "Full-Time"}</p>` +
              `<p>Thanks,<br/>CareerConnect</p>`
          });
        }
      );

      res.json({ message: "Job created", job_id: result.insertId });
    }
  );
});

router.get("/recruiter/jobs", verifyToken, allowRoles("recruiter"), (req, res) => {
  db.query(
    "SELECT * FROM jobs WHERE recruiter_id=? ORDER BY created_at DESC",
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "Database error" });
      res.json(rows);
    }
  );
});

router.put("/recruiter/jobs/:id", verifyToken, allowRoles("recruiter"), (req, res) => {
  const { id } = req.params;
  const { title, company, job_type, salary, experience, location, description, status } = req.body;

  db.query(
    `UPDATE jobs
     SET title=?, company=?, job_type=?, salary=?, experience=?, location=?, description=?, status=?
     WHERE id=? AND recruiter_id=?`,
    [
      title,
      company,
      job_type,
      salary,
      experience,
      location,
      description,
      status || "open",
      id,
      req.user.id
    ],
    (err, result) => {
      if (err) return res.status(500).json({ message: "Database error" });
      if (result.affectedRows === 0) return res.status(404).json({ message: "Job not found" });
      res.json({ message: "Job updated" });
    }
  );
});

router.delete("/recruiter/jobs/:id", verifyToken, allowRoles("recruiter"), (req, res) => {
  const { id } = req.params;
  db.query(
    "DELETE FROM jobs WHERE id=? AND recruiter_id=?",
    [id, req.user.id],
    (err, result) => {
      if (err) return res.status(500).json({ message: "Database error" });
      if (result.affectedRows === 0) return res.status(404).json({ message: "Job not found" });
      res.json({ message: "Job deleted" });
    }
  );
});

router.get(
  "/recruiter/jobs/:id/applications",
  verifyToken,
  allowRoles("recruiter"),
  (req, res) => {
    const { id } = req.params;

    db.query(
      "SELECT id FROM jobs WHERE id=? AND recruiter_id=?",
      [id, req.user.id],
      (jobErr, jobRows) => {
        if (jobErr) return res.status(500).json({ message: "Database error" });
        if (jobRows.length === 0) return res.status(404).json({ message: "Job not found" });

        db.query(
          `SELECT a.id, a.status, a.withdrawal_reason, a.applied_at,
                  u.id AS seeker_id, u.name, u.email,
                  jsp.phone, jsp.experience, jsp.skills, jsp.resume_url
           FROM applications a
           JOIN users u ON u.id = a.seeker_id
           LEFT JOIN jobseeker_profile jsp ON jsp.user_id = a.seeker_id
           WHERE a.job_id=?
           ORDER BY a.applied_at DESC`,
          [id],
          (err, rows) => {
            if (err) return res.status(500).json({ message: "Database error" });
            res.json(rows);
          }
        );
      }
    );
  }
);

/* ================= JOB SEEKER ================= */

router.get(
  "/jobseeker/profile",
  verifyToken,
  allowRoles("job seeker", "jobseeker", "seeker"),
  (req, res) => {
    db.query(
      "SELECT * FROM jobseeker_profile WHERE user_id=?",
      [req.user.id],
      (err, rows) => {
        if (err) return res.status(500).json({ message: "Database error" });
        res.json(rows[0] || {});
      }
    );
  }
);

router.put(
  "/jobseeker/profile",
  verifyToken,
  allowRoles("job seeker", "jobseeker", "seeker"),
  (req, res) => {
    const {
      phone,
      experience,
      skills,
      resume_url,
      summary,
      final_year_project,
      mscit
    } = req.body;

    db.query(
      "SELECT id FROM jobseeker_profile WHERE user_id=?",
      [req.user.id],
      (err, rows) => {
        if (err) return res.status(500).json({ message: "Database error" });

        if (rows.length > 0) {
          db.query(
            `UPDATE jobseeker_profile
             SET phone=?, experience=?, skills=?, resume_url=?, summary=?, final_year_project=?, mscit=?
             WHERE user_id=?`,
            [
              phone,
              experience,
              skills,
              resume_url,
              summary,
              final_year_project,
              mscit,
              req.user.id
            ],
            (updateErr) => {
              if (updateErr) return res.status(500).json({ message: "Database error" });
              res.json({ message: "Job seeker profile updated" });
            }
          );
        } else {
          db.query(
            `INSERT INTO jobseeker_profile
             (user_id, phone, experience, skills, resume_url, summary, final_year_project, mscit)
             VALUES (?,?,?,?,?,?,?,?)`,
            [
              req.user.id,
              phone,
              experience,
              skills,
              resume_url,
              summary,
              final_year_project,
              mscit
            ],
            (insertErr) => {
              if (insertErr) return res.status(500).json({ message: "Database error" });
              res.json({ message: "Job seeker profile created" });
            }
          );
        }
      }
    );
  }
);

router.post(
  "/jobseeker/upload-resume",
  verifyToken,
  allowRoles("job seeker", "jobseeker", "seeker"),
  (req, res) => {
    uploadResume.single("resume")(req, res, (err) => {
      if (err) {
        return res.status(400).json({ message: err.message || "Upload failed" });
      }

      if (!req.file) {
        return res.status(400).json({ message: "Resume file is required" });
      }

      const resumeUrl = `${req.protocol}://${req.get("host")}/uploads/resumes/${req.file.filename}`;
      return res.json({ message: "Resume uploaded", resume_url: resumeUrl });
    });
  }
);
router.get("/jobs", verifyToken, (req, res) => {
  db.query(
    `SELECT j.*, u.name AS recruiter_name, rp.company_name AS recruiter_company
     FROM jobs j
     JOIN users u ON u.id = j.recruiter_id
     LEFT JOIN recruiter_profile rp ON rp.user_id = j.recruiter_id
     WHERE j.status='open'
     ORDER BY j.created_at DESC`,
    (err, rows) => {
      if (err) return res.status(500).json({ message: "Database error" });
      res.json(rows);
    }
  );
});

router.post(
  "/jobs/:id/apply",
  verifyToken,
  allowRoles("job seeker", "jobseeker", "seeker"),
  (req, res) => {
    const { id } = req.params;

    db.query("SELECT id,status FROM jobs WHERE id=?", [id], (jobErr, jobRows) => {
      if (jobErr) return res.status(500).json({ message: "Database error" });
      if (jobRows.length === 0) return res.status(404).json({ message: "Job not found" });
      if (jobRows[0].status !== "open") {
        return res.status(400).json({ message: "Job is closed" });
      }

      db.query(
        "SELECT id, status FROM applications WHERE job_id=? AND seeker_id=?",
        [id, req.user.id],
        (existsErr, existsRows) => {
          if (existsErr) return res.status(500).json({ message: "Database error" });
          if (existsRows.length > 0) {
            const existingStatus = (existsRows[0].status || "").toLowerCase();
            if (existingStatus === "withdrawn") {
              return res.status(400).json({ message: "Cannot apply again after withdrawal" });
            }
            return res.status(400).json({ message: "Already applied" });
          }

          db.query(
            "INSERT INTO applications (job_id,seeker_id,status) VALUES (?,?,?)",
            [id, req.user.id, "Applied"],
            (insertErr, result) => {
              if (insertErr) return res.status(500).json({ message: "Database error" });

              db.query(
                `SELECT j.title, j.company, u.email AS recruiter_email, u.name AS recruiter_name,
                        su.name AS seeker_name, su.email AS seeker_email
                 FROM jobs j
                 JOIN users u ON u.id = j.recruiter_id
                 JOIN users su ON su.id = ?
                 WHERE j.id = ?
                 LIMIT 1`,
                [req.user.id, id],
                async (_mailErr, rows) => {
                  const row = rows?.[0];
                  if (row) {
                    await sendEmailSafe({
                      to: row.recruiter_email,
                      subject: "New Job Application Received",
                      text:
                        `Hello ${row.recruiter_name || "Recruiter"},\n\n` +
                        `${row.seeker_name || "A job seeker"} has applied for your job.\n\n` +
                        `Job: ${row.title}\nCompany: ${row.company}\nApplicant Email: ${row.seeker_email || "-"}\n\n` +
                        `Login to CareerConnect to review the application.`,
                      html:
                        `<p>Hello ${row.recruiter_name || "Recruiter"},</p>` +
                        `<p><b>${row.seeker_name || "A job seeker"}</b> has applied for your job.</p>` +
                        `<p><b>Job:</b> ${row.title}<br/><b>Company:</b> ${row.company}<br/><b>Applicant Email:</b> ${row.seeker_email || "-"}</p>` +
                        `<p>Login to CareerConnect to review the application.</p>`
                    });
                  }
                }
              );

              res.json({ message: "Application submitted", application_id: result.insertId });
            }
          );
        }
      );
    });
  }
);

router.get(
  "/jobseeker/applications",
  verifyToken,
  allowRoles("job seeker", "jobseeker", "seeker"),
  (req, res) => {
    db.query(
      `SELECT a.*, j.title, j.company, j.job_type, j.salary, j.location
       FROM applications a
       JOIN jobs j ON j.id = a.job_id
       WHERE a.seeker_id=?
       ORDER BY a.applied_at DESC`,
      [req.user.id],
      (err, rows) => {
        if (err) return res.status(500).json({ message: "Database error" });
        res.json(rows);
      }
    );
  }
);

router.put(
  "/applications/:id/withdraw",
  verifyToken,
  allowRoles("job seeker", "jobseeker", "seeker"),
  (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;

    db.query(
      `UPDATE applications
       SET status='Withdrawn', withdrawal_reason=?
       WHERE id=? AND seeker_id=? AND status='Applied'`,
      [reason || null, id, req.user.id],
      (err, result) => {
        if (err) return res.status(500).json({ message: "Database error" });
        if (result.affectedRows === 0) {
          return res.status(404).json({ message: "Application not found or already processed" });
        }
        res.json({ message: "Application withdrawn" });
      }
    );
  }
);

/* ================= ADMIN ================= */

router.get("/admin/stats", verifyToken, allowRoles("admin"), (req, res) => {
  const stats = {};

  db.query("SELECT COUNT(*) AS total FROM users", (err, usersRows) => {
    if (err) return res.status(500).json({ message: "Database error" });
    stats.users = usersRows[0].total;

    db.query("SELECT COUNT(*) AS total FROM jobs", (jobsErr, jobsRows) => {
      if (jobsErr) return res.status(500).json({ message: "Database error" });
      stats.jobs = jobsRows[0].total;

      db.query("SELECT COUNT(*) AS total FROM applications", (appsErr, appsRows) => {
        if (appsErr) return res.status(500).json({ message: "Database error" });
        stats.applications = appsRows[0].total;

        db.query(
          "SELECT COUNT(*) AS total FROM users WHERE role='recruiter'",
          (recErr, recRows) => {
            if (recErr) return res.status(500).json({ message: "Database error" });
            stats.recruiters = recRows[0].total;

            db.query(
              "SELECT COUNT(*) AS total FROM users WHERE role='job seeker'",
              (seekErr, seekRows) => {
                if (seekErr) return res.status(500).json({ message: "Database error" });
                stats.job_seekers = seekRows[0].total;
                res.json(stats);
              }
            );
          }
        );
      });
    });
  });
});

router.get("/admin/users", verifyToken, allowRoles("admin"), (req, res) => {
  db.query(
    "SELECT id,name,email,role,created_at FROM users ORDER BY created_at DESC",
    (err, rows) => {
      if (err) return res.status(500).json({ message: "Database error" });
      res.json(rows);
    }
  );
});

router.get("/admin/jobs", verifyToken, allowRoles("admin"), (req, res) => {
  db.query(
    `SELECT j.*, u.name AS recruiter_name, u.email AS recruiter_email
     FROM jobs j
     JOIN users u ON u.id = j.recruiter_id
     ORDER BY j.created_at DESC`,
    (err, rows) => {
      if (err) return res.status(500).json({ message: "Database error" });
      res.json(rows);
    }
  );
});

router.get("/admin/applications", verifyToken, allowRoles("admin"), (req, res) => {
  db.query(
    `SELECT a.*, j.title, j.company, u.name AS seeker_name, u.email AS seeker_email
     FROM applications a
     JOIN jobs j ON j.id = a.job_id
     JOIN users u ON u.id = a.seeker_id
     ORDER BY a.applied_at DESC`,
    (err, rows) => {
      if (err) return res.status(500).json({ message: "Database error" });
      res.json(rows);
    }
  );
});

router.delete("/admin/users/:id", verifyToken, allowRoles("admin"), (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM users WHERE id=?", [id], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (result.affectedRows === 0) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User deleted" });
  });
});

router.delete("/admin/jobs/:id", verifyToken, allowRoles("admin"), (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM jobs WHERE id=?", [id], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (result.affectedRows === 0) return res.status(404).json({ message: "Job not found" });
    res.json({ message: "Job deleted" });
  });
});

router.delete(
  "/admin/applications/:id",
  verifyToken,
  allowRoles("admin"),
  (req, res) => {
    const { id } = req.params;
    db.query("DELETE FROM applications WHERE id=?", [id], (err, result) => {
      if (err) return res.status(500).json({ message: "Database error" });
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Application not found" });
      }
      res.json({ message: "Application deleted" });
    });
  }
);

module.exports = router;








