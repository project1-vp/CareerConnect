-- 1) Create database
CREATE DATABASE IF NOT EXISTS jobportal;
USE jobportal;

-- 2) Users table
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  email VARCHAR(180) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role ENUM('job seeker','recruiter','admin') NOT NULL DEFAULT 'job seeker',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3) Job seeker profile (one-to-one with users)
CREATE TABLE IF NOT EXISTS jobseeker_profile (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL UNIQUE,
  phone VARCHAR(30) DEFAULT NULL,
  experience VARCHAR(120) DEFAULT NULL,
  skills TEXT,
  resume_url VARCHAR(255) DEFAULT NULL,
  summary TEXT,
  final_year_project VARCHAR(20) DEFAULT NULL,
  mscit VARCHAR(20) DEFAULT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_jobseeker_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 4) Recruiter profile (one-to-one with users)
CREATE TABLE IF NOT EXISTS recruiter_profile (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL UNIQUE,
  company_name VARCHAR(180) DEFAULT NULL,
  phone VARCHAR(30) DEFAULT NULL,
  location VARCHAR(180) DEFAULT NULL,
  website VARCHAR(180) DEFAULT NULL,
  about_company TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_recruiter_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 5) Jobs posted by recruiter
CREATE TABLE IF NOT EXISTS jobs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  recruiter_id INT NOT NULL,
  title VARCHAR(180) NOT NULL,
  company VARCHAR(180) NOT NULL,
  job_type VARCHAR(80) DEFAULT NULL,
  salary VARCHAR(80) DEFAULT NULL,
  experience VARCHAR(120) DEFAULT NULL,
  location VARCHAR(180) DEFAULT NULL,
  description TEXT,
  status VARCHAR(40) DEFAULT 'open',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_jobs_recruiter FOREIGN KEY (recruiter_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 6) Applications by job seekers
CREATE TABLE IF NOT EXISTS applications (
  id INT AUTO_INCREMENT PRIMARY KEY,
  job_id INT NOT NULL,
  seeker_id INT NOT NULL,
  status VARCHAR(40) DEFAULT 'Applied',
  withdrawal_reason VARCHAR(255) DEFAULT NULL,
  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_job_seeker (job_id, seeker_id),
  CONSTRAINT fk_app_job FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
  CONSTRAINT fk_app_seeker FOREIGN KEY (seeker_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Optional: create admin row in DB (static login does NOT require this)
-- INSERT INTO users (name,email,password,role)
-- VALUES ('Admin','admin@careerconnect.local','$2a$10$replace_with_real_bcrypt_hash','admin');
