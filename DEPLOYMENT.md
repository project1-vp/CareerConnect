# CareerConnect Deployment Guide

This project is now prepared so one Node.js service can host both:

- the website pages
- the `/api` backend

## Easiest option

Use Render for the website and Railway MySQL or Render MySQL for the database.

## Before you start

You need:

- a GitHub account
- a Render account
- a MySQL database

## Step 1: Put the project on GitHub

1. Create a new GitHub repository.
2. Upload this whole project.
3. Make sure `.env` is not uploaded.

## Step 2: Create a MySQL database

Create a hosted MySQL database on Render or Railway.

After it is created, collect these values:

- host
- database name
- username
- password
- port if provided

## Step 3: Run the database schema

Run the SQL from:

- `jbbackend/schema.sql`

Optional sample data:

- `jbbackend/seed_jobs.sql`

## Step 4: Deploy on Render

1. Open Render dashboard.
2. Click `New +`.
3. Click `Web Service`.
4. Connect your GitHub repository.
5. Render should detect the included `render.yaml`.
6. If asked:
   - Build Command: `npm install`
   - Start Command: `npm start`

## Step 5: Add environment variables on Render

Add these:

```env
DB_HOST=your-db-host
DB_PORT=3306
DB_USER=your-db-user
DB_PASSWORD=your-db-password
DB_NAME=jobportal
JWT_SECRET=replace_with_a_strong_secret
API_BASE_URL=https://your-render-url.onrender.com
```

Render usually provides `PORT` automatically, so you do not need to set it manually there.

## Step 6: Test the live site

After deploy finishes, open:

- `/`
- `/explore`
- `/api/health`

Example:

```text
https://your-app-name.onrender.com/api/health
```

## Step 7: Show it on Google

Google does not host the site for you. Google only finds and lists it.

After your site is live:

1. Buy or connect a custom domain if you want.
2. Open Google Search Console.
3. Add your website property.
4. Verify ownership.
5. Submit your homepage URL.

## Important note

Resume uploads are currently stored in the server filesystem. That is okay for testing, but for a serious production site we should later move uploads to cloud storage.
