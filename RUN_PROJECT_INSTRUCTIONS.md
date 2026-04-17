# CareerConnect Project Run Instructions

This file explains how to run this project from start to end on this PC or on another PC.

## 1. What You Need

Install these first:

- Node.js
- MySQL Server
- phpMyAdmin or MySQL Workbench

## 2. Copy the Project

Copy the full project folder to the new PC.

Project folder:

```text
final year project
```

Important folders/files to keep:

- `jbbackend/`
- `jbbackend/uploads/` if you want old uploaded resumes/files
- all HTML, CSS, and JS files in the root folder

## 3. Export the Database From the Old PC

If you are using phpMyAdmin:

1. Open phpMyAdmin.
2. Select database `jobportal`.
3. Click `Export`.
4. Choose `Quick`.
5. Keep format as `SQL`.
6. Click `Export`.
7. Save the downloaded `.sql` file.

This creates a backup of your project database.

## 4. Import the Database on the New PC

1. Install and start MySQL on the new PC.
2. Open phpMyAdmin.
3. Create a new database named `jobportal`.
4. Open the new `jobportal` database.
5. Click `Import`.
6. Choose the exported `.sql` file.
7. Click `Import`.

## 5. Configure the Backend Environment

Open this file:

`jbbackend/.env`

Use values like this:

```env
PORT=4000
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=
DB_NAME=jobportal
JWT_SECRET=mysecretkey
```

Important:

- If MySQL on the new PC has a password, put that password in `DB_PASSWORD`.
- If MySQL uses another username, update `DB_USER`.
- Keep `DB_NAME=jobportal` unless you imported the database with another name.

## 6. Install Project Dependencies

Open terminal in the project root folder and run:

```bash
npm install
```

Then go to backend folder:

```bash
cd jbbackend
npm install
```

## 7. Start the Project Locally

Inside `jbbackend`, run:

```bash
node server.js
```

Or:

```bash
npm start
```

Do not run:

```bash
node start
```

That command is wrong for this project.

## 8. Open the Project

When the backend starts correctly, you should see:

```text
Server running locally at http://127.0.0.1:4000
MySQL Connected
```

Open this in the browser:

```text
http://127.0.0.1:4000
```

## 9. If You Close the Project

If you close the terminal, the backend stops.

To run the project again later:

1. Open terminal
2. Go to `jbbackend`
3. Run:

```bash
node server.js
```

## 10. Common Errors and Fixes

### Error: `Cannot find module ... start`

Cause:

You used:

```bash
node start
```

Fix:

Use:

```bash
npm start
```

or:

```bash
node server.js
```

### Error: `Access denied for user ''@'localhost'`

Cause:

Database environment values are missing or incorrect.

Fix:

Check `jbbackend/.env` and make sure these are correct:

- `DB_HOST`
- `DB_USER`
- `DB_PASSWORD`
- `DB_NAME`

### Error: Port already in use

Cause:

An old server is still running on port `4000`.

Fix:

Close the old terminal or stop the old Node process, then run again.

## 11. Project Run Summary

Every time you want to run the project:

1. Make sure MySQL is running
2. Open terminal
3. Go to `jbbackend`
4. Run `node server.js`
5. Open `http://127.0.0.1:4000`

## 12. Notes

- This setup is for local use on the PC.
- It does not automatically deploy to Google or make the project live online.
- The backend is set to run locally on `127.0.0.1`.
