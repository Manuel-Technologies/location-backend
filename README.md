# Location Backend (Single-folder, simple & robust)

Minimal realtime location backend that is easy to run from a phone or small server.

## Features
- Express REST (register/login/me/recent)
- Socket.IO realtime (snapshot, userMoved, userLeft)
- JWT auth & bcrypt password hashing
- File-backed persistence in `users.json` (no external DB needed)
- Atomic file writes + capped persisted locations
- Small rate-limiter on auth endpoints

## Files (single folder)
- `server.js`       — main server (copy/paste this file)
- `package.json`    — dependencies & start script
- `.env.example`    — environment variables (copy to `.env`)
- `users.json`      — initial store (keep at root)
- `README.md`       — this file

## Quick start (Termux or any Node host)
1. Install Node >= 16 and Git (if needed).
2. Create folder and add files above.
3. `cp .env.example .env` and edit values (set JWT_SECRET).
4. Install:
   ```bash
   npm install