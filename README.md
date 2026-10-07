# Enterprise Multi-Tenant Security Gateway

CSC337 Lab Assignment 05: Hybrid authentication (local bcrypt + Google/GitHub OAuth 2.0), access/refresh token rotation, Role-Based Access Control and OWASP hardening.

**Stack:** Node.js, Express 4, MySQL / MariaDB (XAMPP locally), Passport.js, JWT, bcrypt, Helmet.

- Live app: `https://YOUR-APP.up.railway.app`
- API base URL: `https://YOUR-APP.up.railway.app/api/v1`

## Test credentials

| Role | Email | Password |
|------|-------|----------|
| SuperAdmin | `superadmin@gateway.test` | `SuperAdmin@123` |
| Manager | `manager@gateway.test` | `Manager@123` |
| Employee | `employee@gateway.test` | `Employee@123` |

These accounts are created automatically on startup when `SEED_ON_START=true` (or run `npm run seed`). Only bcrypt hashes are stored in the database.

## Features and where they live

| Requirement | Implementation |
|-------------|----------------|
| Register / login | `src/routes/auth.js` (`/register`, `/login`) |
| Bcrypt hashing | `bcryptjs`, cost factor 12, unique salt per hash. No plain-text passwords stored. |
| Rate limiting | `express-rate-limit`: max **5 failed logins per 15 min per IP** (`src/middleware/rateLimit.js`) |
| Account lockout | 5 failed attempts on an account locks it for 15 min (HTTP 423), stored in the database |
| Google / GitHub OAuth | Passport.js strategies in `src/config/passport.js`, CSRF `state` check on callback |
| Profile sync | OAuth users are found by provider id or email, linked, and profile (name, avatar) refreshed |
| Access token | JWT, 15 min, sent as `Authorization: Bearer <token>` |
| Refresh token | JWT, 7 days, **httpOnly + Secure + SameSite=Strict** cookie |
| Rotation | `POST /auth/refresh` revokes the used token and issues a new one in the same family |
| Reuse detection | Replaying an old refresh token revokes the whole token family |
| Revocation | `POST /auth/logout` revokes the family and clears the cookie; deleting a user removes their tokens |
| RBAC | `checkRole([...])` middleware in `src/middleware/auth.js` |
| Helmet | Full header set with a strict Content-Security-Policy |
| Strict CORS | Allowlist from `CORS_ORIGINS`, credentials enabled, only needed methods/headers |
| Injection protection | All SQL uses parameterized queries (`mysql2` prepared statements); `src/middleware/sanitize.js` strips operator keys and HTML/script (XSS); inputs are type- and format-checked; ids must be whole numbers |
| Other | 10 kb body limit, no stack traces in errors, generic login error, role never accepted from request body |

## Database

MySQL/MariaDB with two tables, created automatically on first start (no SQL import needed):

- `users` (id, name, email, password_hash, role, tenant_id, google_id, github_id, avatar, failed_login_attempts, lock_until, timestamps)
- `refresh_tokens` (jti, user_id, family, revoked, expires_at), linked to users with `ON DELETE CASCADE`

## API

| Method | Route | Access |
|--------|-------|--------|
| POST | `/api/v1/auth/register` | Public (always creates `Employee`) |
| POST | `/api/v1/auth/login` | Public, rate limited |
| POST | `/api/v1/auth/refresh` | Needs refresh cookie |
| POST | `/api/v1/auth/logout` | Revokes refresh token |
| GET | `/api/v1/auth/google`, `/github` | Starts OAuth |
| GET | `/api/v1/auth/me` | Any authenticated user |
| GET | `/api/v1/employee/profile` | SuperAdmin, Manager, Employee |
| POST | `/api/v1/payroll/approve` | Manager, SuperAdmin |
| GET | `/api/v1/users` | SuperAdmin |
| DELETE | `/api/v1/users/:id` | SuperAdmin |

Payroll approve body: `{ "employeeId": 3, "amount": 1500, "period": "2026-10" }` (use an id from `GET /users`).

## Run locally with XAMPP

1. Open the XAMPP Control Panel and **Start MySQL** (Apache is not needed).
2. In the project folder:
   ```bash
   npm install
   copy .env.example .env      # Windows (use cp on Mac/Linux)
   ```
3. Edit `.env`: set the two token secrets (see below) and `COOKIE_SECURE=false`. The default XAMPP database settings (`root`, empty password, `localhost:3306`) already work.
4. `npm run dev`. You should see `MySQL connected` and three `Seeded ...` lines. The database `security_gateway` appears in phpMyAdmin (http://localhost/phpmyadmin).
5. Open http://localhost:5000.

Generate a secret (run twice, once per secret):
```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

## Environment variables

See `.env.example`. Required: `ACCESS_TOKEN_SECRET`, `REFRESH_TOKEN_SECRET`. Database: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` (and `DB_SSL=true` if the host needs TLS). For deployment also set `APP_URL` and `CORS_ORIGINS`.

## Set up OAuth

**GitHub:** GitHub, Settings, Developer settings, OAuth Apps, New OAuth App. Callback URL: `https://YOUR-APP.up.railway.app/api/v1/auth/github/callback` (create a second app with `http://localhost:5000/api/v1/auth/github/callback` for local testing). Copy into `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`.

**Google:** Google Cloud Console, APIs and Services, Credentials, OAuth client ID (Web application). Authorized redirect URI: `https://YOUR-APP.up.railway.app/api/v1/auth/google/callback`. Copy into `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`.

## Deploy on Railway (app + MySQL)

XAMPP's MySQL only exists on your laptop, so the live deployment needs a hosted MySQL. Railway provides both in one project.

1. Push this repo to GitHub as a **public** repository.
2. On railway.com: New Project, Deploy from GitHub repo, pick this repo.
3. In the same project: New, Database, **Add MySQL**.
4. Open the app service, Variables, and add:
   - `NODE_ENV=production`
   - `ACCESS_TOKEN_SECRET`, `REFRESH_TOKEN_SECRET` (new random values)
   - `SEED_ON_START=true`
   - `MYSQLHOST=${{MySQL.MYSQLHOST}}`, `MYSQLPORT=${{MySQL.MYSQLPORT}}`, `MYSQLUSER=${{MySQL.MYSQLUSER}}`, `MYSQLPASSWORD=${{MySQL.MYSQLPASSWORD}}`, `MYSQLDATABASE=${{MySQL.MYSQLDATABASE}}`
5. Settings, Networking, **Generate Domain**. Then add `APP_URL=https://<that-domain>` and `CORS_ORIGINS=https://<that-domain>` and redeploy.
6. Open the URL and log in with the test accounts.

Start command is `npm start` (Railway detects it). Do not set `COOKIE_SECURE` in production.

## Viva cheat sheet (Postman)

1. **Rate limit / lockout:** use a throwaway account (register one) and send `POST /auth/login` with a wrong password. After 5 failures the account locks (423) and further attempts from your IP get 429 for 15 minutes. Do this demo last, since it blocks logins from your IP for 15 minutes.
2. **Refresh rotation:** login (Postman stores the cookie), call `POST /auth/refresh` and note the new cookie. Re-send the *old* cookie value and you get 401 "reuse detected".
3. **RBAC rejection:** login as Employee, call `POST /payroll/approve` or `DELETE /users/:id` and get **403**. Login as SuperAdmin and the same calls succeed.
4. **OAuth:** click "Continue with Google/GitHub" on the home page. You land back signed in with role Employee.

**If you get locked out while testing:** restart the server (this clears the IP rate limit) and run this in phpMyAdmin (SQL tab) or the MySQL console to clear account locks:
```sql
UPDATE security_gateway.users SET failed_login_attempts = 0, lock_until = NULL;
```

## Security notes

- Self-registered and social users are always `Employee`. Promote roles directly in the `users` table.
- Access tokens live only in JavaScript memory in the demo page; the refresh token is never readable by JavaScript.
- Refresh tokens are tracked server-side (`refresh_tokens` table, expired rows purged hourly), which is what makes rotation and revocation possible.
