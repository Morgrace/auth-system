# GoAuth – Secure Authentication System

A RESTful authentication and authorization system built in Go.  
Uses **JWT access tokens** (RS256), **refresh token rotation**, **HttpOnly cookies** (optional), **PostgreSQL**, and **SMTP** for email verification and password reset.

## Features

- User registration with email verification
- Login with access + refresh tokens
- Refresh token rotation & reuse detection
- Forgot / reset password flow
- Role-based access (user, admin, super_admin)
- Soft delete accounts
- Secure password hashing (argon2d)
- SHA-256 hashing of all stored tokens
- Request-scoped logging with request ID
- Graceful shutdown

## Tech Stack

- **Go** 1.22+
- **PostgreSQL** (with `uuid-ossp`)
- **sqlx** + **pgx** for database
- **golang-migrate** for schema migrations
- **jwt-go** (RS256)
- **SMTP** (Brevo / any provider)

## Project Structure

```
.
├── cmd/api/               # entry point (main.go)
├── internal/
│   ├── auth/              # authentication feature
│   ├── user/              # user profile feature
│   ├── dashboard/         # placeholder dashboard endpoints
│   ├── config/            # environment config
│   ├── database/          # DB connection & migrations
│   ├── middleware/        # JWT auth & role middleware
│   ├── mailer/            # SMTP email sender
│   ├── validator/         # request validation
│   └── router/            # central router mounting
├── migrations/            # SQL up/down migrations
├── pkg/utils/             # shared utilities (JWT, passwords, responses)
├── .env.example           # template for environment variables
└── README.md
```

## Getting Started

### 1. Prerequisites

- Go 1.22+
- PostgreSQL (local or Docker)
- SMTP account (e.g., Brevo, Mailgun, or MailHog for testing)

### 2. Clone & Install

```bash
git clone https://github.com/Morgrace/auth-system
cd auth-system
go mod download
```

### 3. Configure Environment

Copy `.env.example` to `.env` and fill in your values:

```ini
# App
APP_ENV=development
APP_PORT=8080

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=yourpassword
DB_NAME=goauth

# JWT (RSA keys – use escaped newlines or base64)
JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
JWT_ACCESS_TOKEN_EXPIRY=15m
JWT_REFRESH_TOKEN_EXPIRY=168h

# SMTP (example for Brevo)
SMTP_HOST=smtp-relay.brevo.com
SMTP_PORT=465
SMTP_USERNAME=your_brevo_login
SMTP_PASSWORD=your_brevo_smtp_key
SMTP_FROM=noreply@yourapp.com
CLIENT_URL=http://localhost:3000
```

### 4. Run Database Migrations

Migrations run automatically when the server starts.  
To run them manually:

```bash
migrate -path ./migrations -database "postgres://user:pass@localhost:5432/goauth?sslmode=disable" up
```

### 5. Start the Server

```bash
go run cmd/api/main.go
```

You'll see:

```
Database connected successfully 🌐
Database schema migrations applied successfully 🚀
🌐 Server starting on port 8080
```

## API Endpoints

Base URL: `http://localhost:8080/api/v1`

| Method | Endpoint                         | Description                      | Auth |
| ------ | -------------------------------- | -------------------------------- | ---- |
| POST   | `/auth/register`                 | Register a new user              | No   |
| POST   | `/auth/login`                    | Login, returns tokens            | No   |
| POST   | `/auth/refresh-token`            | Rotate refresh token             | No   |
| POST   | `/auth/verify-email?token=...`   | Verify email address             | No   |
| POST   | `/auth/resend-verification`      | Resend verification email        | No   |
| POST   | `/auth/forgot-password`          | Send password reset link         | No   |
| POST   | `/auth/reset-password?token=...` | Reset password                   | No   |
| POST   | `/auth/logout`                   | Revoke refresh token             | Yes  |
| PUT    | `/user/password`                 | Change password                  | Yes  |
| PATCH  | `/user/profile`                  | Update first/last name           | Yes  |
| DELETE | `/user`                          | Soft delete account              | Yes  |
| GET    | `/public/dashboard`              | Public dashboard (authenticated) | Yes  |
| GET    | `/user/dashboard`                | User dashboard                   | Yes  |
| GET    | `/admin/dashboard`               | Admin dashboard                  | Yes  |
| GET    | `/super-admin/dashboard`         | Super admin dashboard            | Yes  |

> **Authentication**: Include the access token in the `Authorization: Bearer <token>` header for protected routes.  
> **Refresh token** is returned in the JSON response — store it in `localStorage` or an HttpOnly cookie depending on your frontend.

## Testing with Postman

1. **Register** – `POST /auth/register` with JSON body
2. **Login** – copy the `access_token` and `refresh_token`
3. Use the access token in the `Authorization` header for protected routes
4. Call `/auth/refresh-token` with the refresh token to get a new pair

## Environment Switching

- `APP_ENV=development` – uses localhost, more verbose logs
- `APP_ENV=production` – should disable debug output, set secure cookies (not yet implemented)

## Security Notes

- All tokens (email verification, password reset, refresh) are stored as SHA-256 hashes
- Passwords are bcrypt-hashed (cost 12)
- Refresh token rotation: every refresh issues a new token and revokes the old one
- Reuse of a revoked token revokes the entire token family
- Role middleware prevents privilege escalation

## Next Steps / Improvements

- Add rate limiting on `/auth/*` endpoints
- Implement CORS for frontend integration
- Add structured logging (e.g., `slog` or `logrus`)
- Write integration tests
- Deploy to a cloud environment (Render, Fly.io, AWS)

## License

MIT
