# Aurora — Registration & Auth System

A production-ready, full-stack registration and sign-in experience built with **HTML5, CSS3, vanilla JavaScript, and Flask**. No frontend frameworks, no CSS libraries — every animation, layout, and interaction is hand-built.

![Aurora preview](static/images/preview-placeholder.svg)

## Overview

Aurora is a portfolio-grade auth flow: a split-screen sign-up/sign-in card with a glassmorphic, animated mesh-gradient background, a 3-step registration wizard, live validation, and a Flask + SQLite backend with real security practices (hashed passwords, CSRF protection, rate limiting, sanitized inputs).

It's intentionally scoped to the essentials a recruiter or reviewer actually checks: does the UI feel considered, does the backend do the boring security work correctly, and is the code easy to read.

## Features

**Design**
- Split-screen layout with an animated aurora/mesh-gradient brand panel
- Glassmorphism card with a cursor-tracked spotlight border
- Full dark mode / light mode with persisted preference
- Floating labels, focus glow, shake-on-error, success checkmarks
- Fully responsive — collapses to a single column on tablet/mobile

**Registration flow**
- 3-step wizard (Account → Security → Confirmation) with animated progress bar
- Live email + name validation, with an async "email already taken" check
- Password strength meter (Weak / Medium / Strong / Very strong) with a live 5-point checklist
- Password show/hide toggle
- Terms, Privacy, and optional newsletter checkboxes
- Animated primary button: ripple → loading spinner → success checkmark
- Toast notifications (success / error / warning / info)

**Sign-in flow**
- Sliding tab switch between Sign In / Sign Up
- "Remember me" + forgot-password placeholder
- Same validation and animation language as sign-up

**Social login**
- Google / Apple / GitHub buttons with proper SVG marks and hover states (wire up real OAuth via `authlib` or `flask-dance` when you're ready — the UI is ready to go)

**Backend & security**
- Flask app factory-style structure with SQLite auto-created on first run
- Passwords hashed with `werkzeug.security` (PBKDF2-SHA256)
- CSRF protection via Flask-WTF on every state-changing request
- Server-side validation mirrors the client-side rules — never trust the client
- Parameterized SQL everywhere (no string-built queries)
- Simple in-memory sliding-window rate limiting on `/api/register` and `/api/login`
- Secure session cookies (`HttpOnly`, `SameSite=Lax`, `Secure` in production)
- Centralized error handlers for 400/404/429/500

## Screenshots

> Add real screenshots or a short screen recording here once you've run the app locally — a light-mode and dark-mode shot of the sign-up card side by side works well.

| Sign up | Dark mode |
|---|---|
| _add screenshot_ | _add screenshot_ |

## Requirements

- Python 3.9+
- pip

## Installation

```bash
git clone https://github.com/your-username/aurora-auth.git
cd aurora-auth

python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

## How to run

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser. The SQLite database (`database.db`) and its `users` table are created automatically on first run.

For production, set a real secret key and enable secure cookies:

```bash
export SECRET_KEY="replace-with-a-long-random-value"
export FLASK_ENV=production
```

## Folder structure

```
aurora-auth/
├── app.py                  # Flask app: routes, validation, security
├── requirements.txt
├── README.md
├── .gitignore
├── database.db              # created automatically, git-ignored
├── templates/
│   ├── index.html            # sign up / sign in page
│   └── dashboard.html        # post-auth landing page
└── static/
    ├── css/
    │   └── style.css          # design tokens, layout, components, animations
    ├── js/
    │   └── script.js          # validation, wizard, theme, toasts, API calls
    └── images/
```

## API

| Method | Route               | Description                          |
|--------|---------------------|---------------------------------------|
| GET    | `/`                  | Sign up / sign in page                |
| POST   | `/api/register`      | Create an account (JSON)              |
| POST   | `/api/login`         | Authenticate (JSON)                   |
| GET    | `/api/check-email`   | Live email-availability check         |
| GET    | `/dashboard`         | Authenticated landing page            |
| GET    | `/logout`            | Clear session                         |

## Contributing

Issues and pull requests are welcome. For larger changes, please open an issue first to discuss what you'd like to change.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/thing`)
3. Commit your changes
4. Open a pull request

## Future improvements

- Real OAuth for Google / Apple / GitHub (e.g. via `authlib`)
- Email verification and password-reset flow
- Move rate limiting to Redis for multi-process deployments
- Swap SQLite for PostgreSQL in production
- Add automated tests (pytest) for routes and validation
- Add a `flask-limiter`-based rate limiter for horizontal scaling

## License

Released under the [MIT License](LICENSE) — free to use for personal and commercial projects.
