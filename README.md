# Ash-agent

## Deployment & Auth

- API server: runs on `http://127.0.0.1:5000` (run `ash_advisor-1.py`).
- Static UI: served on `http://127.0.0.1:8080` (run `app.py`).
- Authentication: only the single admin email `kevlarmackenzie@gmail.com` is authorised by default.
	- The server checks the `ADMIN_EMAIL` environment variable (default `kevlarmackenzie@gmail.com`).
	- To change the admin email, set `ADMIN_EMAIL` before starting the server:

```
export ADMIN_EMAIL=kevlarmackenzie@gmail.com
```

- To run both services locally:

```
export GEMINI_API_KEY=your_key_here   # optional: for chat features
export ADMIN_EMAIL=kevlarmackenzie@gmail.com
python ash_advisor-1.py   # starts API + WS on port 5000
python app.py             # serves ash_advisor-1.html on port 8080
```

Notes:
- The UI (`ash_advisor-1.html`) posts login requests to `http://127.0.0.1:5000/api/login`.
- The server-side login enforces the single authorised email; the UI itself does not restrict the input client-side.
