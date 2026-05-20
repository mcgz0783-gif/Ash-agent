# Ash-agent

## Setup & Deployment

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configuration**:
   Create a `.env` file in the root directory:
   ```env
   GEMINI_API_KEY=your_google_ai_key
   ADMIN_EMAIL=kevlarmackenzie@gmail.com
   GEMINI_MODEL=gemini-2.0-flash
   ```

3. **Run the Agent**:
   ```bash
   python ash_advisor.py
   ```

4. **Access the UI**:
   The server now serves both the API and the UI on:
   `http://127.0.0.1:5000/`

## Authentication

- Authentication is restricted to the email defined in `ADMIN_EMAIL`.
- The login process issues a secure hex token stored in the session history.

## Features
- Real-time Terminal (PTY) via WebSockets.
- AI-driven methodology advisor using Gemini 2.0 Flash.
- Automated tool availability checks.
