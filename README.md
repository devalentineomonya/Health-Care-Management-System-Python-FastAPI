# Health Care Management System — Python / FastAPI

This repository implements a Health Care Management System API using FastAPI. It includes services for appointments, doctors, patients, users, and a notification worker.

Maintainers
- Repository owner: turabbb
- Primary contributor (this branch): umarm

Quickstart (local)

1. Create a virtual environment and activate it:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Run the API locally:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

4. Run tests:

```powershell
pip install pytest
pytest -q
```

Docker / Compose

This project includes a `Dockerfile` and `docker-compose.yml`. To run with Docker Compose:

```powershell
docker-compose up --build
```

Repository layout (key files)
- `app/` — FastAPI application and routes
- `core/` — configuration, security helpers, notifications
- `crud/` — CRUD layer for DB models
- `db/` — SQLAlchemy models and session
- `schemas/` — Pydantic schemas
- `tests/` — pytest tests (basic smoke tests on this branch)

Notes
- This branch `feat/testing-docs` adds baseline tests and documentation.
- For issues or contributions, open a pull request against `main` and assign to `turabbb`.
