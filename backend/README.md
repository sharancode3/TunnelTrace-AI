# TunnelTrace AI — Backend Service

The core Python backend service for TunnelTrace AI, providing the REST/WebSocket API, database persistence, asynchronous worker tasks, and protocol analysis engines.

## Runtime Architecture (Stage 1)
- **FastAPI (ASGI):** Asynchronous API layer with typed Pydantic Settings and standard error envelopes.
- **SQLAlchemy 2.x + asyncpg:** Async PostgreSQL connection pooling and schema management.
- **Alembic:** Versioned database migrations (initial migration enables `pgvector`).
- **Redis & Celery:** Transient queue broker and background task execution runtime.
- **Local Storage Provider:** Path-safe local file and artifact storage abstraction.

## Local Developer Setup

1. **Activate virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Or on Windows: .venv\Scripts\activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -e ".[dev]"
   ```

3. **Run local migrations:**
   ```bash
   alembic upgrade head
   ```

4. **Start the API service:**
   ```bash
   uvicorn app.main:create_app --factory --reload --port 8000
   ```

5. **Run tests:**
   ```bash
   pytest
   ```
