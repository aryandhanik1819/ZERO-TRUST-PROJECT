# ============================================================
#  database.py — SQLAlchemy Database Engine & Session Factory
# ============================================================
#
#  WHAT IS THIS?
#  This is the single entry point for all database operations.
#  Every module that needs to read or write persistent data
#  imports from here.
#
#  WHY SQLALCHEMY?
#  SQLAlchemy is the de-facto Python ORM. It lets us:
#    1. Define tables as Python classes (models.py)
#    2. Write queries in Python instead of raw SQL
#    3. Swap databases (SQLite → PostgreSQL) with ONE config change
#    4. Get connection pooling, transactions, and migrations for free
#
#  WHY SQLite?
#  - Zero setup — ships with Python, no server to install
#  - Perfect for development and single-node deployments
#  - Same SQL semantics as PostgreSQL for our use case
#  - Upgrade path: just change the DATABASE_URL string
#
#  ARCHITECTURE:
#    database.py  → engine + SessionLocal (this file)
#    models.py    → table definitions (ORM models)
#    modules      → import get_db() for request-scoped sessions
# ============================================================

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from config.settings import config


# ── Engine ────────────────────────────────────────────────────
# The engine manages the actual database connection.
# echo=False in production to avoid logging every SQL statement.

# Ensure the data directory exists for SQLite
_db_dir = os.path.dirname(config.database_url.replace("sqlite:///", ""))
if _db_dir:
    os.makedirs(_db_dir, exist_ok=True)

engine = create_engine(
    config.database_url,
    # SQLite requires this for multi-threaded access (FastAPI is async)
    connect_args={"check_same_thread": False},
    echo=config.debug,  # Print SQL statements only in debug mode
)


# ── Session Factory ───────────────────────────────────────────
# Each API request gets its own session (unit of work).
# autocommit=False: we explicitly commit or rollback.
# autoflush=False:  we control when pending changes are sent to DB.

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)


# ── Declarative Base ─────────────────────────────────────────
# All ORM models inherit from this base class.
# It provides the mapping between Python classes and DB tables.

Base = declarative_base()


# ── Database Initialization ──────────────────────────────────

def init_db():
    """
    Create all tables defined in models.py.

    Uses CREATE TABLE IF NOT EXISTS — safe to call multiple times.
    On first run: creates the schema.
    On subsequent runs: no-op (tables already exist).

    IMPORTANT: Import models BEFORE calling this so Base knows
    about all the table classes.
    """
    import models  # noqa: F401 — registers models with Base
    Base.metadata.create_all(bind=engine)


def get_db():
    """
    FastAPI dependency — provides a database session per request.

    Usage in endpoints:
        @app.get("/example")
        def example(db: Session = Depends(get_db)):
            ...

    The session is automatically closed after the request completes,
    even if an exception occurs.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
