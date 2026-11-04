import os

# Юнит-тесты работают на SQLite в режиме разработки; PostgreSQL — в docker compose.
os.environ.setdefault("GRC_DEV_MODE", "1")
os.environ.setdefault("GRC_DATABASE_URL", "sqlite+pysqlite:///:memory:")
