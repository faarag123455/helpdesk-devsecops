from collections.abc import Generator
from contextlib import contextmanager

import psycopg2
from psycopg2.extensions import connection

from config import Config


@contextmanager
def get_db_connection() -> Generator[connection, None, None]:
    conn = psycopg2.connect(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        dbname=Config.DB_NAME,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
    )
    try:
        yield conn
    finally:
        conn.close()


def fetch_one(query: str, params: tuple[object, ...] = ()) -> dict[str, object] | None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            row = cursor.fetchone()
            if row is None:
                return None
            description = cursor.description
            if description is None:
                raise RuntimeError("Database query did not return columns")
            columns = [column.name for column in description]
            return dict(zip(columns, row))


def execute(query: str, params: tuple[object, ...] = ()) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
        conn.commit()
