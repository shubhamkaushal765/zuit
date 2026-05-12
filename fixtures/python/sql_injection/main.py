"""Positive fixture for SEC006-sql-injection: builds SQL strings via interpolation."""

import sqlite3


def get_user(conn: sqlite3.Connection, username: str):
    """Fetch a user by name using unsafe string interpolation."""
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return conn.execute(query)


def delete_record(conn: sqlite3.Connection, table: str, record_id: int):
    """Delete a record using percent-format interpolation."""
    sql = "DELETE FROM %s WHERE id = %d" % (table, record_id)
    conn.execute(sql)
