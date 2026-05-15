---
title: SEC006 — SQL Injection via String Interpolation
sidebar_label: SEC006
description: Flags SQL queries built with string interpolation
---

# SEC006-sql-injection — SQL Injection via String Interpolation

**Dimension:** Security
**Default severity:** High
**CWE:** CWE-89
**OWASP:** A03:2021 – Injection
**Languages:** All
**Last reviewed:** 2026-05-06

## What it detects

Flags source lines where a SQL keyword appears together with string interpolation, indicating that user-controlled data may be spliced directly into a SQL query.

A finding is emitted for each line satisfying **all three** conditions:

1. **SQL keyword** — the line matches (case-insensitive): `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, `FROM`, `JOIN`, or `WHERE`.

2. **Quote character** — the line contains `"`, `'`, or a backtick.

3. **Interpolation marker** — the line contains at least one of:
   - Python f-string: `f"…{` or `f'…{`
   - Python percent-format: `% (`
   - Method call: `.format(`
   - JS/TS template literal: `${`
   - String concatenation: `" + ` / `' + ` / `` ` + ``

One finding is emitted per matching line.

## Why it matters

SQL injection is the most prevalent injection vulnerability. Constructing SQL queries by string concatenation or interpolation allows an attacker to modify the query logic, extract data, modify records, or execute commands. OWASP A03:2021 (Injection) consistently appears near the top of the OWASP Top 10.

## Configuration

This rule has no configurable threshold. Disable per project:

```toml
[rules.SEC006-sql-injection]
enabled = false
```

## Examples flagged

**Python** — f-string interpolation:

```python
def get_user(conn, username: str):
    query = f"SELECT * FROM users WHERE name = '{username}'"  # flagged
    return conn.execute(query)
```

**Python** — percent-format interpolation:

```python
def delete_record(conn, table: str, record_id: int):
    sql = "DELETE FROM %s WHERE id = %d" % (table, record_id)  # flagged
    conn.execute(sql)
```

**JS/TS** — template literal:

```typescript
export function getUser(db: any, userId: string): Promise<any> {
  const query = `SELECT * FROM users WHERE id = ${userId}`;  // flagged
  return db.query(query);
}
```

## Examples not flagged

**Python** — parameterised query with `?` placeholder:

```python
def get_user(conn, user_id: int):
    conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # not flagged
```

**Python** — static SQL with no interpolation:

```python
def count_users(conn):
    return conn.execute("SELECT COUNT(*) FROM users").fetchone()  # not flagged
```

## Fix guidance

- Use **parameterised queries** / **prepared statements** in every database client library:
  - Python (sqlite3): `cursor.execute("SELECT … WHERE id = ?", (user_id,))`
  - Python (SQLAlchemy): use `text()` with bound parameters or the ORM query API
  - Node.js (pg, mysql2): `client.query("SELECT … WHERE id = $1", [userId])`
  - Knex / Sequelize: use builder methods that bind parameters automatically
- Never construct SQL via f-strings, `%` formatting, `.format()`, or `+` concatenation with values that originate from user input.

## Implementation

- Source: [crates/zuit-analyzers/src/sql_injection.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/sql_injection.rs)
- Severity / supported languages: see `RuleMeta` in source.

## References

- [OWASP A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-89: Improper Neutralisation of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
