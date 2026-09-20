import sqlite3
from pathlib import Path

DB = Path("database/siem_ids.db")
OUT = Path("database/migrate_to_postgres.sql")

tables = [
    "roles",
    "users",
    "password_reset_tokens",
    "login_logs",
    "security_alerts",
    "security_events",
    "audit_logs",
]

boolean_columns = {
    "users": {"is_active_flag", "is_locked"},
    "login_logs": {"success"},
    "security_alerts": {"is_resolved"},
}

def sql_value(table, column, value):
    if value is None:
        return "NULL"

    if column in boolean_columns.get(table, set()):
        return "TRUE" if bool(value) else "FALSE"

    if isinstance(value, bytes):
        return "'\\\\x" + value.hex() + "'"

    if isinstance(value, (int, float)):
        return str(value)

    value = str(value).replace("'", "''")
    return "'" + value + "'"

conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

with OUT.open("w", encoding="utf-8", newline="\n") as f:
    f.write("BEGIN;\n\n")
    f.write("SET session_replication_role = replica;\n\n")

    for table in tables:
        rows = conn.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()

        columns = [d[1] for d in conn.execute(f"PRAGMA table_info({table})").fetchall()]

        f.write(f"-- {table}: {len(rows)} rows\n")

        for row in rows:
            values = [
                sql_value(table, column, row[column])
                for column in columns
            ]

            f.write(
                f"INSERT INTO {table} ({', '.join(columns)}) "
                f"VALUES ({', '.join(values)});\n"
            )

        f.write("\n")

        if rows:
            f.write(
                f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                f"(SELECT MAX(id) FROM {table}), true);\n\n"
            )

    f.write("SET session_replication_role = DEFAULT;\n")
    f.write("COMMIT;\n")

conn.close()

print(f"Migration SQL created: {OUT}")
print(f"Size: {OUT.stat().st_size:,} bytes")
