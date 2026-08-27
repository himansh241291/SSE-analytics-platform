import os
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI
import clickhouse_connect

app = FastAPI(title="SSE Analytics API", version="0.1.0")


def ch():
    return clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST", "localhost"),
        port=int(os.getenv("CLICKHOUSE_HTTP_PORT", "8123")),
        database=os.getenv("CLICKHOUSE_DB", "sse"),
    )


@app.get("/health")
def health():
    try:
        client = ch()
        client.command("SELECT 1")
        client.close()
        return {"status": "ok", "clickhouse": "ok"}
    except Exception as exc:
        return {"status": "degraded", "clickhouse": "unavailable", "error": str(exc)}


@app.get("/api/overview")
def overview(hours: int = 24):
    client = ch()
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    result = client.query("""
        SELECT
          count() AS events,
          countIf(severity IN ('HIGH','CRITICAL')) AS high_severity,
          countIf(action IN ('BLOCK','BLOCKED','DENY','DENIED')) AS blocked,
          countIf(source_type = 'dlp') AS dlp,
          uniqExactIf(user_identity, user_identity != '') AS users
        FROM sse.events
        WHERE event_time >= {since:DateTime}
    """, parameters={"since": since})
    row = result.result_rows[0]
    client.close()
    return {
        "events": row[0],
        "high_severity": row[1],
        "blocked": row[2],
        "dlp": row[3],
        "users": row[4],
        "hours": hours,
    }


@app.get("/api/recent")
def recent(limit: int = 50):
    client = ch()
    result = client.query("""
        SELECT event_time, source_type, user_identity, source_ip,
               destination, action, severity, category
        FROM sse.events
        ORDER BY event_time DESC
        LIMIT {limit:UInt32}
    """, parameters={"limit": limit})
    rows = [dict(zip(result.column_names, r)) for r in result.result_rows]
    client.close()
    return rows
