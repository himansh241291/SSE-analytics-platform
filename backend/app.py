import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import clickhouse_connect
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SSE Analytics API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
def overview(hours: int = Query(24, ge=1, le=720)):
    client = ch()
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    query = """
        SELECT
          count() AS events,
          countIf(upper(severity) IN ('HIGH','CRITICAL')) AS high_severity,
          countIf(upper(action) IN ('BLOCK','BLOCKED','DENY','DENIED')) AS blocked,
          countIf(source_type = 'dlp') AS dlp,
          uniqExactIf(user_identity, user_identity != '') AS users,
          countIf(source_type = 'dns') AS dns_events,
          countIf(source_type = 'proxy') AS proxy_events,
          countIf(source_type = 'firewall') AS firewall_events,
          countIf(source_type = 'ztna') AS ztna_events
        FROM sse.events
        WHERE event_time >= {since:DateTime}
    """
    result = client.query(query, parameters={"since": since})
    row = result.result_rows[0]
    client.close()
    return {
        "events": row[0],
        "high_severity": row[1],
        "blocked": row[2],
        "dlp": row[3],
        "users": row[4],
        "dns_events": row[5],
        "proxy_events": row[6],
        "firewall_events": row[7],
        "ztna_events": row[8],
        "hours": hours,
    }


@app.get("/api/timeline")
def timeline(hours: int = Query(24, ge=1, le=720)):
    client = ch()
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    result = client.query("""
        SELECT
            toStartOfHour(event_time) AS bucket,
            count() AS events,
            countIf(upper(action) IN ('BLOCK','BLOCKED','DENY','DENIED')) AS blocked,
            countIf(upper(severity) IN ('HIGH','CRITICAL')) AS high_severity
        FROM sse.events
        WHERE event_time >= {since:DateTime}
        GROUP BY bucket
        ORDER BY bucket
    """, parameters={"since": since})
    rows = [
        {
            "timestamp": r[0].isoformat(sep=" "),
            "events": r[1],
            "blocked": r[2],
            "high_severity": r[3],
        }
        for r in result.result_rows
    ]
    client.close()
    return rows


@app.get("/api/by-source")
def by_source(hours: int = Query(24, ge=1, le=720)):
    client = ch()
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    result = client.query("""
        SELECT source_type, count() AS events
        FROM sse.events
        WHERE event_time >= {since:DateTime}
        GROUP BY source_type
        ORDER BY events DESC
    """, parameters={"since": since})
    rows = [{"source": r[0], "events": r[1]} for r in result.result_rows]
    client.close()
    return rows


@app.get("/api/top-users")
def top_users(limit: int = Query(10, ge=1, le=100), hours: int = Query(24, ge=1, le=720)):
    client = ch()
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    result = client.query("""
        SELECT user_identity, count() AS events,
               countIf(upper(action) IN ('BLOCK','BLOCKED','DENY','DENIED')) AS blocked
        FROM sse.events
        WHERE event_time >= {since:DateTime} AND user_identity != ''
        GROUP BY user_identity
        ORDER BY events DESC
        LIMIT {limit:UInt32}
    """, parameters={"since": since, "limit": limit})
    rows = [{"user": r[0], "events": r[1], "blocked": r[2]} for r in result.result_rows]
    client.close()
    return rows


@app.get("/api/recent")
def recent(limit: int = Query(50, ge=1, le=500)):
    client = ch()
    result = client.query("""
        SELECT event_time, source_type, user_identity, source_ip,
               destination, action, severity, category, event_correlation_id
        FROM sse.events
        ORDER BY event_time DESC
        LIMIT {limit:UInt32}
    """, parameters={"limit": limit})
    rows = [dict(zip(result.column_names, r)) for r in result.result_rows]
    client.close()
    return rows
