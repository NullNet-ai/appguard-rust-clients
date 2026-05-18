import { drizzle } from "drizzle-orm/node-postgres";
import { sql } from "drizzle-orm";
import pg from "pg";

import { METRICS_TABLE } from "./schema.js";

const DEFAULT_DATABASE_URL =
  "postgresql://admin:admin@timescale.color.dnamicro.net:5432/forms";

const PROBE_QUERY = sql`
SELECT
    time_bucket('1 minute', time) AS bucket,
    device_id,
    avg(value) AS avg_value,
    count(*) AS cnt
FROM pgpool_sample_metrics
WHERE time >= now() - interval '1 hour'
GROUP BY bucket, device_id
ORDER BY bucket DESC, device_id
`;

function envInt(key: string, fallback: number): number {
  const raw = process.env[key];
  if (raw === undefined || raw === "") return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function log(level: "info" | "warn", msg: string, fields: Record<string, unknown> = {}) {
  const payload = { ts: new Date().toISOString(), level, msg, ...fields };
  const stream = level === "warn" ? process.stderr : process.stdout;
  stream.write(JSON.stringify(payload) + "\n");
}

function elapsedMs(start: bigint): number {
  return Number(process.hrtime.bigint() - start) / 1_000_000;
}

function redactUrl(url: string): string {
  const schemeEnd = url.indexOf("://");
  if (schemeEnd < 0) return url;
  const afterScheme = schemeEnd + 3;
  const at = url.indexOf("@", afterScheme);
  if (at < 0) return url;
  const authority = url.slice(afterScheme, at);
  const colon = authority.indexOf(":");
  if (colon < 0) return url;
  return `${url.slice(0, afterScheme)}${authority.slice(0, colon)}:***${url.slice(at)}`;
}

async function logServerInfo(db: ReturnType<typeof drizzle>) {
  const version = await db.execute<{ version: string }>(sql`SELECT version()`);
  log("info", "server version", { version: version.rows[0]?.version });

  const ts = await db.execute<{ extversion: string }>(
    sql`SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'`,
  );
  if (ts.rows.length > 0) {
    log("info", "timescaledb extension", { version: ts.rows[0].extversion });
  } else {
    log("info", "timescaledb extension not installed");
  }
}

async function setupHypertable(
  db: ReturnType<typeof drizzle>,
  seedRows: number,
) {
  const tableId = sql.identifier(METRICS_TABLE);
  const t0 = process.hrtime.bigint();

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS ${tableId} (
      time TIMESTAMPTZ NOT NULL,
      device_id INT NOT NULL,
      value DOUBLE PRECISION NOT NULL
    )
  `);

  await db.execute(
    sql`SELECT create_hypertable(${METRICS_TABLE}, 'time', if_not_exists => TRUE)`,
  );
  log("info", "hypertable ready", {
    table: METRICS_TABLE,
    elapsed_ms: elapsedMs(t0),
  });

  if (seedRows <= 0) {
    log("info", "SEED_ROWS<=0, skipping seed");
    return;
  }

  const truncStarted = process.hrtime.bigint();
  await db.execute(sql`TRUNCATE ${tableId}`);
  log("info", "truncated metrics", { elapsed_ms: elapsedMs(truncStarted) });

  const seedStarted = process.hrtime.bigint();
  const inserted = await db.execute(sql`
    INSERT INTO ${tableId} (time, device_id, value)
    SELECT
        now() - (interval '1 hour' * (i::float8 / ${seedRows}::float8)),
        (i % 10)::int,
        random() * 100
    FROM generate_series(0, ${seedRows} - 1) AS i
  `);
  log("info", "seeded metrics", {
    rows: inserted.rowCount ?? 0,
    elapsed_ms: elapsedMs(seedStarted),
  });
}

async function runProbeRound(
  pool: pg.Pool,
  round: number,
  concurrency: number,
  queriesPerWorker: number,
) {
  log("info", "round start", {
    round,
    size: pool.totalCount,
    idle: pool.idleCount,
  });
  const started = process.hrtime.bigint();

  const workers = Array.from({ length: concurrency }, async (_, i) => {
    const acqStart = process.hrtime.bigint();
    let client: pg.PoolClient;
    try {
      client = await pool.connect();
    } catch (e) {
      return { i, ok: false as const, error: e };
    }
    const acquireMs = elapsedMs(acqStart);

    try {
      const conn = drizzle(client, { logger: true });
      const qStart = process.hrtime.bigint();
      let totalRows = 0;
      for (let q = 0; q < queriesPerWorker; q++) {
        const result = await conn.execute(PROBE_QUERY);
        totalRows += result.rows.length;
      }
      const queryMs = elapsedMs(qStart);
      return {
        i,
        ok: true as const,
        acquireMs,
        queryMs,
        rows: totalRows,
      };
    } catch (e) {
      return { i, ok: false as const, error: e };
    } finally {
      client.release();
    }
  });

  const results = await Promise.all(workers);

  let ok = 0;
  let err = 0;
  for (const r of results) {
    if (r.ok) {
      ok += 1;
      log("info", "worker ok", {
        round,
        worker: r.i,
        acquire_ms: r.acquireMs,
        total_query_ms: r.queryMs,
        queries: queriesPerWorker,
        rows: r.rows,
      });
    } else {
      err += 1;
      log("warn", "worker error", {
        round,
        worker: r.i,
        error: r.error instanceof Error ? r.error.message : String(r.error),
      });
    }
  }

  log("info", "round done", {
    round,
    elapsed_ms: elapsedMs(started),
    ok,
    err,
    size: pool.totalCount,
    idle: pool.idleCount,
  });
}

async function main() {
  const databaseUrl = process.env.DATABASE_URL ?? DEFAULT_DATABASE_URL;

  const minConnections = envInt("PG_MIN_CONNECTIONS", 2);
  const maxConnections = envInt("PG_MAX_CONNECTIONS", 8);
  const acquireTimeout = envInt("PG_ACQUIRE_TIMEOUT_SECS", 10);
  const idleTimeout = envInt("PG_IDLE_TIMEOUT_SECS", 60);
  const maxLifetime = envInt("PG_MAX_LIFETIME_SECS", 600);
  const probeInterval = envInt("PROBE_INTERVAL_SECS", 5);
  const probeConcurrency = envInt("PROBE_CONCURRENCY", 4);
  const queriesPerWorker = envInt("QUERIES_PER_WORKER", 1);
  const seedRows = envInt("SEED_ROWS", 10_000);

  log("info", "connecting pool", { url: redactUrl(databaseUrl) });
  log("info", "pool config", {
    min: minConnections,
    max: maxConnections,
    acquire_timeout_secs: acquireTimeout,
    idle_timeout_secs: idleTimeout,
    max_lifetime_secs: maxLifetime,
  });
  log("info", "probe schedule", {
    interval_secs: probeInterval,
    concurrency: probeConcurrency,
    queries_per_worker: queriesPerWorker,
    seed_rows: seedRows,
  });

  const t0 = process.hrtime.bigint();
  const pool = new pg.Pool({
    connectionString: databaseUrl,
    min: minConnections,
    max: maxConnections,
    connectionTimeoutMillis: acquireTimeout * 1000,
    idleTimeoutMillis: idleTimeout * 1000,
    maxLifetimeSeconds: maxLifetime,
  });

  pool.on("error", (err) => {
    log("warn", "pool error", { error: err.message });
  });

  // Eagerly open `min` connections to mirror sqlx's min_connections behavior.
  // pg.Pool only opens lazily, so connect+release `min` clients up front.
  const warmup = Array.from({ length: minConnections }, () => pool.connect());
  const warm = await Promise.all(warmup);
  for (const c of warm) c.release();

  log("info", "pool ready", {
    elapsed_ms: elapsedMs(t0),
    size: pool.totalCount,
    idle: pool.idleCount,
  });

  const db = drizzle(pool, { logger: true });

  try {
    await logServerInfo(db);
  } catch (e) {
    log("warn", "server info query failed", {
      error: e instanceof Error ? e.message : String(e),
    });
  }

  try {
    await setupHypertable(db, seedRows);
  } catch (e) {
    log("warn", "hypertable setup failed", {
      error: e instanceof Error ? e.message : String(e),
    });
  }

  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    log("info", "ctrl-c received, closing pool");
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);

  let round = 0;
  while (!stopping) {
    const tickStart = process.hrtime.bigint();
    round += 1;
    await runProbeRound(pool, round, probeConcurrency, queriesPerWorker);

    if (stopping) break;

    const elapsed = elapsedMs(tickStart);
    const remaining = probeInterval * 1000 - elapsed;
    if (remaining > 0) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, remaining);
        const onSignal = () => {
          clearTimeout(timer);
          resolve();
        };
        process.once("SIGINT", onSignal);
        process.once("SIGTERM", onSignal);
      });
    }
  }

  await pool.end();
}

main().catch((e) => {
  log("warn", "fatal", { error: e instanceof Error ? e.stack ?? e.message : String(e) });
  process.exit(1);
});
