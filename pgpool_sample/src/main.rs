use std::env;
use std::time::{Duration, Instant};

use sqlx::postgres::{PgPool, PgPoolOptions};
use tokio::signal;
use tokio::task::JoinSet;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const DEFAULT_DATABASE_URL: &str =
    "postgresql://admin:admin@timescale.color.dnamicro.net:5432/forms";

const METRICS_TABLE: &str = "pgpool_sample_metrics";

const PROBE_QUERY: &str = "
SELECT
    time_bucket('1 minute', time) AS bucket,
    device_id,
    avg(value) AS avg_value,
    count(*) AS cnt
FROM pgpool_sample_metrics
WHERE time >= now() - interval '1 hour'
GROUP BY bucket, device_id
ORDER BY bucket DESC, device_id
";

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let database_url =
        env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_string());

    let min_connections: u32 = env_parse("PG_MIN_CONNECTIONS", 2);
    let max_connections: u32 = env_parse("PG_MAX_CONNECTIONS", 8);
    let acquire_timeout: u64 = env_parse("PG_ACQUIRE_TIMEOUT_SECS", 10);
    let idle_timeout: u64 = env_parse("PG_IDLE_TIMEOUT_SECS", 60);
    let max_lifetime: u64 = env_parse("PG_MAX_LIFETIME_SECS", 600);
    let probe_interval: u64 = env_parse("PROBE_INTERVAL_SECS", 5);
    let probe_concurrency: u32 = env_parse("PROBE_CONCURRENCY", 4);
    let queries_per_worker: u32 = env_parse("QUERIES_PER_WORKER", 1);
    let seed_rows: i64 = env_parse("SEED_ROWS", 10_000);

    info!(url = %redact_url(&database_url), "connecting pool");
    info!(
        min = min_connections,
        max = max_connections,
        acquire_timeout_secs = acquire_timeout,
        idle_timeout_secs = idle_timeout,
        max_lifetime_secs = max_lifetime,
        "pool config"
    );
    info!(
        interval_secs = probe_interval,
        concurrency = probe_concurrency,
        queries_per_worker,
        seed_rows,
        "probe schedule"
    );

    let t0 = Instant::now();
    let pool = PgPoolOptions::new()
        .min_connections(min_connections)
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(acquire_timeout))
        .idle_timeout(Duration::from_secs(idle_timeout))
        .max_lifetime(Duration::from_secs(max_lifetime))
        .connect(&database_url)
        .await?;
    info!(
        elapsed = ?t0.elapsed(),
        size = pool.size(),
        idle = pool.num_idle(),
        "pool ready"
    );

    if let Err(e) = log_server_info(&pool).await {
        warn!(error = %e, "server info query failed");
    }

    if let Err(e) = setup_hypertable(&pool, seed_rows).await {
        warn!(error = %e, "hypertable setup failed");
    }

    let mut ticker = tokio::time::interval(Duration::from_secs(probe_interval));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut round: u64 = 0;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                round += 1;
                run_probe_round(&pool, round, probe_concurrency, queries_per_worker).await;
            }
            _ = signal::ctrl_c() => {
                info!("ctrl-c received, closing pool");
                pool.close().await;
                return Ok(());
            }
        }
    }
}

async fn log_server_info(pool: &PgPool) -> Result<(), sqlx::Error> {
    let version: String = sqlx::query_scalar("SELECT version()")
        .fetch_one(pool)
        .await?;
    info!(%version, "server version");

    let ts: Option<String> =
        sqlx::query_scalar("SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'")
            .fetch_optional(pool)
            .await?;
    match ts {
        Some(v) => info!(version = %v, "timescaledb extension"),
        None => info!("timescaledb extension not installed"),
    }
    Ok(())
}

async fn setup_hypertable(pool: &PgPool, seed_rows: i64) -> Result<(), sqlx::Error> {
    let t0 = Instant::now();
    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS {METRICS_TABLE} (
            time TIMESTAMPTZ NOT NULL,
            device_id INT NOT NULL,
            value DOUBLE PRECISION NOT NULL
        )"
    ))
    .execute(pool)
    .await?;

    sqlx::query(&format!(
        "SELECT create_hypertable('{METRICS_TABLE}', 'time', if_not_exists => TRUE)"
    ))
    .execute(pool)
    .await?;
    info!(elapsed = ?t0.elapsed(), table = METRICS_TABLE, "hypertable ready");

    if seed_rows <= 0 {
        info!("SEED_ROWS<=0, skipping seed");
        return Ok(());
    }

    let trunc_started = Instant::now();
    sqlx::query(&format!("TRUNCATE {METRICS_TABLE}"))
        .execute(pool)
        .await?;
    info!(elapsed = ?trunc_started.elapsed(), "truncated metrics");

    let seed_started = Instant::now();
    let inserted = sqlx::query(&format!(
        "INSERT INTO {METRICS_TABLE} (time, device_id, value)
         SELECT
             now() - (interval '1 hour' * (i::float8 / $1::float8)),
             (i % 10)::int,
             random() * 100
         FROM generate_series(0, $1 - 1) AS i"
    ))
    .bind(seed_rows)
    .execute(pool)
    .await?
    .rows_affected();
    info!(
        rows = inserted,
        elapsed = ?seed_started.elapsed(),
        "seeded metrics"
    );

    Ok(())
}

async fn run_probe_round(pool: &PgPool, round: u64, concurrency: u32, queries_per_worker: u32) {
    info!(
        round,
        size = pool.size(),
        idle = pool.num_idle(),
        "round start"
    );
    let started = Instant::now();

    let mut tasks: JoinSet<(u32, Result<(Duration, Duration, u64), sqlx::Error>)> = JoinSet::new();
    for i in 0..concurrency {
        let pool = pool.clone();
        tasks.spawn(async move {
            let acq_start = Instant::now();
            let conn = pool.acquire().await;
            let acquire_took = acq_start.elapsed();
            let mut conn = match conn {
                Ok(c) => c,
                Err(e) => return (i, Err(e)),
            };

            let q_start = Instant::now();
            let mut total_rows: u64 = 0;
            for _ in 0..queries_per_worker {
                match sqlx::query(PROBE_QUERY).fetch_all(&mut *conn).await {
                    Ok(rows) => total_rows += rows.len() as u64,
                    Err(e) => return (i, Err(e)),
                }
            }
            let query_took = q_start.elapsed();
            (i, Ok((acquire_took, query_took, total_rows)))
        });
    }

    let mut ok = 0u32;
    let mut err = 0u32;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((i, Ok((acquire, query, rows)))) => {
                ok += 1;
                info!(
                    round,
                    worker = i,
                    acquire = ?acquire,
                    total_query = ?query,
                    queries = queries_per_worker,
                    rows,
                    "worker ok"
                );
            }
            Ok((i, Err(e))) => {
                err += 1;
                warn!(round, worker = i, error = %e, "worker error");
            }
            Err(e) => {
                err += 1;
                warn!(round, error = %e, "worker join error");
            }
        }
    }

    info!(
        round,
        elapsed = ?started.elapsed(),
        ok,
        err,
        size = pool.size(),
        idle = pool.num_idle(),
        "round done"
    );
}

/// Mask the password portion of a postgres URL so it doesn't leak into logs.
fn redact_url(url: &str) -> String {
    let scheme_end = match url.find("://") {
        Some(i) => i + 3,
        None => return url.to_string(),
    };
    let Some(at_rel) = url[scheme_end..].find('@') else {
        return url.to_string();
    };
    let at = scheme_end + at_rel;
    let authority = &url[scheme_end..at];
    let rest = &url[at..];
    let prefix = &url[..scheme_end];
    if let Some(colon) = authority.find(':') {
        format!("{prefix}{}:***{rest}", &authority[..colon])
    } else {
        url.to_string()
    }
}
