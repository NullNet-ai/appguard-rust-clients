import {
  doublePrecision,
  integer,
  pgTable,
  timestamp,
} from "drizzle-orm/pg-core";

export const METRICS_TABLE = "pgpool_sample_metrics";

export const metrics = pgTable(METRICS_TABLE, {
  time: timestamp("time", { withTimezone: true }).notNull(),
  deviceId: integer("device_id").notNull(),
  value: doublePrecision("value").notNull(),
});
