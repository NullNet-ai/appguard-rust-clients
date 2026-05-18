import { defineConfig } from "drizzle-kit";

const DEFAULT_DATABASE_URL =
  "postgresql://admin:admin@timescale.color.dnamicro.net:5432/forms";

export default defineConfig({
  dialect: "postgresql",
  schema: "./src/schema.ts",
  out: "./drizzle",
  dbCredentials: {
    url: process.env.DATABASE_URL ?? DEFAULT_DATABASE_URL,
  },
});
