import type { Config } from "drizzle-kit";
import "dotenv/config";

export default {
  schema: "./src/db/schema.ts",
  out: "./drizzle",
  driver: "pg",
  dbCredentials: {
    connectionString: process.env.DATABASE_URL || "postgresql://postgres:password@localhost:5432/netty_hunter",
  },
  verbose: true,
  strict: true,
  // "sessions" is connect-pg-simple's own login-session store table
  // (index.ts, createTableIfMissing: true) -- it's owned by that middleware,
  // not this app's data model, and must never be declared here or diffed by
  // push. Excluding it (rather than declaring it as an app table) keeps
  // Drizzle from fighting connect-pg-simple over who owns its schema.
  tablesFilter: ["!sessions"],
} satisfies Config;
