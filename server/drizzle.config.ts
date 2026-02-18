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
} satisfies Config;
