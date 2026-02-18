import { Router, Request, Response } from "express";
import bcrypt from "bcryptjs";
import { db } from "../db";
import { users } from "../db/schema";
import { eq } from "drizzle-orm";
import logger from "../utils/logger";

const router = Router();

router.post("/register", async (req: Request, res: Response) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 8) {
    return res.status(400).json({ error: "Username and password (min 8 chars) required" });
  }

  const existing = await db.select().from(users).where(eq(users.username, username)).limit(1);
  if (existing.length > 0) return res.status(409).json({ error: "Username taken" });

  const passwordHash = await bcrypt.hash(password, 12);
  const [user] = await db.insert(users).values({ username, passwordHash }).returning({ id: users.id, username: users.username });

  req.session.userId = user.id;
  logger.info("User registered", { username });
  return res.json({ user: { id: user.id, username: user.username } });
});

router.post("/login", async (req: Request, res: Response) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Credentials required" });

  const [user] = await db.select().from(users).where(eq(users.username, username)).limit(1);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });

  req.session.userId = user.id;
  logger.info("User logged in", { username });
  return res.json({ user: { id: user.id, username: user.username, role: user.role } });
});

router.post("/logout", (req: Request, res: Response) => {
  req.session.destroy(() => res.json({ ok: true }));
});

router.get("/me", async (req: Request, res: Response) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not authenticated" });
  const [user] = await db.select({ id: users.id, username: users.username, role: users.role })
    .from(users).where(eq(users.id, req.session.userId)).limit(1);
  if (!user) return res.status(401).json({ error: "User not found" });
  return res.json({ user });
});

export default router;
