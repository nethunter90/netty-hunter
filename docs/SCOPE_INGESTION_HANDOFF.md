# Scope Ingestion — Build-Ready Handoff

> **Status:** v1 fully scoped, build-ready. Wire-only job + one non-negotiable
> safety rule. All claims below verified against source. ~an afternoon, $0, no hunt.

---

## TL;DR
**Branch A task.** The hard consumer (`ScopeGuard`) is already built and is
governance-protected. The producer is mostly built too. v1 is a **wire-only**
job: add two textareas to an existing form and pass them through a route that
already accepts them. One safety landmine — path-level out-of-scope — is flagged
below as **NON-NEGOTIABLE**.

---

## ⛔ NON-NEGOTIABLE SAFETY RULE (read first)

**A path-level out-of-scope exclusion must NEVER be silently collapsed to a host
or stored verbatim.**

`ScopeGuard` matches on `new URL(url).hostname` only — it has no path
granularity. This creates an asymmetry:

- **In-scope at path level** (`example.com/api/*`) collapsing to host
  (`example.com`) → over-permissive but still on an authorized host.
  **Coverage gap, not a violation. Acceptable for v1** (warn, don't block).

- **Out-of-scope at path level** (`example.com/legacy/*`) → **DANGEROUS.**
  Verified against `matchesPattern`:
  ```ts
  const normalized = pattern.replace(/^\*\./, "");
  return hostname === normalized || hostname.endsWith(`.${normalized}`);
  ```
  A pattern of `example.com/legacy/*` can never equal or `.endsWith` a bare
  hostname → **a path-bearing out-of-scope entry stored verbatim is silently
  inert. The exclusion never fires and the host stays fully huntable = a real
  scope violation.** This is guaranteed by the matcher, not hypothetical.
  Stripping the path to host instead would nuke the host's in-scope parts too.

**Required behavior (fail-closed — the same principle `ScopeGuard` embodies):**
If an out-of-scope entry contains a path (a `/` after the host), the importer
must **reject** it with a clear message. It must NEVER silently strip the path
and keep the host in-scope, and must NEVER store the path-bearing string
verbatim (the matcher makes it inert either way).

**Enforcement lives server-side, in the route** (client validation can be
bypassed). The form may *also* show a friendly message, but the hard rejection
belongs at the route.

---

## 1. The consumer (`ScopeGuard`) — DONE, do not touch

`server/src/middleware/scopeGuard.ts` (governance-protected):
- `matchesPattern` handles `"*"`, `"*.example.com"`, and exact hosts — exactly
  what real scope needs.
- CNAME-chain follow + per-hop out-of-scope sweep + shared-infra classification
  (block SaaS / warn CDN) + private-IP A-record check (DNS-rebinding defense).
- Fail-closed: errors → `allowed: false`.
- Reads `programs.scope` / `programs.outOfScope` (string[]), cached 30s by
  `programId`.

**Contract:** two string arrays of host patterns. Does NOT need to change.

---

## 2. The producer UI — EXISTS, but has the hole

`client/src/components/bounty/ScopeManager.tsx` ("Program Manager"): Import form,
active-programs list that *displays* in/out scope, Target Validator (live
`isInScope`), ScopeGuard stats/audit dashboard.

**The hole:** the Import form (`handleImport`) collects only
`handle, platform, stealthProfile, noveltyFloor, maxScanRate` — no scope:
```ts
body: JSON.stringify({ handle, platform, stealthProfile, noveltyFloor, maxScanRate })
// no `scope`, no `outOfScope`
```
→ UI-imported program lands with `scope: []` → ScopeGuard's in-scope loop never
matches → **fail-closed blocks everything → program unhuntable.** Latent because
the failure is the safe direction (blocks rather than over-permits).

---

## 3. Where scope writes to the DB today
- `POST /api/bounty/programs` (raw API) — takes `scope: string[]` verbatim.
- `POST /api/bounty/programs/import` — accepts scope but UI sends none → `[]`.
- `PATCH /api/bounty/programs/:id/scope` / `POST /api/bounty/programs/:id/update`
  — accept arrays; UI doesn't send scope through them.
- Local-lab auto-create (`programId === -1`) → `scope: ["*"]`.

## 4. Rich producer — EXISTS but unwired (v2)
`server/src/lib/bounty-intelligence/program-fetcher.ts` pulls real structured
scope (`ScopeAsset[]`) from HackerOne/Bugcrowd/Intigriti/Synack/YesWeHack, but
writes **only to flat files**, never to `programs.scope`. "Import by handle" does
NOT call it. This is the **v2 auto-ingest** story — correctly deferred.

```ts
interface ScopeAsset {
  type: 'url'|'domain'|'wildcard'|'ios'|'android'|'api'|'hardware'|'other';
  identifier: string;     // e.g. "https://api.example.com/v2" or "*.example.com"
  maxSeverity?: string; eligible?: boolean; instruction?: string;
}
```

---

## 5. v1 TASK — build-ready

### Step 1 — Add two textareas to the Import form
In-scope / out-of-scope, one pattern per line. Send the **raw textarea string**
under the keys `scope` / `outOfScope` and let the route split. Do NOT double-handle.

### Step 2 — Verify the body shape (the no-op trap)
The route's `toList` (verified at `bounty.ts:1256`):
```ts
const toList = (v: any): string[] => {
  if (Array.isArray(v)) return v.map(String).map(s => s.trim()).filter(Boolean);
  if (typeof v === "string") return v.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
  return [];                       // ← non-string/array silently yields []
};
```
The third branch returns `[]` for `null`/`undefined`/misspelled keys —
**reproducing the exact `scope: []` bug being fixed.** Confirm the POST body
carries `scope`/`outOfScope` as top-level strings under those exact names.

### Step 3 — Enforce the safety rule SERVER-SIDE
In `POST /api/bounty/programs/import`, right after `toList` is defined
(`bounty.ts:1260`) and before the insert (`bounty.ts:1262`):
```ts
const outList = toList(outOfScope);
const pathBearing = outList.filter(s => s.replace(/^https?:\/\//i, "").includes("/"));
if (pathBearing.length) {
  return res.status(400).json({
    error: "Path-level out-of-scope not supported yet — exclude the whole host or wait for v2 path-scoping.",
    offending: pathBearing,
  });
}
// then use `outList` for the insert's `outOfScope`
```
In-scope path entries are merely *inert/dead* (safe) — warn, don't block.

### Step 4 — Test via the on-page Target Validator ($0, no hunt)
```
Setup: import program — in-scope: example.com, *.example.com
                        out-of-scope: staging.example.com
[ ] https://example.com/anything          → ALLOWED
[ ] https://app.example.com/x             → ALLOWED  (wildcard depth)
[ ] https://staging.example.com/anything  → BLOCKED  (out-of-scope host)
[ ] https://unrelated.com                 → BLOCKED  (not in any in-scope)
SAFETY CASE (proves the rule fires):
[ ] import program with out-of-scope: example.com/legacy/*
                                          → REJECTED 400 with the clear message
                                          → NOT silently stored as example.com
```
The last case is the proof: a rejected path-bearing out-of-scope import means the
landmine is defused **and verified**.

---

## 6. v2 — explicitly deferred
- Wire `program-fetcher.ts` → `programs.scope` for multi-platform auto-ingest,
  using a translator (host-level extraction, sketch below).
- Add a path-level matcher to `ScopeGuard` so path-scoped programs are
  expressible (removes the Step 3 rejection).

```ts
function toScopeGuardStrings(assets: ScopeAsset[]): string[] {
  return assets.flatMap(a => {
    if (a.type === 'wildcard' || a.type === 'domain') return [a.identifier];
    if (a.type === 'url' || a.type === 'api') {
      try { return [new URL(a.identifier).hostname]; } catch { return []; }
    }
    return []; // ios/android/hardware — not web host patterns
  });
  // NOTE: out-of-scope assets must obey the NON-NEGOTIABLE rule — never collapse
  // a path-bearing identifier to host silently; flag for the v2 path-matcher.
}
```

---

## Decisions resolved
1. **Program entry** — form exists; add in/out scope fields + pass through. Route
   already handles them. Done.
2. **Path scoping** — host-granularity v1 for in-scope (warn); out-of-scope path
   entries rejected server-side, NEVER silently collapsed or stored. (See the
   NON-NEGOTIABLE rule.)

## Files referenced
| File | Role |
|---|---|
| `server/src/middleware/scopeGuard.ts` | Consumer (protected — do not touch) |
| `server/src/routes/bounty.ts` | Program CRUD + import/validate routes (`toList` at 1256, import insert at 1262) |
| `server/src/routes/hunt.ts` | Hunt start; local-lab `["*"]` path |
| `server/src/lib/bounty-intelligence/program-fetcher.ts` | Rich fetcher — flat-file only (v2) |
| `client/src/components/bounty/ScopeManager.tsx` | Program Manager UI — missing scope fields |
| `server/src/db/schema.ts` | `programs.scope` / `programs.outOfScope` jsonb → string[] |

## Effort
- Two textareas + pass-through — the easy 80%.
- Server-side path-level rejection — the safety 15%.
- Target Validator confirmation — the 5% that proves it works.

This is the **first of three v1 pieces** (scope ingestion). Novelty checking and
report format remain.
