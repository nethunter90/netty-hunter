import axios from "axios";
import logger from "../../utils/logger";

interface BucketResult {
  bucketUrl: string;
  provider: "aws_s3" | "gcp_gcs" | "azure_blob";
  bucketName: string;
  readable: boolean;
  listable: boolean;
  writable: boolean;
  severity: "critical" | "high" | "medium";
  detail: string;
}

interface BucketProbeResult {
  buckets: BucketResult[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string }>;
}

class CloudBucketProber {
  private extractCandidates(targetUrl: string): string[] {
    let hostname: string;
    try {
      hostname = new URL(targetUrl).hostname;
    } catch {
      hostname = targetUrl.split("/")[0];
    }

    const parts = hostname.split(".");
    // Remove TLD (last part) and second-level domain becomes the "name"
    const partsMinusTld = parts.length > 1 ? parts.slice(0, -1) : parts;
    const domainName = partsMinusTld[partsMinusTld.length - 1] || partsMinusTld[0];
    const subdomainParts = partsMinusTld.slice(0, -1);

    const candidates: string[] = [];

    // hostname with dots replaced by dashes (minus TLD)
    const hostnameCandidate = partsMinusTld.join("-");
    if (hostnameCandidate) candidates.push(hostnameCandidate);

    // each subdomain part
    for (const part of subdomainParts) {
      if (part && !candidates.includes(part)) {
        candidates.push(part);
      }
    }

    // domain name itself
    if (domainName && !candidates.includes(domainName)) {
      candidates.push(domainName);
    }

    // prefixed combinations using the domain name
    const prefixes = ["assets", "static", "uploads", "files", "media", "backup", "data", "cdn"];
    for (const prefix of prefixes) {
      const combo = `${prefix}-${domainName}`;
      if (!candidates.includes(combo)) {
        candidates.push(combo);
      }
    }

    return candidates.slice(0, 12);
  }

  async probe(targetUrl: string): Promise<BucketProbeResult> {
    const candidates = this.extractCandidates(targetUrl);
    const buckets: BucketResult[] = [];

    const checks: Array<() => Promise<BucketResult | null>> = [];

    for (const name of candidates) {
      // AWS S3 - virtual-hosted style
      checks.push(async () => {
        const url = `https://${name}.s3.amazonaws.com/?list-type=2&max-keys=5`;
        try {
          const resp = await axios.get(url, { timeout: 6000, validateStatus: () => true });
          if (resp.status === 200) {
            const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
            const listable = body.includes("<Contents>");
            const readable = true;
            const severity: "critical" | "high" | "medium" = listable ? "critical" : "high";
            const detail = listable
              ? `S3 bucket '${name}' is publicly listable (virtual-hosted)`
              : `S3 bucket '${name}' is publicly readable (virtual-hosted)`;
            logger.debug(`[cloud-bucket-probe] Found S3 bucket (virtual): ${name}`);
            return {
              bucketUrl: `https://${name}.s3.amazonaws.com/`,
              provider: "aws_s3",
              bucketName: name,
              readable,
              listable,
              writable: false,
              severity,
              detail,
            };
          }
        } catch (err) {
          logger.debug(`[cloud-bucket-probe] S3 virtual check error for ${name}: ${err}`);
        }
        return null;
      });

      // AWS S3 - path style
      checks.push(async () => {
        const url = `https://s3.amazonaws.com/${name}/?list-type=2&max-keys=5`;
        try {
          const resp = await axios.get(url, { timeout: 6000, validateStatus: () => true });
          if (resp.status === 200) {
            const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
            const listable = body.includes("<Contents>");
            const readable = true;
            const severity: "critical" | "high" | "medium" = listable ? "critical" : "high";
            const detail = listable
              ? `S3 bucket '${name}' is publicly listable (path-style)`
              : `S3 bucket '${name}' is publicly readable (path-style)`;
            logger.debug(`[cloud-bucket-probe] Found S3 bucket (path): ${name}`);
            return {
              bucketUrl: `https://s3.amazonaws.com/${name}/`,
              provider: "aws_s3",
              bucketName: name,
              readable,
              listable,
              writable: false,
              severity,
              detail,
            };
          }
        } catch (err) {
          logger.debug(`[cloud-bucket-probe] S3 path check error for ${name}: ${err}`);
        }
        return null;
      });

      // GCP GCS
      checks.push(async () => {
        const url = `https://storage.googleapis.com/${name}/`;
        try {
          const resp = await axios.get(url, { timeout: 6000, validateStatus: () => true });
          if (resp.status === 200) {
            const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
            const isListing = body.includes("<ListBucketResult");
            const listable = isListing && body.includes("<Contents>");
            const readable = true;
            const severity: "critical" | "high" | "medium" = listable ? "critical" : "high";
            const detail = listable
              ? `GCS bucket '${name}' is publicly listable`
              : `GCS bucket '${name}' is publicly readable`;
            logger.debug(`[cloud-bucket-probe] Found GCS bucket: ${name}`);
            return {
              bucketUrl: url,
              provider: "gcp_gcs",
              bucketName: name,
              readable,
              listable,
              writable: false,
              severity,
              detail,
            };
          }
        } catch (err) {
          logger.debug(`[cloud-bucket-probe] GCS check error for ${name}: ${err}`);
        }
        return null;
      });

      // Azure Blob Storage
      checks.push(async () => {
        const url = `https://${name}.blob.core.windows.net/${name}?restype=container&comp=list`;
        try {
          const resp = await axios.get(url, { timeout: 6000, validateStatus: () => true });
          if (resp.status === 200) {
            const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
            const listable = body.includes("<Blob>");
            const readable = true;
            const severity: "critical" | "high" | "medium" = listable ? "critical" : "high";
            const detail = listable
              ? `Azure Blob container '${name}' is publicly listable`
              : `Azure Blob container '${name}' is publicly readable`;
            logger.debug(`[cloud-bucket-probe] Found Azure Blob container: ${name}`);
            return {
              bucketUrl: `https://${name}.blob.core.windows.net/${name}`,
              provider: "azure_blob",
              bucketName: name,
              readable,
              listable,
              writable: false,
              severity,
              detail,
            };
          }
        } catch (err) {
          logger.debug(`[cloud-bucket-probe] Azure check error for ${name}: ${err}`);
        }
        return null;
      });
    }

    const results = await Promise.allSettled(checks.map((fn) => fn()));

    for (const result of results) {
      if (result.status === "fulfilled" && result.value !== null) {
        buckets.push(result.value);
      }
    }

    const hypotheses = buckets.map((bucket) => ({
      vulnClass: "cloud_storage_exposure",
      reasoning: bucket.detail,
      confidence: 0.9,
      priority: 10,
      endpoint: bucket.bucketUrl,
    }));

    return { buckets, hypotheses };
  }
}

export const cloudBucketProber = new CloudBucketProber();
