import axios from "axios";
import logger from "../../utils/logger";

interface BizLogicVuln {
  endpoint: string;
  technique: "negative_quantity" | "zero_price" | "coupon_reuse" | "quantity_overflow" | "price_manipulation" | "free_item";
  payload: Record<string, unknown>;
  responseStatus: number;
  accepted: boolean;
  severity: "critical" | "high" | "medium";
  detail: string;
}

interface BizLogicResult {
  vulns: BizLogicVuln[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number }>;
}

const CART_PATHS = [
  "/cart",
  "/api/cart",
  "/api/v1/cart",
  "/shop/cart",
  "/checkout",
  "/api/checkout",
  "/order",
  "/api/order",
  "/api/orders",
  "/api/v1/order",
  "/coupon",
  "/api/coupon",
  "/api/apply-coupon",
  "/api/discount",
  "/api/purchase",
  "/api/buy",
  "/api/payment",
];

class BusinessLogicProber {
  async probe(targetUrl: string, authHeaders?: Record<string, string>): Promise<BizLogicResult> {
    const vulns: BizLogicVuln[] = [];
    const baseUrl = targetUrl.replace(/\/$/, "");
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(authHeaders ?? {}),
    };

    // Discover active endpoints
    const activeEndpoints: string[] = [];
    const discoveryTasks = CART_PATHS.map(async (path) => {
      const url = `${baseUrl}${path}`;
      try {
        const res = await axios.get(url, {
          timeout: 6000,
          validateStatus: () => true,
          headers: authHeaders ?? {},
        });
        if (res.status !== 404) {
          activeEndpoints.push(url);
        }
      } catch {
        // unreachable endpoint — skip
      }
    });

    await Promise.allSettled(discoveryTasks);
    logger.debug(`[business-logic-probe] discovered ${activeEndpoints.length} active endpoints`);

    // Helper: record a vuln if the response is accepted (2xx)
    const record = (
      endpoint: string,
      technique: BizLogicVuln["technique"],
      payload: Record<string, unknown>,
      status: number,
      severity: BizLogicVuln["severity"],
      detail: string,
    ) => {
      const accepted = status >= 200 && status < 300;
      vulns.push({ endpoint, technique, payload, responseStatus: status, accepted, severity, detail });
    };

    const attackTasks: Array<Promise<void>> = [];

    for (const endpoint of activeEndpoints) {
      // 1. Negative quantity
      attackTasks.push(
        (async () => {
          const payload = { quantity: -1, amount: -1, qty: -1 };
          try {
            const res = await axios.post(endpoint, payload, {
              timeout: 6000,
              validateStatus: () => true,
              headers,
            });
            if (res.status >= 200 && res.status < 300) {
              record(
                endpoint,
                "negative_quantity",
                payload,
                res.status,
                "critical",
                "Server accepted a negative quantity value which may result in a negative charge or credit to the attacker.",
              );
            }
          } catch {
            // swallow
          }
        })(),
      );

      // 2. Zero price
      attackTasks.push(
        (async () => {
          const payload = { price: 0, cost: 0, amount: 0, unit_price: 0 };
          try {
            const res = await axios.post(endpoint, payload, {
              timeout: 6000,
              validateStatus: () => true,
              headers,
            });
            if (res.status >= 200 && res.status < 300) {
              record(
                endpoint,
                "zero_price",
                payload,
                res.status,
                "critical",
                "Server accepted a zero-price payload; items may be obtainable for free.",
              );
            }
          } catch {
            // swallow
          }
        })(),
      );

      // 3. Quantity overflow
      attackTasks.push(
        (async () => {
          const payload = { quantity: 2147483647, qty: 9999999 };
          try {
            const res = await axios.post(endpoint, payload, {
              timeout: 6000,
              validateStatus: () => true,
              headers,
            });
            if (res.status >= 200 && res.status < 300) {
              record(
                endpoint,
                "quantity_overflow",
                payload,
                res.status,
                "high",
                "Server accepted an integer-overflow quantity value which may trigger wraparound pricing or stock depletion.",
              );
            }
          } catch {
            // swallow
          }
        })(),
      );

      // 4. Coupon reuse — always target /api/apply-coupon but also the discovered endpoint
      attackTasks.push(
        (async () => {
          const couponEndpoint = `${baseUrl}/api/apply-coupon`;
          const payload = { code: "TEST10", coupon: "TEST10" };
          try {
            const [res1, res2] = await Promise.all([
              axios.post(couponEndpoint, payload, {
                timeout: 6000,
                validateStatus: () => true,
                headers,
              }),
              axios.post(couponEndpoint, payload, {
                timeout: 6000,
                validateStatus: () => true,
                headers,
              }),
            ]);
            const bothAccepted = res1.status >= 200 && res1.status < 300 && res2.status >= 200 && res2.status < 300;
            if (bothAccepted) {
              record(
                couponEndpoint,
                "coupon_reuse",
                payload,
                res2.status,
                "high",
                "The same coupon code was accepted twice in rapid succession; coupon codes may be reusable.",
              );
            }
          } catch {
            // swallow
          }
        })(),
      );

      // 5. Price manipulation
      attackTasks.push(
        (async () => {
          const payload = { price: -100, total: -100 };
          try {
            const res = await axios.post(endpoint, payload, {
              timeout: 6000,
              validateStatus: () => true,
              headers,
            });
            if (res.status >= 200 && res.status < 300) {
              record(
                endpoint,
                "price_manipulation",
                payload,
                res.status,
                "critical",
                "Server accepted a negative price/total value; an attacker may be able to receive a refund or credit on purchase.",
              );
            }
          } catch {
            // swallow
          }
        })(),
      );

      // 6. Free item
      attackTasks.push(
        (async () => {
          const payload = { price: 0.0, discount: 100, coupon_discount: 100 };
          try {
            const res = await axios.post(endpoint, payload, {
              timeout: 6000,
              validateStatus: () => true,
              headers,
            });
            if (res.status >= 200 && res.status < 300) {
              record(
                endpoint,
                "free_item",
                payload,
                res.status,
                "critical",
                "Server accepted an add-to-cart request with a 100% discount and zero price; items may be obtainable for free.",
              );
            }
          } catch {
            // swallow
          }
        })(),
      );
    }

    await Promise.allSettled(attackTasks);

    // Build hypotheses from accepted vulns only
    const hypotheses = vulns
      .filter((v) => v.accepted)
      .map((v) => ({
        vulnClass: "business_logic",
        reasoning: `Endpoint ${v.endpoint} accepted a ${v.technique} payload (HTTP ${v.responseStatus}). ${v.detail}`,
        confidence: 0.7,
        priority: v.severity === "critical" ? 9 : 7,
      }));

    logger.info(`[business-logic-probe] found ${vulns.filter((v) => v.accepted).length} accepted business-logic vulnerabilities`);

    return { vulns, hypotheses };
  }
}

export const businessLogicProber = new BusinessLogicProber();
