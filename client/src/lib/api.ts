import axios from "axios";

const api = axios.create({
  baseURL: "/api",
  withCredentials: true,
  timeout: 30000,
});

api.interceptors.response.use(
  (r) => r,
  (error) => {
    if (error.response?.status === 401 && !window.location.pathname.includes("/login")) {
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

export default api;

// Typed API helpers
export const hunterAPI = {
  startHunt: (data: Record<string, unknown>) => api.post("/hunt/start", data),
  stopHunt: (uuid: string) => api.post(`/hunt/stop/${uuid}`),
  getSession: (uuid: string) => api.get(`/hunt/session/${uuid}`),
  getCampaigns: (programId?: number) => api.get("/hunt/campaigns", { params: programId ? { programId } : undefined }),
  getCampaign: (id: number) => api.get(`/hunt/campaigns/${id}`),
  getFindings: (filters?: Record<string, string>) => api.get("/hunt/findings", { params: filters }),
  getFinding: (id: number) => api.get(`/hunt/findings/${id}`),
  verifyFinding: (id: number) => api.post(`/hunt/findings/${id}/verify`),
  updateFinding: (id: number, data: Record<string, unknown>) => api.patch(`/hunt/findings/${id}`, data),
  exportFindings: (format: "csv" | "json") => api.get(`/hunt/findings/export?format=${format}`, { responseType: "blob" }),
  getNucleiTemplate: (id: number) => api.post(`/hunt/findings/${id}/nuclei-template`),
  generateReport: (id: number, body?: Record<string, unknown>) => api.post(`/hunt/findings/${id}/report`, body || {}),
  spawnSolvers: (data: Record<string, unknown>) => api.post("/hunt/solve", data),
  buildStrategy: (data: Record<string, unknown>) => api.post("/hunt/strategy", data),
};

export const bountyAPI = {
  getPrograms: () => api.get("/bounty/programs"),
  createProgram: (data: Record<string, unknown>) => api.post("/bounty/programs", data),
  getProgram: (id: number) => api.get(`/bounty/programs/${id}`),
  updateProgram: (id: number, data: Record<string, unknown>) => api.patch(`/bounty/programs/${id}`, data),
  deleteProgram: (id: number) => api.delete(`/bounty/programs/${id}`),
  rankPrograms: () => api.get("/bounty/rank-programs"),
  recommendTarget: (exclude?: number[]) => api.get("/bounty/recommend-target", { params: exclude ? { exclude: exclude.join(",") } : undefined }),
  getRoiRanking: (maxPayout?: number) => api.get("/bounty/roi-ranking", { params: maxPayout ? { maxPayout } : undefined }),
  getRlStats: () => api.get("/bounty/rl-stats"),
  getAutonomy: () => api.get("/bounty/autonomy"),
  getAutonomyHistory: () => api.get("/bounty/autonomy/history"),
  getExploitChains: () => api.get("/bounty/exploit-chains"),
  getPrebuiltChains: () => api.get("/bounty/exploit-chains/prebuilt"),
  getWafProfiles: () => api.get("/bounty/waf-profiles"),
  getHuntTemplates: () => api.get("/bounty/hunt-templates"),
  aiChat: (message: string, context?: Record<string, unknown>) => api.post("/bounty/ai/chat", { message, context }),
  getModels: () => api.get("/bounty/models"),
};

export const authAPI = {
  login: (username: string, password: string) => api.post("/auth/login", { username, password }),
  register: (username: string, password: string) => api.post("/auth/register", { username, password }),
  logout: () => api.post("/auth/logout"),
  me: () => api.get("/auth/me"),
};

export const orchestrationAPI = {
  /** Describe all 6 layers */
  getLayers: () => api.get("/orchestration/layers"),
  /** Start a full orchestrated hunt (REST – fires async, use Socket.IO for real-time) */
  run: (data: Record<string, unknown>) => api.post("/orchestration/run", data),
  /** Abort an active orchestration */
  stop: (id: string) => api.post(`/orchestration/stop/${id}`),
  /** Get orchestration state by ID */
  getState: (id: string) => api.get(`/orchestration/${id}`),
  /** List recent orchestrations */
  list: () => api.get("/orchestration"),
  /** Summary stats */
  stats: () => api.get("/orchestration/stats/summary"),
};

// ── Hunter Subsystem API (/api/hunter) ──────────────────────────────────────

const H = "/hunter";

export const sessionAPI = {
  // Session lifecycle
  create:          (data: Record<string, unknown>) => api.post(`${H}/sessions`, data),
  list:            ()                               => api.get(`${H}/sessions`),
  get:             (id: string)                     => api.get(`${H}/sessions/${id}`),
  stop:            (id: string)                     => api.post(`${H}/sessions/${id}/stop`),
  pause:           (id: string)                     => api.post(`${H}/sessions/${id}/pause`),
  resume:          (id: string)                     => api.post(`${H}/sessions/${id}/resume`),

  // Session intel
  getFindings:     (id: string) => api.get(`${H}/sessions/${id}/findings`),
  getHypotheses:   (id: string) => api.get(`${H}/sessions/${id}/hypotheses`),
  getTargetModel:  (id: string) => api.get(`${H}/sessions/${id}/target-model`),
  getObservability:(id: string) => api.get(`${H}/sessions/${id}/observability`),
  getReasoning:    (id: string) => api.get(`${H}/sessions/${id}/reasoning`),
  getReasoningFindings: (id: string) => api.get(`${H}/sessions/${id}/reasoning/findings`),

  // Intelligence synthesis
  getIntelligence: (id: string) => api.get(`${H}/sessions/${id}/intelligence`),

  // Strategy & plan
  getStrategy:       (id: string) => api.get(`${H}/sessions/${id}/strategy`),
  adaptStrategy:     (id: string, data: Record<string, unknown>) => api.post(`${H}/sessions/${id}/strategy/adapt`, data),
  addStrategyStep:   (id: string, data: Record<string, unknown>) => api.post(`${H}/sessions/${id}/strategy/add-step`, data),
  getPlan:           (id: string) => api.get(`${H}/sessions/${id}/plan`),
  advancePlan:       (id: string) => api.post(`${H}/sessions/${id}/plan/advance`),

  // Coordination
  getCoordination:  (id: string) => api.get(`${H}/sessions/${id}/coordination`),
  getDecisionLog:   (id: string) => api.get(`${H}/sessions/${id}/coordination/decisions`),
  simulateEvent:    (id: string, data: Record<string, unknown>) => api.post(`${H}/sessions/${id}/coordination/simulate`, data),

  // Validation
  getValidationStats: (id: string) => api.get(`${H}/sessions/${id}/validation-stats`),

  // Nuclei templates
  getNucleiTemplates:  (id: string) => api.get(`${H}/sessions/${id}/nuclei-templates`),
  getNucleiTemplate:   (id: string, tId: string) => api.get(`${H}/sessions/${id}/nuclei-templates/${tId}`),
  downloadAllTemplates:(id: string) => api.get(`${H}/sessions/${id}/nuclei-templates/download/all`),

  // Reports
  getReports:        (id: string) => api.get(`${H}/sessions/${id}/reports`),
  getReport:         (id: string, rId: string) => api.get(`${H}/sessions/${id}/reports/${rId}`),
  generateReport:    (id: string, data?: Record<string, unknown>) => api.post(`${H}/sessions/${id}/reports/generate`, data || {}),
  downloadReport:    (id: string, rId: string) => api.get(`${H}/sessions/${id}/reports/${rId}/download`),

  // WAF
  getWaf:            (id: string) => api.get(`${H}/sessions/${id}/waf`),
  escalateWaf:       (id: string, data: Record<string, unknown>) => api.post(`${H}/sessions/${id}/waf/escalate`, data),
  getWafRules:       (id: string) => api.get(`${H}/sessions/${id}/waf/rules`),
  getWafBehavior:    (id: string) => api.get(`${H}/sessions/${id}/waf/behavior`),
  getEvasionRanking: (id: string) => api.get(`${H}/sessions/${id}/waf/evasion-ranking`),
  getTemporalAnalysis:(id: string) => api.get(`${H}/sessions/${id}/waf/temporal`),
  getWafClusters:    (id: string) => api.get(`${H}/sessions/${id}/waf/clusters`),
  getWafAnomalies:   (id: string) => api.get(`${H}/sessions/${id}/waf/anomalies`),
  getWafCorrelations:(id: string) => api.get(`${H}/sessions/${id}/waf/correlations`),

  // Exploit chains
  startChain:   (id: string, data: Record<string, unknown>) => api.post(`${H}/sessions/${id}/chains/start`, data),
  addChainStep: (id: string, chainId: string, data: Record<string, unknown>) => api.post(`${H}/sessions/${id}/chains/${chainId}/step`, data),
  completeChain:(id: string, chainId: string, data: Record<string, unknown>) => api.post(`${H}/sessions/${id}/chains/${chainId}/complete`, data),

  // Backward hunt
  createBackwardHunt:    (id: string, data: Record<string, unknown>) => api.post(`${H}/sessions/${id}/backward-hunt`, data),
  getBackwardHunt:       (id: string) => api.get(`${H}/sessions/${id}/backward-hunt`),
  generateBHypotheses:   (id: string) => api.post(`${H}/sessions/${id}/backward-hunt/hypotheses`),
  recordBStepResult:     (id: string, data: Record<string, unknown>) => api.post(`${H}/sessions/${id}/backward-hunt/step-result`, data),
};

export const hunterROI = {
  getGlobal:         ()                        => api.get(`${H}/roi/global`),
  getForProgram:     (programId: number)       => api.get(`${H}/roi/program/${programId}`),
  getThresholds:     ()                        => api.get(`${H}/roi/thresholds`),
  setOverride:       (data: Record<string, unknown>) => api.post(`${H}/roi/override`, data),
  clearOverride:     (programId: number)       => api.delete(`${H}/roi/override`, { data: { programId } }),
  getMultiplier:     (vulnType: string)        => api.get(`${H}/roi/multiplier/${vulnType}`),
};

export const hunterTargets = {
  addProgram:    (data: Record<string, unknown>) => api.post(`${H}/targets/program`, data),
  getProgram:    (programId: number)             => api.get(`${H}/targets/program/${programId}`),
  rankAll:       ()                              => api.get(`${H}/targets/rank`),
  getQueue:      ()                              => api.get(`${H}/targets/queue`),
  updateOutcome: (programId: number, data: Record<string, unknown>) => api.post(`${H}/targets/program/${programId}/outcome`, data),
};

export const hunterChains = {
  record:        (data: Record<string, unknown>) => api.post(`${H}/chains/record`, data),
  recordOutcome: (chainId: string, data: Record<string, unknown>) => api.post(`${H}/chains/${chainId}/outcome`, data),
  getPatterns:   ()                              => api.get(`${H}/chains/patterns`),
  recommend:     (data: Record<string, unknown>) => api.post(`${H}/chains/recommend`, data),
  getAvoid:      ()                              => api.get(`${H}/chains/avoid`),
  getROI:        ()                              => api.get(`${H}/chains/roi`),
};

export const hunterStatic = {
  analyze: (data: Record<string, unknown>) => api.post(`${H}/static-analysis/analyze`, data),
  routes:  (data: Record<string, unknown>) => api.post(`${H}/static-analysis/routes`, data),
  hypotheses: (data: Record<string, unknown>) => api.post(`${H}/static-analysis/hypotheses`, data),
};

export const hunterVendor = {
  getProfile:      (vendor: string) => api.get(`${H}/vendor-profile/${vendor}`),
  getChains:       (vendor: string) => api.get(`${H}/vendor-profile/${vendor}/chains`),
  getIntelligence: (vendor: string) => api.get(`${H}/intelligence/${vendor}`),
};

export const hunterCalibration = {
  getMetrics: () => api.get(`${H}/calibration/metrics`),
  autoTune:   () => api.post(`${H}/calibration/auto-tune`),
};

export const toolsAPI = {
  list: () => api.get("/tools"),
  create: (data: Record<string, unknown>) => api.post("/tools", data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/tools/${id}`, data),
  remove: (id: number) => api.delete(`/tools/${id}`),
  test: (id: number, url: string) => api.post(`/tools/${id}/test`, { url }),
};
