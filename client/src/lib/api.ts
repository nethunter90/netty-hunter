import axios from "axios";

const api = axios.create({
  baseURL: "/api",
  withCredentials: true,
  timeout: 30000,
});

api.interceptors.response.use(
  (r) => r,
  (error) => {
    if (error.response?.status === 401) {
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
