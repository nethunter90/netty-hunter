import { MissionMemory, Endpoint, Technology, Vulnerability, Credential } from './types';

const MAX_ENDPOINTS = 2000;
const MAX_TECHNOLOGIES = 500;
const MAX_VULNERABILITIES = 500;
const MAX_SUBDOMAINS = 1000;
const MAX_NOTES = 200;

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export class MissionMemoryStore {
  private memories: Map<string, MissionMemory> = new Map();

  initialize(huntId: string, initialDomains: string[]): MissionMemory {
    const seedEndpoints: Endpoint[] = initialDomains
      .filter(d => d.startsWith('http'))
      .map(d => ({
        url: d.replace(/\/$/, ''),
        method: 'GET',
        statusCode: 0,
        title: 'Target (seed)',
        discoveredBy: 'orchestrator',
        discoveredAt: new Date()
      }));

    const memory: MissionMemory = {
      huntId,
      domains: initialDomains,
      subdomains: [],
      endpoints: seedEndpoints,
      technologies: [],
      vulnerabilities: [],
      credentials: [],
      notes: [],
      lastUpdated: new Date()
    };

    if (seedEndpoints.length > 0) {
      console.log(`[MissionMemory] Seeded ${seedEndpoints.length} baseline endpoint(s) for hunt ${huntId}`);
    }

    this.memories.set(huntId, memory);
    return memory;
  }

  get(huntId: string): MissionMemory | null {
    return this.memories.get(huntId) || null;
  }

  addSubdomains(huntId: string, subdomains: string[]): void {
    const memory = this.memories.get(huntId);
    if (!memory) return;

    const newSubdomains = subdomains.filter(s => !memory.subdomains.includes(s));
    memory.subdomains.push(...newSubdomains);
    while (memory.subdomains.length > MAX_SUBDOMAINS) memory.subdomains.shift();
    memory.lastUpdated = new Date();
  }

  addEndpoints(huntId: string, endpoints: Endpoint[]): void {
    const memory = this.memories.get(huntId);
    if (!memory) return;

    const existingUrls = new Set(memory.endpoints.map(e => e.url));
    const newEndpoints = endpoints.filter(e => !existingUrls.has(e.url));

    memory.endpoints.push(...newEndpoints);
    while (memory.endpoints.length > MAX_ENDPOINTS) memory.endpoints.shift();
    memory.lastUpdated = new Date();
  }

  addTechnologies(huntId: string, technologies: Technology[]): void {
    const memory = this.memories.get(huntId);
    if (!memory) return;

    for (const tech of technologies) {
      const existing = memory.technologies.find(t => t.name === tech.name);
      if (!existing) {
        memory.technologies.push(tech);
      } else if (tech.version && existing.version && tech.version !== existing.version) {
        console.warn(`[MissionMemory] Tech version contradiction for ${tech.name}: ${existing.version} vs ${tech.version} — merging to newer`);
        existing.version = tech.version;
        existing.confidence = Math.max(existing.confidence, tech.confidence);
      }
    }
    while (memory.technologies.length > MAX_TECHNOLOGIES) memory.technologies.shift();
    memory.lastUpdated = new Date();
  }

  addVulnerabilities(huntId: string, vulnerabilities: Vulnerability[]): void {
    const memory = this.memories.get(huntId);
    if (!memory) return;

    for (const vuln of vulnerabilities) {
      const key = `${vuln.endpoint}:${vuln.type}`;
      const existing = memory.vulnerabilities.find(v => `${v.endpoint}:${v.type}` === key);
      if (!existing) {
        memory.vulnerabilities.push(vuln);
      } else {
        const inRank = SEVERITY_RANK[vuln.severity] ?? 0;
        const exRank = SEVERITY_RANK[existing.severity] ?? 0;
        if (inRank !== exRank) {
          console.warn(`[MissionMemory] Severity contradiction for ${key}: ${existing.severity} vs ${vuln.severity} — keeping higher`);
          if (inRank > exRank) existing.severity = vuln.severity;
        }
      }
    }
    while (memory.vulnerabilities.length > MAX_VULNERABILITIES) memory.vulnerabilities.shift();
    memory.lastUpdated = new Date();
  }

  addCredentials(huntId: string, credentials: Credential[]): void {
    const memory = this.memories.get(huntId);
    if (!memory) return;

    memory.credentials.push(...credentials);
    memory.lastUpdated = new Date();
  }

  addNote(huntId: string, note: string): void {
    const memory = this.memories.get(huntId);
    if (!memory) return;

    memory.notes.push(note);
    while (memory.notes.length > MAX_NOTES) memory.notes.shift();
    memory.lastUpdated = new Date();
  }

  getTargets(huntId: string, phase: string): string[] {
    const memory = this.memories.get(huntId);
    if (!memory) return [];

    switch (phase) {
      case 'recon':
        return memory.domains;
      case 'scanning':
        return memory.endpoints.map(e => e.url);
      case 'exploitation':
        return memory.vulnerabilities
          .filter(v => v.exploitable)
          .map(v => v.endpoint);
      default:
        return [];
    }
  }

  clear(huntId: string): void {
    this.memories.delete(huntId);
  }
}

export const missionMemory = new MissionMemoryStore();
