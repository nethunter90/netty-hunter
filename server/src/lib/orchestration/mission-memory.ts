import { MissionMemory, Endpoint, Technology, Vulnerability, Credential } from './types';

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
    memory.lastUpdated = new Date();
  }

  addEndpoints(huntId: string, endpoints: Endpoint[]): void {
    const memory = this.memories.get(huntId);
    if (!memory) return;

    const existingUrls = new Set(memory.endpoints.map(e => e.url));
    const newEndpoints = endpoints.filter(e => !existingUrls.has(e.url));

    memory.endpoints.push(...newEndpoints);
    memory.lastUpdated = new Date();
  }

  addTechnologies(huntId: string, technologies: Technology[]): void {
    const memory = this.memories.get(huntId);
    if (!memory) return;

    const existingNames = new Set(memory.technologies.map(t => t.name));
    const newTech = technologies.filter(t => !existingNames.has(t.name));

    memory.technologies.push(...newTech);
    memory.lastUpdated = new Date();
  }

  addVulnerabilities(huntId: string, vulnerabilities: Vulnerability[]): void {
    const memory = this.memories.get(huntId);
    if (!memory) return;

    memory.vulnerabilities.push(...vulnerabilities);
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
