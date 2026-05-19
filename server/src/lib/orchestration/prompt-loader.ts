import fs from 'fs';
import path from 'path';

export interface PromptTemplate {
  id: string;
  phase: string;
  agent: string;
  name: string;
  description: string;
  template: string;
  variables: string[];
  confidence_threshold: number;
  version: number;
  output_schema: Record<string, any>;
  tags: string[];
}

export interface PromptsData {
  metadata: {
    version: string;
    total_templates: number;
    last_updated: string;
    phases: string[];
    agents: string[];
  };
  templates: PromptTemplate[];
  confidence_thresholds?: Record<string, number>;
  phase_progression?: Record<string, string[]>;
}

class PromptManager {
  private templates: Map<string, PromptTemplate> = new Map();
  private promptsData: PromptsData = {
    metadata: {
      version: '1.0.0',
      total_templates: 0,
      last_updated: new Date().toISOString().split('T')[0],
      phases: [],
      agents: []
    },
    templates: []
  };

  constructor() {
    try {
      this.loadFromFile();
    } catch (e) {
      console.log('PromptManager: prompts.json not found, starting with empty templates');
    }
  }

  loadFromFile(filePath?: string): void {
    const resolvedPath = filePath || path.resolve(process.cwd(), 'prompts.json');
    const raw = fs.readFileSync(resolvedPath, 'utf-8');
    this.promptsData = JSON.parse(raw);
    this.templates.clear();
    for (const t of this.promptsData.templates) {
      this.templates.set(t.id, t);
    }
  }

  getTemplate(id: string): PromptTemplate | null {
    return this.templates.get(id) || null;
  }

  getByPhase(phase: string): PromptTemplate[] {
    return this.promptsData.templates.filter(t => t.phase === phase);
  }

  getByAgent(agent: string): PromptTemplate[] {
    return this.promptsData.templates.filter(t => t.agent === agent);
  }

  getByTags(tags: string[]): PromptTemplate[] {
    return this.promptsData.templates.filter(t =>
      t.tags.some(tag => tags.includes(tag))
    );
  }

  searchTemplates(query: string): PromptTemplate[] {
    const q = query.toLowerCase();
    return this.promptsData.templates.filter(t =>
      t.name.toLowerCase().includes(q) ||
      t.description.toLowerCase().includes(q) ||
      t.tags.some(tag => tag.toLowerCase().includes(q))
    );
  }

  renderTemplate(id: string, variables: Record<string, string>): string | null {
    const template = this.templates.get(id);
    if (!template) return null;
    return this.renderTemplateRaw(template.template, variables);
  }

  renderTemplateRaw(template: string, variables: Record<string, string>): string {
    let result = template;
    for (const [key, value] of Object.entries(variables)) {
      result = result.replace(new RegExp(`\\{\\{${key}\\}\\}`, 'g'), value);
    }
    return result;
  }

  addTemplate(template: PromptTemplate): void {
    this.templates.set(template.id, template);
    this.promptsData.templates.push(template);
    this.promptsData.metadata.total_templates = this.promptsData.templates.length;
  }

  updateTemplate(id: string, updates: Partial<PromptTemplate>): PromptTemplate | null {
    const existing = this.templates.get(id);
    if (!existing) return null;
    const updated = { ...existing, ...updates, id };
    this.templates.set(id, updated);
    const idx = this.promptsData.templates.findIndex(t => t.id === id);
    if (idx !== -1) {
      this.promptsData.templates[idx] = updated;
    }
    return updated;
  }

  deleteTemplate(id: string): boolean {
    if (!this.templates.has(id)) return false;
    this.templates.delete(id);
    this.promptsData.templates = this.promptsData.templates.filter(t => t.id !== id);
    this.promptsData.metadata.total_templates = this.promptsData.templates.length;
    return true;
  }

  getAllTemplates(): PromptTemplate[] {
    return [...this.promptsData.templates];
  }

  getStats(): object {
    const byPhase: Record<string, number> = {};
    const byAgent: Record<string, number> = {};
    for (const t of this.promptsData.templates) {
      byPhase[t.phase] = (byPhase[t.phase] || 0) + 1;
      byAgent[t.agent] = (byAgent[t.agent] || 0) + 1;
    }
    return {
      total: this.promptsData.templates.length,
      byPhase,
      byAgent,
      phases: Object.keys(byPhase),
      agents: Object.keys(byAgent),
      version: this.promptsData.metadata.version,
      lastUpdated: this.promptsData.metadata.last_updated
    };
  }

  saveToFile(filePath?: string): void {
    const resolvedPath = filePath || path.resolve(process.cwd(), 'prompts.json');
    this.promptsData.metadata.total_templates = this.promptsData.templates.length;
    this.promptsData.metadata.last_updated = new Date().toISOString().split('T')[0];
    fs.writeFileSync(resolvedPath, JSON.stringify(this.promptsData, null, 2), 'utf-8');
  }

  resetToDefaults(): void {
    this.loadFromFile();
  }

  validateTemplate(template: Partial<PromptTemplate>): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    const required: (keyof PromptTemplate)[] = ['id', 'phase', 'agent', 'name', 'description', 'template', 'variables', 'confidence_threshold', 'version', 'output_schema', 'tags'];
    for (const field of required) {
      if (template[field] === undefined || template[field] === null) {
        errors.push(`Missing required field: ${field}`);
      }
    }
    if (template.id && typeof template.id !== 'string') {
      errors.push('id must be a string');
    }
    if (template.variables && !Array.isArray(template.variables)) {
      errors.push('variables must be an array');
    }
    if (template.tags && !Array.isArray(template.tags)) {
      errors.push('tags must be an array');
    }
    if (template.confidence_threshold !== undefined && (typeof template.confidence_threshold !== 'number' || template.confidence_threshold < 0 || template.confidence_threshold > 1)) {
      errors.push('confidence_threshold must be a number between 0 and 1');
    }
    if (template.version !== undefined && typeof template.version !== 'number') {
      errors.push('version must be a number');
    }
    return { valid: errors.length === 0, errors };
  }

  exportTemplates(): PromptsData {
    return JSON.parse(JSON.stringify(this.promptsData));
  }

  importTemplates(data: PromptsData): { imported: number; errors: string[] } {
    const errors: string[] = [];
    let imported = 0;
    if (!data || !data.templates || !Array.isArray(data.templates)) {
      errors.push('Invalid data format: missing templates array');
      return { imported, errors };
    }
    for (const t of data.templates) {
      const validation = this.validateTemplate(t);
      if (!validation.valid) {
        errors.push(`Template ${t.id || 'unknown'}: ${validation.errors.join(', ')}`);
        continue;
      }
      if (this.templates.has(t.id)) {
        this.updateTemplate(t.id, t);
      } else {
        this.addTemplate(t);
      }
      imported++;
    }
    return { imported, errors };
  }

  getConfidenceThresholds(): Record<string, number> {
    if (this.promptsData.confidence_thresholds) {
      return { ...this.promptsData.confidence_thresholds };
    }
    const result: Record<string, number> = {};
    this.templates.forEach((t, id) => {
      result[id] = t.confidence_threshold;
    });
    return result;
  }

  setConfidenceThresholds(thresholds: Record<string, number>): void {
    this.promptsData.confidence_thresholds = { ...thresholds };
  }

  getPhaseProgression(): Record<string, string[]> {
    return this.promptsData.phase_progression || {};
  }

  getTemplatesForPhase(phase: string): PromptTemplate[] {
    const progression = this.promptsData.phase_progression || {};
    const templateIds = progression[phase] || [];
    return templateIds
      .map(id => this.templates.get(id))
      .filter((t): t is PromptTemplate => t !== undefined);
  }

  setPhaseProgression(progression: Record<string, string[]>): void {
    this.promptsData.phase_progression = { ...progression };
  }
}

export const promptManager = new PromptManager();
