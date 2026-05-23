import { MITRE_TECHNIQUES, MitreTechnique, MitreNodeType } from './seed-knowledge';

export interface AttackChain {
  techniques: MitreTechnique[];
  totalProbability: number;
  totalImpact: number;
  avgStealth: number;
  prerequisites: string[];
  provides: string[];
  length: number;
}

export interface PrerequisiteAnalysis {
  goal: string;
  requiredCapabilities: string[];
  availableCapabilities: string[];
  missingCapabilities: string[];
  suggestedTechniques: MitreTechnique[];
  viableChains: AttackChain[];
}

export interface ChokePoint {
  capability: string;
  dependentTechniques: MitreTechnique[];
  isBottleneck: boolean;
  alternativePaths: number;
}

class MITREPrereqTree {
  private techniques: MitreTechnique[];
  private adjacencyMap: Map<string, Set<string>>;
  private providerMap: Map<string, MitreTechnique[]>;
  private requirerMap: Map<string, MitreTechnique[]>;

  constructor() {
    this.techniques = MITRE_TECHNIQUES;
    this.adjacencyMap = new Map();
    this.providerMap = new Map();
    this.requirerMap = new Map();
    this.buildMaps();
  }

  private buildMaps(): void {
    for (const tech of this.techniques) {
      for (const cap of tech.provides) {
        if (!this.providerMap.has(cap)) {
          this.providerMap.set(cap, []);
        }
        this.providerMap.get(cap)!.push(tech);
      }
      for (const cap of tech.requires) {
        if (!this.requirerMap.has(cap)) {
          this.requirerMap.set(cap, []);
        }
        this.requirerMap.get(cap)!.push(tech);
      }
    }

    for (const tech of this.techniques) {
      const followers = new Set<string>();
      for (const provided of tech.provides) {
        const dependents = this.requirerMap.get(provided) || [];
        for (const dep of dependents) {
          if (dep.id !== tech.id) {
            followers.add(dep.id);
          }
        }
      }
      this.adjacencyMap.set(tech.id, followers);
    }
  }

  private buildChain(techniques: MitreTechnique[]): AttackChain {
    const totalProbability = techniques.reduce((acc, t) => acc * t.probability, 1);
    const totalImpact = techniques.reduce((acc, t) => acc + t.impact, 0);
    const avgStealth = techniques.length > 0
      ? techniques.reduce((acc, t) => acc + t.stealth, 0) / techniques.length
      : 0;

    const allRequires = new Set<string>();
    const allProvides = new Set<string>();
    for (const t of techniques) {
      for (const r of t.requires) allRequires.add(r);
      for (const p of t.provides) allProvides.add(p);
    }

    const prerequisites = Array.from(allRequires).filter(r => !allProvides.has(r));

    return {
      techniques,
      totalProbability,
      totalImpact,
      avgStealth,
      prerequisites,
      provides: Array.from(allProvides),
      length: techniques.length,
    };
  }

  findChainsToGoal(
    goalCapability: string,
    currentCapabilities: string[] = [],
    maxDepth: number = 10
  ): AttackChain[] {
    const chains: AttackChain[] = [];
    const currentSet = new Set(currentCapabilities);

    const recurse = (
      targetCapability: string,
      path: MitreTechnique[],
      visited: Set<string>,
      depth: number
    ): void => {
      if (chains.length >= 50) return;
      if (depth > maxDepth) return;

      if (currentSet.has(targetCapability)) {
        if (path.length > 0) {
          chains.push(this.buildChain([...path].reverse()));
        }
        return;
      }

      const providers = this.providerMap.get(targetCapability) || [];
      for (const tech of providers) {
        if (visited.has(tech.id)) continue;
        if (chains.length >= 50) return;

        visited.add(tech.id);
        path.push(tech);

        const unmetRequires = tech.requires.filter(r => !currentSet.has(r));

        if (unmetRequires.length === 0) {
          chains.push(this.buildChain([...path].reverse()));
        } else {
          const subPaths = this.findSubPaths(unmetRequires, currentSet, visited, path, depth + 1, maxDepth, chains);
          if (!subPaths) {
            for (const req of unmetRequires) {
              recurse(req, path, visited, depth + 1);
            }
          }
        }

        path.pop();
        visited.delete(tech.id);
      }
    };

    recurse(goalCapability, [], new Set(), 0);

    chains.sort((a, b) => {
      const scoreA = a.totalProbability * a.totalImpact;
      const scoreB = b.totalProbability * b.totalImpact;
      return scoreB - scoreA;
    });

    return chains.slice(0, 50);
  }

  private findSubPaths(
    unmetRequires: string[],
    currentSet: Set<string>,
    visited: Set<string>,
    path: MitreTechnique[],
    depth: number,
    maxDepth: number,
    chains: AttackChain[]
  ): boolean {
    if (unmetRequires.length === 1) return false;

    let allMet = true;
    for (const req of unmetRequires) {
      const providers = this.providerMap.get(req) || [];
      const available = providers.filter(p => !visited.has(p.id));
      if (available.length === 0 && !currentSet.has(req)) {
        allMet = false;
        break;
      }
    }

    if (!allMet) return false;

    for (const req of unmetRequires) {
      if (!currentSet.has(req)) {
        const providers = this.providerMap.get(req) || [];
        for (const tech of providers) {
          if (visited.has(tech.id)) continue;
          if (chains.length >= 50) return true;

          const techUnmet = tech.requires.filter(r => !currentSet.has(r));
          if (techUnmet.length === 0) {
            visited.add(tech.id);
            path.push(tech);
            chains.push(this.buildChain([...path].reverse()));
            path.pop();
            visited.delete(tech.id);
          }
        }
      }
    }

    return chains.length > 0;
  }

  analyzePrerequisites(
    goalCapability: string,
    currentCapabilities: string[] = []
  ): PrerequisiteAnalysis {
    const currentSet = new Set(currentCapabilities);
    const viableChains = this.findChainsToGoal(goalCapability, currentCapabilities);

    const requiredSet = new Set<string>();
    for (const chain of viableChains) {
      for (const t of chain.techniques) {
        for (const r of t.requires) {
          requiredSet.add(r);
        }
      }
    }

    const requiredCapabilities = Array.from(requiredSet);
    const availableCapabilities = requiredCapabilities.filter(r => currentSet.has(r));
    const missingCapabilities = requiredCapabilities.filter(r => !currentSet.has(r));

    const suggestedTechniques: MitreTechnique[] = [];
    const seen = new Set<string>();
    for (const missing of missingCapabilities) {
      const providers = this.providerMap.get(missing) || [];
      for (const tech of providers) {
        if (!seen.has(tech.id)) {
          seen.add(tech.id);
          suggestedTechniques.push(tech);
        }
      }
    }

    suggestedTechniques.sort((a, b) => (b.probability * b.impact) - (a.probability * a.impact));

    return {
      goal: goalCapability,
      requiredCapabilities,
      availableCapabilities,
      missingCapabilities,
      suggestedTechniques,
      viableChains,
    };
  }

  getNextTechnique(
    currentCapabilities: string[],
    goalCapability: string
  ): MitreTechnique | null {
    const currentSet = new Set(currentCapabilities);

    const goalProviders = this.providerMap.get(goalCapability) || [];
    const goalRequirements = new Set<string>();
    for (const provider of goalProviders) {
      for (const r of provider.requires) {
        goalRequirements.add(r);
      }
    }

    const candidates = this.techniques.filter(tech => {
      const hasPrereqs = tech.requires.every(r => currentSet.has(r));
      if (!hasPrereqs) return false;
      const providesGoalDirectly = tech.provides.some(p => p === goalCapability);
      const fillsGoalPrereqs = tech.provides.some(p => goalRequirements.has(p));
      return providesGoalDirectly || fillsGoalPrereqs;
    });

    if (candidates.length === 0) {
      const reachable = this.techniques.filter(tech =>
        tech.requires.every(r => currentSet.has(r))
      );

      if (reachable.length === 0) return null;

      const allGoalReqs = this.collectAllRequirements(goalCapability, new Set());

      reachable.sort((a, b) => {
        const aRelevance = a.provides.filter(p => allGoalReqs.has(p)).length;
        const bRelevance = b.provides.filter(p => allGoalReqs.has(p)).length;
        const aScore = aRelevance * a.probability * a.stealth;
        const bScore = bRelevance * b.probability * b.stealth;
        return bScore - aScore;
      });

      return reachable[0] || null;
    }

    candidates.sort((a, b) => {
      const aFills = a.provides.filter(p => goalRequirements.has(p) || p === goalCapability).length;
      const bFills = b.provides.filter(p => goalRequirements.has(p) || p === goalCapability).length;
      const aScore = aFills * a.probability * a.stealth;
      const bScore = bFills * b.probability * b.stealth;
      return bScore - aScore;
    });

    return candidates[0];
  }

  private collectAllRequirements(capability: string, visited: Set<string>): Set<string> {
    if (visited.has(capability)) return new Set();
    visited.add(capability);

    const result = new Set<string>([capability]);
    const providers = this.providerMap.get(capability) || [];
    for (const tech of providers) {
      for (const req of tech.requires) {
        const sub = this.collectAllRequirements(req, visited);
        Array.from(sub).forEach(s => result.add(s));
      }
    }
    return result;
  }

  findChokePoints(): ChokePoint[] {
    const allCapabilities = new Set<string>();
    for (const tech of this.techniques) {
      for (const r of tech.requires) allCapabilities.add(r);
      for (const p of tech.provides) allCapabilities.add(p);
    }

    const chokePoints: ChokePoint[] = [];

    for (const cap of Array.from(allCapabilities)) {
      const dependents = this.requirerMap.get(cap) || [];
      const providers = this.providerMap.get(cap) || [];

      if (dependents.length === 0) continue;

      const isBottleneck = providers.length <= 1 && dependents.length > 0;
      const alternativePaths = providers.length;

      chokePoints.push({
        capability: cap,
        dependentTechniques: dependents,
        isBottleneck,
        alternativePaths,
      });
    }

    chokePoints.sort((a, b) => {
      const aScore = a.dependentTechniques.length / Math.max(a.alternativePaths, 1);
      const bScore = b.dependentTechniques.length / Math.max(b.alternativePaths, 1);
      return bScore - aScore;
    });

    return chokePoints;
  }

  getReachableCapabilities(currentCapabilities: string[]): string[] {
    const reachable = new Set(currentCapabilities);
    let changed = true;

    while (changed) {
      changed = false;
      for (const tech of this.techniques) {
        const canExecute = tech.requires.every(r => reachable.has(r));
        if (canExecute) {
          for (const p of tech.provides) {
            if (!reachable.has(p)) {
              reachable.add(p);
              changed = true;
            }
          }
        }
      }
    }

    return Array.from(reachable).filter(c => !currentCapabilities.includes(c));
  }

  getTechniquesByNodeType(nodeType: MitreNodeType): MitreTechnique[] {
    return this.techniques.filter(t => t.nodeType === nodeType);
  }

  getStats(): {
    totalTechniques: number;
    totalCapabilities: number;
    entryPoints: number;
    goalNodes: number;
    chokePointCount: number;
  } {
    const allCaps = new Set<string>();
    for (const tech of this.techniques) {
      for (const r of tech.requires) allCaps.add(r);
      for (const p of tech.provides) allCaps.add(p);
    }

    return {
      totalTechniques: this.techniques.length,
      totalCapabilities: allCaps.size,
      entryPoints: this.techniques.filter(t => t.nodeType === 'entry').length,
      goalNodes: this.techniques.filter(t => t.nodeType === 'goal' || t.nodeType === 'exfil').length,
      chokePointCount: this.findChokePoints().filter(c => c.isBottleneck).length,
    };
  }
}

export const mitrePrereqTree = new MITREPrereqTree();
