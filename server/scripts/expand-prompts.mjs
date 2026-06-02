/**
 * expand-prompts.mjs
 *
 * Expands the server/data/prompts dataset from ~1700 to ~10,000+ entries
 * using Claude to generate high-quality security reasoning examples.
 *
 * Usage:
 *   ANTHROPIC_API_KEY=sk-ant-... node server/scripts/expand-prompts.mjs
 *
 * Options (env vars):
 *   TARGET_PER_CATEGORY=50   entries to add per category (default: 50)
 *   BATCH_SIZE=10             entries per API call (default: 10)
 *   MODEL=claude-haiku-4-5-20251001   (default, cheapest + fast)
 *   DRY_RUN=1                 print prompts without calling API
 */

import Anthropic from '@anthropic-ai/sdk';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.resolve(__dirname, '../../server/data/prompts');
const OUTPUT_DIR = path.resolve(__dirname, '../../server/data/prompts');

const TARGET_PER_CATEGORY = parseInt(process.env.TARGET_PER_CATEGORY || '50');
const BATCH_SIZE = parseInt(process.env.BATCH_SIZE || '10');
const MODEL = process.env.MODEL || 'claude-haiku-4-5-20251001';
const DRY_RUN = process.env.DRY_RUN === '1';

if (!process.env.ANTHROPIC_API_KEY && !DRY_RUN) {
  console.error('ERROR: ANTHROPIC_API_KEY not set. Export it before running.');
  process.exit(1);
}

const client = DRY_RUN ? null : new Anthropic();

// ─── Category definitions ────────────────────────────────────────────────────

const CATEGORIES = [
  {
    file: 'api-auth-chains.json',
    outputFile: 'api-auth-chains-generated.json',
    name: 'API Auth Chains',
    schema: { id: 'string (T3-N)', prompt_id: 'string', complexity: 'L1|L2|L3|L4|L5', auth_domain: 'string', scenario: 'string', prompt: 'string', reasoning_focus: 'string', expected_answer: 'string (detailed, 3-5 sentences)', evaluation_criteria: 'string', category: '"api_auth_chains"' },
    authDomains: ['JWT', 'OAuth2', 'SAML', 'OIDC', 'Session Management', 'SSO', 'MFA/2FA', 'API Keys', 'mTLS', 'Certificate Auth', 'WebSocket Auth', 'GraphQL Auth', 'Token Refresh/Rotation', 'LDAP/AD', 'CORS'],
    systemPrompt: `You are a senior application security engineer and bug bounty hunter specializing in authentication vulnerabilities. Generate realistic, technically accurate security reasoning examples about authentication chains, token handling, and auth bypass techniques. Each scenario should reflect real-world misconfiguration patterns found in production systems. Expected answers must be detailed (150-250 words), technically precise, and include specific attack steps and remediation.`,
  },
  {
    file: 'chain-scenarios.json',
    outputFile: 'chain-scenarios-generated.json',
    name: 'Attack Chain Scenarios',
    schema: { id: 'number', scenario: 'string', chain_steps: 'string (step1 → step2 → step3)', prompt: 'string', expected_answer: 'string', reasoning_requirement: 'string', impact_level: 'string (Critical/High/Medium – description)', category: '"chain_scenarios"', evaluation_criteria: 'string' },
    chainTypes: ['XSS → CSRF', 'SSRF → RCE', 'IDOR → Privilege Escalation', 'SQLi → Data Exfiltration', 'Open Redirect → Phishing → Account Takeover', 'CORS → CSRF → Account Takeover', 'XXE → SSRF → Internal Network Access', 'JWT Weakness → Auth Bypass → Data Exfiltration', 'Race Condition → Double Spend', 'LFI → Log Poisoning → RCE', 'Subdomain Takeover → Cookie Theft', 'GraphQL Introspection → IDOR → Data Breach', 'OAuth Misconfiguration → Token Theft → Account Takeover', 'Deserialization → RCE → Lateral Movement', 'Path Traversal → Config Exposure → Credential Theft'],
    systemPrompt: `You are a senior penetration tester who specializes in chained vulnerability exploitation. Generate realistic multi-step attack chain scenarios found in real bug bounty programs. Each chain must be technically plausible, connect vulnerabilities logically, and reflect actual exploitation patterns. The expected answer should explain each step's role in the chain and why the chain as a whole is more severe than individual vulnerabilities.`,
  },
  {
    file: 'vulnerability-severity-reasoning.json',
    outputFile: 'vulnerability-severity-generated.json',
    name: 'Vulnerability Severity Reasoning',
    schema: { id: 'string (T8-N)', complexity: 'L1|L2|L3|L4|L5', vulnerability_type: 'string', scenario: 'string', prompt: 'string', reasoning_focus: 'string', expected_answer: 'string (include CVSS considerations)', evaluation_criteria: 'string' },
    vulnTypes: ['Stored XSS', 'Reflected XSS', 'DOM XSS', 'SQLi (Error-Based)', 'SQLi (Blind)', 'SQLi (Out-of-Band)', 'SSRF (Internal)', 'SSRF (Cloud Metadata)', 'RCE (Deserialization)', 'RCE (Command Injection)', 'IDOR (Horizontal)', 'IDOR (Vertical)', 'Auth Bypass', 'JWT None Algorithm', 'CORS Misconfiguration', 'CSRF (Sensitive Action)', 'XXE (File Read)', 'XXE (SSRF)', 'Path Traversal', 'Open Redirect', 'Business Logic Flaw', 'Race Condition', 'Mass Assignment', 'GraphQL Introspection', 'Subdomain Takeover'],
    systemPrompt: `You are a security researcher with deep expertise in CVSS scoring and vulnerability impact assessment. Generate examples that test nuanced understanding of how context, exploitation complexity, and impact scope affect severity ratings. Expected answers must reference CVSS vector components when relevant and explain why certain factors increase or decrease severity. Focus on edge cases where intuitive severity ratings differ from CVSS-derived ones.`,
  },
  {
    file: 'kali-tool-reasoning.json',
    outputFile: 'kali-tool-reasoning-generated.json',
    name: 'Kali Tool Reasoning',
    schema: { id: 'number', prompt_id: 'string (KT-N)', tool: 'string', scenario: 'string', prompt: 'string', reasoning_focus: 'string', expected_answer: 'string', evaluation_criteria: 'string', category: '"kali_tool_reasoning"' },
    tools: ['nmap', 'sqlmap', 'burpsuite', 'metasploit', 'nikto', 'gobuster', 'ffuf', 'subfinder', 'amass', 'nuclei', 'hydra', 'john', 'hashcat', 'wireshark', 'tcpdump', 'netcat', 'socat', 'curl', 'wfuzz', 'dirb', 'whatweb', 'wapiti', 'masscan', 'shodan', 'theharvester', 'maltego', 'responder', 'impacket', 'crackmapexec', 'bloodhound'],
    systemPrompt: `You are an expert penetration tester and Kali Linux power user. Generate scenarios that test understanding of tool output interpretation, flag selection, and decision-making during active engagements. Scenarios should reflect real-world situations where tool output is ambiguous or where the choice of tool flags significantly affects results. Expected answers should explain the reasoning behind tool selection and configuration decisions.`,
  },
  {
    file: 'kali-tool-interpretation.json',
    outputFile: 'kali-tool-interpretation-generated.json',
    name: 'Kali Tool Output Interpretation',
    schema: { id: 'number', prompt_id: 'string', tool: 'string', scenario: 'string', prompt: 'string', reasoning_focus: 'string', expected_answer: 'string', evaluation_criteria: 'string', category: '"kali_tool_interpretation"' },
    tools: ['nmap', 'sqlmap', 'nikto', 'nuclei', 'gobuster', 'ffuf', 'subfinder', 'amass', 'wfuzz', 'hydra', 'metasploit', 'wireshark', 'tcpdump', 'burpsuite', 'whatweb'],
    systemPrompt: `You are an expert penetration tester who can rapidly interpret security tool output. Generate scenarios where a tool produces specific output that requires interpretation to extract actionable intelligence. The scenario should include a snippet of realistic tool output and ask the tester to interpret what it means and what to do next. Expected answers must explain each relevant finding and provide specific next steps.`,
  },
  {
    file: 'tool-chain-reasoning.json',
    outputFile: 'tool-chain-reasoning-generated.json',
    name: 'Tool Chain Reasoning',
    schema: { id: 'number', prompt_id: 'string', tools_involved: 'string[] (array of tool names)', scenario: 'string', prompt: 'string', reasoning_focus: 'string', expected_answer: 'string', evaluation_criteria: 'string', category: '"tool_chain_reasoning"' },
    toolChains: [
      ['subfinder', 'httpx', 'nuclei'],
      ['nmap', 'gobuster', 'sqlmap'],
      ['amass', 'massdns', 'aquatone'],
      ['burpsuite', 'sqlmap', 'hydra'],
      ['ffuf', 'wfuzz', 'burpsuite'],
      ['nmap', 'metasploit', 'impacket'],
      ['shodan', 'nuclei', 'metasploit'],
      ['theharvester', 'maltego', 'hydra'],
      ['wapiti', 'nikto', 'burpsuite'],
      ['bloodhound', 'crackmapexec', 'impacket'],
    ],
    systemPrompt: `You are a senior penetration tester who designs efficient tool chains for security assessments. Generate scenarios that test understanding of how to sequence security tools for maximum effectiveness. Each scenario should present a specific recon or exploitation objective and ask which tools to chain and why. Expected answers must justify the tool sequence, explain data flow between tools, and identify what each tool adds to the chain.`,
  },
  {
    file: 'attack-paths.json',
    outputFile: 'attack-paths-generated.json',
    name: 'Attack Paths',
    schema: { id: 'number', objective: 'string', scenario: 'string', prompt: 'string', reasoning_requirement: 'string', expected_answer: 'string', evaluation_criteria: 'string', category: '"attack_paths"' },
    objectives: ['Achieve RCE on web application', 'Exfiltrate database credentials', 'Escalate from user to admin', 'Bypass 2FA', 'Access internal network from external', 'Steal session tokens at scale', 'Compromise cloud infrastructure from web app', 'Perform account takeover without credentials', 'Extract PII from API', 'Bypass WAF and exploit SQLi', 'Achieve persistent access', 'Lateral movement from DMZ to internal', 'Exploit business logic for financial gain', 'Enumerate hidden API endpoints', 'Compromise CI/CD pipeline'],
    systemPrompt: `You are a bug bounty hunter and penetration tester who specializes in attack path planning. Generate scenarios that test strategic thinking about how to achieve a specific objective given limited initial access. Scenarios should reflect real-world web application and infrastructure targets. Expected answers must outline a prioritized attack path with specific techniques, explain the reasoning behind each step, and identify key pivot points.`,
  },
  {
    file: 'cloud-security.json',
    outputFile: 'cloud-security-generated.json',
    name: 'Cloud Security',
    schema: { id: 'string (T4-N)', complexity: 'L1|L2|L3|L4|L5', cloud_domain: 'string', scenario: 'string', prompt: 'string', reasoning_focus: 'string', expected_answer: 'string (150-250 words)', evaluation_criteria: 'string' },
    cloudDomains: ['AWS S3', 'AWS IAM', 'AWS EC2', 'AWS Lambda', 'AWS RDS', 'AWS API Gateway', 'AWS CloudTrail', 'AWS STS', 'GCP IAM', 'GCP Storage', 'GCP Compute', 'Azure AD', 'Azure Storage', 'Azure RBAC', 'Kubernetes', 'Docker', 'CI/CD', 'Container Registry', 'Serverless', 'Multi-Cloud'],
    systemPrompt: `You are a cloud security architect and penetration tester specializing in AWS, GCP, Azure, and Kubernetes security. Generate scenarios that test understanding of cloud-specific attack techniques, IAM privilege escalation, metadata service exploitation, and misconfiguration patterns. Scenarios should reflect real-world cloud security findings from bug bounty programs and red team engagements. Expected answers must be technically precise and include specific API calls, IAM policies, or configuration details where relevant.`,
  },
  {
    file: 'business-logic.json',
    outputFile: 'business-logic-generated.json',
    name: 'Business Logic Flaws',
    schema: { id: 'string (T5-N)', complexity: 'L1|L2|L3|L4|L5', domain: 'string', scenario: 'string', prompt: 'string', reasoning_focus: 'string', expected_answer: 'string', evaluation_criteria: 'string' },
    domains: ['E-commerce', 'Fintech', 'Marketplace', 'SaaS Subscription', 'Rewards/Loyalty', 'Payments', 'Coupon/Promo', 'Referrals', 'Auctions', 'Gift Cards', 'Cryptocurrency', 'Insurance', 'Travel Booking', 'Gaming', 'Lending'],
    systemPrompt: `You are a bug bounty hunter who specializes in business logic vulnerabilities in financial and e-commerce applications. Generate scenarios that test understanding of how business rules can be abused for financial gain or unauthorized access. Scenarios should reflect real-world business logic flaws found in production systems. Expected answers must explain the precise abuse flow, quantify the financial or data impact, and describe detection and remediation strategies.`,
  },
  {
    file: 'bounty-patterns.json',
    outputFile: 'bounty-patterns-generated.json',
    name: 'Bug Bounty Patterns',
    schema: { id: 'number', scenario: 'string', prompt: 'string', expected_answer: 'string', evaluation_criteria: 'string', category: '"bounty_patterns"' },
    patterns: ['Rate limiting bypass', 'Mass assignment vulnerability', 'Insecure direct object reference', 'API versioning exposure', 'GraphQL introspection abuse', 'Webhook abuse', 'File upload bypass', 'SSRF via URL parameter', 'Subdomain enumeration findings', 'Cache poisoning', 'HTTP request smuggling', 'Host header injection', 'Parameter pollution', 'JSON injection', 'XML injection'],
    systemPrompt: `You are a prolific bug bounty hunter who has reported hundreds of valid findings across major programs. Generate scenarios that test pattern recognition for common bug bounty vulnerability classes. Each scenario should present realistic application behavior and ask the hunter to identify the vulnerability and exploitation approach. Expected answers must identify the root cause, explain the exploitation technique, and describe a minimal proof-of-concept.`,
  },
  {
    file: 'access-level-scenarios.json',
    outputFile: 'access-level-generated.json',
    name: 'Access Level Scenarios',
    schema: { id: 'string (T7-N)', complexity: 'L1|L2|L3|L4|L5', access_level: 'string', scenario: 'string', prompt: 'string', reasoning_focus: 'string', expected_answer: 'string', evaluation_criteria: 'string' },
    accessLevels: ['Unauthenticated', 'Authenticated User', 'Privileged User', 'Admin', 'Service Account', 'Read-Only', 'API Key (Limited)', 'API Key (Full)', 'OAuth (Limited Scope)', 'Compromised Employee'],
    systemPrompt: `You are a penetration tester specializing in authorization testing and privilege escalation. Generate scenarios that test understanding of what an attacker can achieve from different initial access levels. Scenarios should focus on what additional access can be gained from a starting point and what the realistic impact is. Expected answers must map the access level to specific attack techniques and explain the privilege escalation path.`,
  },
  {
    file: 'engagement-signals.json',
    outputFile: 'engagement-signals-generated.json',
    name: 'Engagement Signals',
    schema: { id: 'string (T6-N)', complexity: 'L1|L2|L3|L4|L5', signal_type: 'string', signal_observed: 'string', prompt: 'string', reasoning_focus: 'string', expected_answer: 'string', evaluation_criteria: 'string' },
    signalTypes: ['HTTP Response Code Pattern', 'Error Message Disclosure', 'Response Time Anomaly', 'Header Disclosure', 'Cookie Attribute', 'Redirect Behavior', 'Content-Type Mismatch', 'CORS Header', 'Cache Header', 'Authentication Challenge', 'Rate Limit Response', 'WAF Fingerprint', 'Technology Fingerprint', 'Debug Information', 'Version Disclosure'],
    systemPrompt: `You are a security researcher who specializes in reading subtle signals during web application assessments. Generate scenarios where specific HTTP responses, headers, or application behavior signals the presence of a vulnerability or interesting attack surface. Each scenario should describe a concrete observable signal and ask what it implies and what to investigate next. Expected answers must explain why the signal is significant and provide specific follow-up actions.`,
  },
  {
    file: 'engagement-decision-reasoning.json',
    outputFile: 'engagement-decision-generated.json',
    name: 'Engagement Decision Reasoning',
    schema: { id: 'string (T10-N)', complexity: 'L1|L2|L3|L4|L5', engagement_context: 'string', scenario: 'string', prompt: 'string', reasoning_focus: 'string', expected_answer: 'string', evaluation_criteria: 'string' },
    contexts: ['Black-box web app', 'Grey-box API assessment', 'White-box code review', 'Bug bounty (public program)', 'Bug bounty (private program)', 'Internal red team', 'Purple team exercise', 'Cloud infrastructure assessment', 'Mobile app testing', 'IoT device assessment'],
    systemPrompt: `You are a lead penetration tester who makes strategic decisions during security engagements. Generate scenarios that test tactical and strategic decision-making: when to escalate a finding, how to prioritize limited time, how to handle ambiguous scope, and how to balance thoroughness with noise. Expected answers must explain the reasoning behind the decision and consider the engagement constraints.`,
  },
  {
    file: 'core-security-logic.json',
    outputFile: 'core-security-logic-generated.json',
    name: 'Core Security Logic',
    schema: { id: 'number', scenario: 'string', prompt: 'string', expected_answer: 'string', evaluation_criteria: 'string', category: '"core_security_logic"' },
    topics: ['Cryptographic weaknesses', 'Session management flaws', 'Input validation bypass', 'Output encoding failures', 'Access control patterns', 'Security misconfiguration', 'Insecure deserialization', 'Using components with known vulnerabilities', 'Insufficient logging', 'Security through obscurity failures'],
    systemPrompt: `You are a security architect with expertise in fundamental security principles and their application to real-world systems. Generate scenarios that test deep understanding of core security concepts and how they manifest as vulnerabilities in production systems. Scenarios should be specific enough to require technical knowledge but general enough to apply across different tech stacks. Expected answers must explain the underlying security principle, how it was violated, and what correct implementation looks like.`,
  },
  {
    file: 'cybersec-reasoning.json',
    outputFile: 'cybersec-reasoning-generated.json',
    name: 'Cybersecurity Reasoning',
    schema: { id: 'number', scenario: 'string', prompt: 'string', expected_answer: 'string', evaluation_criteria: 'string', category: '"cybersec_reasoning"' },
    topics: ['Threat modeling', 'Risk assessment', 'Defense in depth', 'Zero trust architecture', 'Incident response decision', 'Forensic analysis', 'Malware behavior', 'Network segmentation', 'Cryptographic protocol analysis', 'Social engineering defense'],
    systemPrompt: `You are a cybersecurity expert with broad knowledge spanning offensive and defensive security. Generate scenarios that test higher-order security reasoning: threat modeling, risk prioritization, architectural security decisions, and incident response triage. Expected answers should demonstrate nuanced understanding of attacker motivation, defensive trade-offs, and the relationship between technical controls and business risk.`,
  },
  {
    file: 'defensive-awareness.json',
    outputFile: 'defensive-awareness-generated.json',
    name: 'Defensive Awareness',
    schema: { id: 'number', signal_observed: 'string', level: 'string', scenario: 'string', prompt: 'string', expected_answer: 'string', evaluation_criteria: 'string', category: '"defensive_awareness"' },
    levels: ['Low', 'Medium', 'High', 'Advanced'],
    systemPrompt: `You are a red team operator who understands blue team detection capabilities. Generate scenarios that test awareness of what defensive signals an offensive action triggers. Each scenario should describe an attack technique and ask what logs, alerts, or anomalies it generates. Expected answers must identify specific log sources (SIEM, EDR, WAF, etc.), detection rules, and how a skilled attacker would modify their behavior to reduce detection while maintaining effectiveness.`,
  },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function loadExisting(filename) {
  const p = path.join(DATA_DIR, filename);
  if (!fs.existsSync(p)) return [];
  try { return JSON.parse(fs.readFileSync(p, 'utf-8')); } catch { return []; }
}

function loadCheckpoint(filename) {
  const p = path.join(OUTPUT_DIR, filename);
  if (!fs.existsSync(p)) return [];
  try { return JSON.parse(fs.readFileSync(p, 'utf-8')); } catch { return []; }
}

function saveCheckpoint(filename, entries) {
  fs.writeFileSync(path.join(OUTPUT_DIR, filename), JSON.stringify(entries, null, 2));
}

function pickRandom(arr, n) {
  const shuffled = [...arr].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, n);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function callWithRetry(fn, retries = 4) {
  for (let i = 0; i <= retries; i++) {
    try { return await fn(); }
    catch (err) {
      if (i === retries) throw err;
      const wait = Math.pow(2, i) * 2000;
      console.log(`  Retry ${i + 1} in ${wait / 1000}s... (${err.message?.slice(0, 60)})`);
      await sleep(wait);
    }
  }
}

// ─── Generation ───────────────────────────────────────────────────────────────

async function generateBatch(category, seedEntries, alreadyGenerated, batchSize) {
  const seeds = pickRandom(seedEntries, Math.min(3, seedEntries.length));
  const schemaStr = JSON.stringify(category.schema, null, 2);

  // Build a category-specific diversity hint
  let diversityHint = '';
  if (category.authDomains)   diversityHint = `Vary across auth domains: ${pickRandom(category.authDomains, 4).join(', ')}`;
  if (category.chainTypes)    diversityHint = `Use attack chains like: ${pickRandom(category.chainTypes, 3).join(' | ')}`;
  if (category.vulnTypes)     diversityHint = `Cover vuln types: ${pickRandom(category.vulnTypes, 4).join(', ')}`;
  if (category.tools)         diversityHint = `Focus on tools: ${pickRandom(category.tools, 4).join(', ')}`;
  if (category.toolChains)    diversityHint = `Use tool chains: ${JSON.stringify(pickRandom(category.toolChains, 2))}`;
  if (category.objectives)    diversityHint = `Target objectives: ${pickRandom(category.objectives, 3).join(' | ')}`;
  if (category.cloudDomains)  diversityHint = `Cloud domains: ${pickRandom(category.cloudDomains, 4).join(', ')}`;
  if (category.domains)       diversityHint = `Business domains: ${pickRandom(category.domains, 4).join(', ')}`;
  if (category.patterns)      diversityHint = `Cover patterns: ${pickRandom(category.patterns, 4).join(', ')}`;
  if (category.accessLevels)  diversityHint = `Access levels: ${pickRandom(category.accessLevels, 4).join(', ')}`;
  if (category.signalTypes)   diversityHint = `Signal types: ${pickRandom(category.signalTypes, 4).join(', ')}`;
  if (category.contexts)      diversityHint = `Engagement contexts: ${pickRandom(category.contexts, 3).join(', ')}`;
  if (category.topics)        diversityHint = `Topics: ${pickRandom(category.topics, 4).join(', ')}`;
  if (category.levels)        diversityHint = `Defensive levels: ${pickRandom(category.levels, 3).join(', ')}`;

  const nextId = (seedEntries.length + alreadyGenerated.length) + 1;

  const userPrompt = `Generate exactly ${batchSize} new security training examples for the "${category.name}" category.

SCHEMA (every entry must have ALL these fields):
${schemaStr}

SEED EXAMPLES (match this quality and style, but generate DIFFERENT scenarios):
${JSON.stringify(seeds, null, 2)}

DIVERSITY REQUIREMENT: ${diversityHint}

REQUIREMENTS:
- Each entry must be technically accurate and reflect real-world security findings
- Scenarios must be specific and concrete, not generic
- Expected answers must be detailed (150-250 words for complex topics, 80-150 for simpler ones)
- Vary complexity levels (L1=basic, L5=expert) across entries
- IDs should start from ${nextId} and increment
- No duplicate scenarios from the seeds or each other
- Return ONLY a valid JSON array of ${batchSize} objects, no other text`;

  if (DRY_RUN) {
    console.log('\n--- DRY RUN PROMPT ---');
    console.log(`System: ${category.systemPrompt.slice(0, 100)}...`);
    console.log(`User: ${userPrompt.slice(0, 200)}...`);
    return [];
  }

  const response = await callWithRetry(() => client.messages.create({
    model: MODEL,
    max_tokens: 8000,
    temperature: 0.85,
    system: category.systemPrompt,
    messages: [{ role: 'user', content: userPrompt }],
  }));

  const text = response.content[0].type === 'text' ? response.content[0].text : '';

  // Extract JSON array from response (handle markdown code blocks)
  const jsonMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/) || text.match(/(\[[\s\S]*\])/);
  const jsonStr = jsonMatch ? jsonMatch[1] : text.trim();

  try {
    const entries = JSON.parse(jsonStr);
    if (!Array.isArray(entries)) throw new Error('Not an array');
    return entries;
  } catch (err) {
    console.warn(`  Parse error: ${err.message}. Response snippet: ${text.slice(0, 200)}`);
    return [];
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`\n🔐 Prompt Dataset Expander`);
  console.log(`   Model: ${MODEL}`);
  console.log(`   Target per category: ${TARGET_PER_CATEGORY}`);
  console.log(`   Batch size: ${BATCH_SIZE}`);
  console.log(`   Dry run: ${DRY_RUN}`);
  console.log(`   Output dir: ${OUTPUT_DIR}\n`);

  let totalGenerated = 0;
  const startTime = Date.now();

  for (const category of CATEGORIES) {
    const seedEntries = loadExisting(category.file);
    const checkpoint = loadCheckpoint(category.outputFile);

    const needed = Math.max(0, TARGET_PER_CATEGORY - checkpoint.length);
    console.log(`\n📂 ${category.name}`);
    console.log(`   Seed entries: ${seedEntries.length} | Already generated: ${checkpoint.length} | Need: ${needed}`);

    if (needed === 0) {
      console.log(`   ✅ Already at target, skipping`);
      continue;
    }

    if (seedEntries.length === 0) {
      console.log(`   ⚠️  No seed file found (${category.file}), skipping`);
      continue;
    }

    const generated = [...checkpoint];
    let batchNum = 0;

    while (generated.length < TARGET_PER_CATEGORY) {
      const remaining = TARGET_PER_CATEGORY - generated.length;
      const thisBatch = Math.min(BATCH_SIZE, remaining);
      batchNum++;

      process.stdout.write(`   Batch ${batchNum} (${generated.length}/${TARGET_PER_CATEGORY})... `);

      try {
        const newEntries = await generateBatch(category, seedEntries, generated, thisBatch);
        if (DRY_RUN) { process.stdout.write(`(dry-run, skipping)\n`); break; }
        if (newEntries.length > 0) {
          generated.push(...newEntries);
          saveCheckpoint(category.outputFile, generated);
          process.stdout.write(`✓ +${newEntries.length}\n`);
          totalGenerated += newEntries.length;
        } else {
          process.stdout.write(`⚠ empty response\n`);
        }
      } catch (err) {
        process.stdout.write(`✗ ${err.message?.slice(0, 80)}\n`);
      }

      // Small delay between batches to respect rate limits
      if (!DRY_RUN && generated.length < TARGET_PER_CATEGORY) {
        await sleep(1000);
      }
    }

    console.log(`   ✅ ${category.name}: ${generated.length} total entries saved to ${category.outputFile}`);
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`\n✅ Done! Generated ${totalGenerated} new entries in ${elapsed}s`);
  console.log(`   Files saved to: ${OUTPUT_DIR}`);
  console.log(`\nNext step: the server auto-loads all *.json files in data/prompts/ on startup.`);
  console.log(`Restart the server to pick up the new entries.\n`);
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
