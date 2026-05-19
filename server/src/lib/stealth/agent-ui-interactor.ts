import { stealthLogger } from './stealth-logger';

function rand(min: number, max: number): number {
  return Math.random() * (max - min) + min;
}

function randInt(min: number, max: number): number {
  return Math.floor(rand(min, max + 1));
}

function easeInOut(t: number): number {
  return t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
}

const SPECIAL_CHARS = '!@#$%^&*()_+-=[]{}|;:\'",.<>?/`~';
const NEIGHBOR_KEYS: Record<string, string> = {
  a: 'sq', b: 'vn', c: 'xv', d: 'sf', e: 'wr', f: 'dg', g: 'fh',
  h: 'gj', i: 'uo', j: 'hk', k: 'jl', l: 'k;', m: 'n,', n: 'bm',
  o: 'ip', p: 'o[', q: 'wa', r: 'et', s: 'ad', t: 'ry', u: 'yi',
  v: 'cb', w: 'qe', x: 'zc', y: 'tu', z: 'xs',
};

function getTypoChar(correct: string): string {
  const lower = correct.toLowerCase();
  const neighbors = NEIGHBOR_KEYS[lower];
  if (neighbors) {
    const picked = neighbors[randInt(0, neighbors.length - 1)];
    return correct === correct.toUpperCase() ? picked.toUpperCase() : picked;
  }
  return String.fromCharCode(correct.charCodeAt(0) + (Math.random() > 0.5 ? 1 : -1));
}

interface TypingEvent {
  char: string;
  delay: number;
  isTypo?: boolean;
  backspaceDelay?: number;
}

interface MousePoint {
  x: number;
  y: number;
  timestamp: number;
}

interface ClickResult {
  hoverDelay: number;
  doubleClick: boolean;
  preMovePoints: Array<{ x: number; y: number }>;
}

interface ScrollResult {
  scrollSteps: Array<{ delta: number; delay: number }>;
  postPause: number;
}

interface IdleResult {
  idle: boolean;
  duration: number;
}

interface InteractionStep {
  action: string;
  idle?: IdleResult;
  responseDelay: number;
  details: any;
}

class AgentUIInteractor {
  simulateTyping(text: string): TypingEvent[] {
    const wpm = rand(80, 180);
    const isBurst = Math.random() < 0.15;
    const effectiveWpm = isBurst ? wpm * 1.4 : wpm;
    const charsPerMs = (effectiveWpm * 5) / 60000;
    const baseDelay = 1 / charsPerMs;

    const events: TypingEvent[] = [];

    for (const char of text) {
      let delay = baseDelay + rand(-baseDelay * 0.2, baseDelay * 0.2);

      if (char === ' ') {
        delay *= 1.5;
      } else if (char === char.toUpperCase() && char !== char.toLowerCase()) {
        delay *= 1.3;
      } else if (SPECIAL_CHARS.includes(char)) {
        delay *= 1.4;
      }

      const isTypo = Math.random() < 0.02;

      if (isTypo) {
        const wrongChar = getTypoChar(char);
        const backspaceDelay = rand(80, 200);
        events.push({
          char: wrongChar,
          delay: Math.round(delay),
          isTypo: true,
          backspaceDelay: Math.round(backspaceDelay),
        });
        events.push({
          char,
          delay: Math.round(rand(50, 150)),
        });
      } else {
        events.push({ char, delay: Math.round(delay) });
      }
    }

    stealthLogger.log('human_simulation', {
      type: 'typing',
      textLength: text.length,
      eventCount: events.length,
      wpm: Math.round(effectiveWpm),
      burst: isBurst,
    });

    return events;
  }

  simulateMouseMove(fromX: number, fromY: number, toX: number, toY: number): MousePoint[] {
    const points: MousePoint[] = [];
    const now = Date.now();
    const duration = rand(200, 600);
    const numPoints = 5;

    const cx1 = fromX + (toX - fromX) * rand(0.2, 0.4) + rand(-30, 30);
    const cy1 = fromY + (toY - fromY) * rand(0.1, 0.3) + rand(-30, 30);
    const cx2 = fromX + (toX - fromX) * rand(0.6, 0.8) + rand(-30, 30);
    const cy2 = fromY + (toY - fromY) * rand(0.7, 0.9) + rand(-30, 30);

    for (let i = 0; i < numPoints; i++) {
      const t = easeInOut(i / (numPoints - 1));
      const u = 1 - t;

      let x = u * u * u * fromX + 3 * u * u * t * cx1 + 3 * u * t * t * cx2 + t * t * t * toX;
      let y = u * u * u * fromY + 3 * u * u * t * cy1 + 3 * u * t * t * cy2 + t * t * t * toY;

      x += rand(-2, 2);
      y += rand(-2, 2);

      points.push({
        x: Math.round(x * 100) / 100,
        y: Math.round(y * 100) / 100,
        timestamp: Math.round(now + duration * (i / (numPoints - 1))),
      });
    }

    stealthLogger.log('human_simulation', {
      type: 'mouse_move',
      from: { x: fromX, y: fromY },
      to: { x: toX, y: toY },
      pointCount: numPoints,
      duration: Math.round(duration),
    });

    return points;
  }

  simulateClick(x: number, y: number): ClickResult {
    const hoverDelay = Math.round(rand(200, 800));
    const doubleClick = Math.random() < 0.02;

    const offsetX = rand(-50, 50);
    const offsetY = rand(-50, 50);
    const movePoints = this.simulateMouseMove(x + offsetX, y + offsetY, x, y);
    const preMovePoints = movePoints.map(p => ({ x: p.x, y: p.y }));

    stealthLogger.log('human_simulation', {
      type: 'click',
      position: { x, y },
      hoverDelay,
      doubleClick,
      preMovePointCount: preMovePoints.length,
    });

    return { hoverDelay, doubleClick, preMovePoints };
  }

  simulateScroll(amount: number): ScrollResult {
    const stepCount = randInt(3, 8);
    const scrollSteps: Array<{ delta: number; delay: number }> = [];
    let remaining = amount;

    for (let i = 0; i < stepCount; i++) {
      const isLast = i === stepCount - 1;
      const portion = isLast ? remaining : Math.round(remaining * rand(0.15, 0.35));
      remaining -= portion;

      scrollSteps.push({
        delta: portion,
        delay: Math.round(rand(30, 120)),
      });
    }

    const postPause = Math.round(rand(500, 1500));

    stealthLogger.log('human_simulation', {
      type: 'scroll',
      totalAmount: amount,
      steps: stepCount,
      postPause,
    });

    return { scrollSteps, postPause };
  }

  shouldIdle(): IdleResult {
    const idle = Math.random() < 0.10;
    const duration = idle ? Math.round(rand(3000, 8000)) : 0;

    if (idle) {
      stealthLogger.log('human_simulation', {
        type: 'idle_pause',
        duration,
      });
    }

    return { idle, duration };
  }

  getResponseDelay(): number {
    const delay = Math.round(rand(500, 2000));

    stealthLogger.log('human_simulation', {
      type: 'response_delay',
      delay,
    });

    return delay;
  }

  generateInteractionPlan(actions: string[]): InteractionStep[] {
    const plan: InteractionStep[] = [];

    for (const action of actions) {
      const idle = this.shouldIdle();
      const responseDelay = this.getResponseDelay();
      let details: any;

      if (action.startsWith('type:')) {
        details = { typing: this.simulateTyping(action.slice(5)) };
      } else if (action.startsWith('click:')) {
        const [xStr, yStr] = action.slice(6).split(',');
        details = { click: this.simulateClick(parseFloat(xStr), parseFloat(yStr)) };
      } else if (action.startsWith('scroll:')) {
        details = { scroll: this.simulateScroll(parseFloat(action.slice(7))) };
      } else if (action.startsWith('move:')) {
        const [x1, y1, x2, y2] = action.slice(5).split(',').map(Number);
        details = { mouseMove: this.simulateMouseMove(x1, y1, x2, y2) };
      } else {
        details = { raw: action };
      }

      plan.push({ action, idle, responseDelay, details });
    }

    stealthLogger.log('human_simulation', {
      type: 'interaction_plan',
      actionCount: actions.length,
      idlePauses: plan.filter(s => s.idle?.idle).length,
    });

    return plan;
  }
}

export const humanSimulator = new AgentUIInteractor();
