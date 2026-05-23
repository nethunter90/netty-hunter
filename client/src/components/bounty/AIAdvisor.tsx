import { useState, useEffect, useRef } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Sparkles, Send, AlertCircle, Loader2, Brain } from 'lucide-react';
import { csrfFetch } from '@/services/api';

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

interface CampaignContext {
  domain: string;
  successfulTechniques: string[];
  avgPayout: number;
  techStack: Record<string, unknown>;
  similarity: number;
}

const QUICK_PROMPTS = [
  'Suggest next steps',
  'Analyze findings',
  'Generate payloads',
  'Explain vulnerability',
];

export function AIAdvisor() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [huntContext, setHuntContext] = useState<any>(null);
  const [campaignContext, setCampaignContext] = useState<CampaignContext[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchContext();
  }, []);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const fetchCampaignContext = async (targetDomain: string) => {
    try {
      const res = await csrfFetch('/api/intelligence/campaigns/similar', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetProfile: {
            domain: targetDomain,
            industry: 'unknown',
            techStack: { language: null, framework: null, server: null, database: null, cdn: null, jsLibraries: [] },
            defensePosture: {
              wafType: null, wafStrictness: 'moderate',
              rateLimiting: { detected: false, threshold: null, resetWindow: null },
              errorVerbosity: 'standard',
              cspPolicy: { present: false, strictness: 'none', reportOnly: false },
              securityHeaders: { hsts: false, xFrameOptions: false, xContentType: false, referrerPolicy: null },
              cookieFlags: { httpOnly: false, secure: false, sameSite: null },
              authMechanisms: [], apiStyle: 'rest',
            },
          },
        }),
      });
      const data = await res.json();
      if (data.success && data.data && Array.isArray(data.data)) {
        const mapped: CampaignContext[] = data.data.slice(0, 3).map((c: any) => ({
          domain: c.profile?.target?.domain || c.domain || 'unknown',
          successfulTechniques: c.profile?.techniques
            ?.filter((t: any) => t.result === 'success')
            ?.map((t: any) => t.technique) || [],
          avgPayout: c.profile?.findings?.length > 0
            ? c.profile.findings.reduce((sum: number, f: any) => sum + (f.cvssScore || 0), 0) / c.profile.findings.length * 100
            : 0,
          techStack: c.profile?.target?.techStack || {},
          similarity: c.similarity || 0,
        }));
        setCampaignContext(mapped);
      }
    } catch {
      // Campaign context is optional enhancement
    }
  };

  const fetchContext = async () => {
    try {
      const response = await fetch('/api/bounty/hunts');
      const data = await response.json();
      if (data.success && data.hunts?.length > 0) {
        const active = data.hunts.find((h: any) => h.status === 'active');
        if (active) {
          setHuntContext(active);
          await fetchCampaignContext(active.target);
        }
      }
    } catch {
      // Context is optional
    }
  };

  const sendMessage = async (content: string) => {
    if (!content.trim() || loading) return;
    setError('');

    const userMessage: ChatMessage = { role: 'user', content: content.trim() };
    const updatedMessages = [...messages, userMessage];
    setMessages(updatedMessages);
    setInput('');
    setLoading(true);

    try {
      const enhancedContext = huntContext ? {
        huntId: huntContext.id,
        target: huntContext.target,
        currentPhase: huntContext.status,
        ...(campaignContext.length > 0 && {
          campaignIntelligence: campaignContext.map(c => ({
            domain: c.domain,
            successfulTechniques: c.successfulTechniques,
            avgPayout: c.avgPayout,
            techStack: c.techStack,
            similarity: c.similarity,
          })),
        }),
      } : undefined;

      const response = await csrfFetch('/api/bounty/advisor/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: content.trim(),
          context: enhancedContext,
        }),
      });

      const data = await response.json();

      if (data.error) {
        setError(data.error);
        if (data.message) {
          const msgContent = typeof data.message === 'string' ? data.message : data.message?.content || '';
          if (msgContent) setMessages(prev => [...prev, { role: 'assistant', content: msgContent }]);
        }
      } else {
        const msg = data.message;
        const assistantContent = typeof msg === 'string'
          ? msg
          : msg?.content || data.response || data.content || 'No response received.';
        setMessages(prev => [...prev, { role: 'assistant', content: assistantContent }]);
      }
    } catch (err) {
      setError('Failed to connect to AI service. Is Ollama running?');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] p-6">
      <div className="mb-4">
        <div className="flex items-center gap-3 mb-2">
          <Sparkles className="w-6 h-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-gray-100">AI Advisor</h1>
        </div>
        <p className="text-sm text-gray-400">AI-powered bug bounty hunting assistant</p>
      </div>

      {huntContext && (
        <Card className="bg-[#252526] border-[#3d3d3d] p-3 mb-3">
          <div className="flex items-center gap-2 text-xs flex-wrap">
            <span className="text-gray-400">Active Hunt:</span>
            <span className="text-cyan-400 font-medium">{huntContext.target}</span>
            <span className="text-gray-500">|</span>
            <span className="text-purple-400">{huntContext.goal}</span>
            {campaignContext.length > 0 && (
              <>
                <span className="text-gray-500">|</span>
                <Badge
                  variant="outline"
                  className="text-emerald-400 border-emerald-500/30 bg-emerald-500/10 text-xs py-0"
                  data-testid="badge-campaign-context"
                >
                  <Brain className="w-3 h-3 mr-1" />
                  {campaignContext.length} similar campaign{campaignContext.length !== 1 ? 's' : ''} loaded
                </Badge>
              </>
            )}
          </div>
          {campaignContext.length > 0 && (
            <div className="mt-2 space-y-1" data-testid="campaign-context-details">
              {campaignContext.map((c, idx) => (
                <div key={idx} className="flex items-center gap-2 text-xs text-gray-500 ml-2">
                  <span className="text-gray-400">{c.domain}</span>
                  {c.successfulTechniques.length > 0 && (
                    <span className="text-green-400/70">
                      {c.successfulTechniques.slice(0, 3).join(', ')}
                    </span>
                  )}
                  <span className="text-gray-600">({Math.round(c.similarity * 100)}% match)</span>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {error && (
        <Card className="bg-red-500/10 border-red-500/30 p-3 mb-3">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
            <p className="text-xs text-red-400">{error}</p>
          </div>
        </Card>
      )}

      <div className="flex gap-2 mb-3 flex-wrap">
        {QUICK_PROMPTS.map(prompt => (
          <Button
            key={prompt}
            onClick={() => sendMessage(prompt)}
            disabled={loading}
            variant="outline"
            size="sm"
            className="bg-[#252526] border-[#3d3d3d] text-gray-400 hover:bg-[#333] hover:text-cyan-400 text-xs"
            data-testid={`button-quick-${prompt.toLowerCase().replace(/\s+/g, '-')}`}
          >
            {prompt}
          </Button>
        ))}
      </div>

      <ScrollArea className="flex-1 mb-3">
        <div ref={scrollRef} className="space-y-3 pr-2">
          {messages.length === 0 ? (
            <div className="text-center py-16 text-gray-500 text-sm" data-testid="text-no-messages">
              Start a conversation with your AI hunting advisor.
              {campaignContext.length > 0
                ? ` Intelligence from ${campaignContext.length} similar campaign(s) will enhance responses.`
                : ' Use the quick prompts above or type your own question.'}
            </div>
          ) : (
            messages.map((msg, idx) => (
              <div
                key={idx}
                className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                data-testid={`message-${msg.role}-${idx}`}
              >
                <div
                  className={`max-w-[80%] rounded-lg px-4 py-3 text-sm ${
                    msg.role === 'user'
                      ? 'bg-cyan-600/20 text-cyan-100 border border-cyan-500/30'
                      : 'bg-[#252526] text-gray-300 border border-[#3d3d3d]'
                  }`}
                >
                  <pre className="whitespace-pre-wrap font-sans">{msg.content}</pre>
                </div>
              </div>
            ))
          )}
          {loading && (
            <div className="flex justify-start">
              <div className="bg-[#252526] border border-[#3d3d3d] rounded-lg px-4 py-3 flex items-center gap-2">
                <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
                <span className="text-sm text-gray-400">Thinking...</span>
              </div>
            </div>
          )}
        </div>
      </ScrollArea>

      <Card className="bg-[#252526] border-[#3d3d3d] p-3">
        <div className="flex gap-2">
          <Input
            placeholder="Ask your AI advisor..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && sendMessage(input)}
            disabled={loading}
            className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
            data-testid="input-ai-message"
          />
          <Button
            onClick={() => sendMessage(input)}
            disabled={loading || !input.trim()}
            className="bg-cyan-600 hover:bg-cyan-700 text-white h-9 px-4"
            data-testid="button-send-message"
          >
            <Send className="w-4 h-4" />
          </Button>
        </div>
      </Card>
    </div>
  );
}
