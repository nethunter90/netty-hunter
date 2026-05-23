import { useState, useEffect } from 'react';
import { csrfFetch } from '@/services/api';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Globe, ArrowRight, Code, Link, FormInput, Camera, AlertTriangle } from 'lucide-react';

interface BrowserStatus {
  available: boolean;
  message?: string;
}

interface PageInfo {
  url: string;
  title?: string;
  statusCode?: number;
  content?: string;
  links?: string[];
  forms?: any[];
}

export function BrowserView() {
  const [url, setUrl] = useState('');
  const [status, setStatus] = useState<BrowserStatus>({ available: false });
  const [pageInfo, setPageInfo] = useState<PageInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [viewMode, setViewMode] = useState<'info' | 'source' | 'links' | 'forms'>('info');
  const [sourceContent, setSourceContent] = useState('');
  const [linksData, setLinksData] = useState<string[]>([]);
  const [formsData, setFormsData] = useState<any[]>([]);

  useEffect(() => {
    checkStatus();
    const interval = setInterval(checkStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const checkStatus = async () => {
    try {
      const response = await fetch('/api/bounty/browser/status');
      const data = await response.json();
      setStatus({ available: data.available ?? false, message: data.message });
    } catch {
      setStatus({ available: false, message: 'Browser service unavailable' });
    }
  };

  const navigate = async () => {
    if (!url.trim()) return;
    setLoading(true);
    try {
      const targetUrl = url.startsWith('http') ? url : `https://${url}`;
      const response = await csrfFetch('/api/bounty/browser/navigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl }),
      });
      const data = await response.json();
      setPageInfo(data);
      setViewMode('info');
    } catch (error) {
      console.error('Navigation failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const viewSource = async () => {
    if (!pageInfo?.url) return;
    try {
      const response = await csrfFetch('/api/bounty/browser/dom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: pageInfo.url }),
      });
      const data = await response.json();
      setSourceContent(data.source || data.content || '');
      setViewMode('source');
    } catch (error) {
      console.error('Failed to get source:', error);
    }
  };

  const viewLinks = async () => {
    if (!pageInfo?.url) return;
    try {
      const response = await csrfFetch('/api/bounty/browser/links', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: pageInfo.url }),
      });
      const data = await response.json();
      setLinksData(data.links || []);
      setViewMode('links');
    } catch (error) {
      console.error('Failed to get links:', error);
    }
  };

  const viewForms = async () => {
    if (!pageInfo?.url) return;
    try {
      const response = await csrfFetch('/api/bounty/browser/forms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: pageInfo.url }),
      });
      const data = await response.json();
      setFormsData(data.forms || []);
      setViewMode('forms');
    } catch (error) {
      console.error('Failed to get forms:', error);
    }
  };

  const takeScreenshot = async () => {
    if (!pageInfo?.url) return;
    try {
      await csrfFetch('/api/bounty/browser/screenshot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: pageInfo.url }),
      });
    } catch (error) {
      console.error('Screenshot failed:', error);
    }
  };

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] p-6">
      <div className="mb-4">
        <div className="flex items-center gap-3 mb-2">
          <Globe className="w-6 h-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-gray-100">Browser</h1>
        </div>
        <p className="text-sm text-gray-400">Embedded browser for web testing and reconnaissance</p>
      </div>

      {!status.available && (
        <Card className="bg-orange-500/10 border-orange-500/30 p-4 mb-4">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-orange-400 flex-shrink-0" />
            <div>
              <p className="text-sm font-medium text-orange-400">Browser Not Available</p>
              <p className="text-xs text-gray-400 mt-1">
                {status.message || 'Install Puppeteer to enable browser functionality: npm install puppeteer'}
              </p>
            </div>
          </div>
        </Card>
      )}

      <Card className="bg-[#252526] border-[#3d3d3d] p-3 mb-4">
        <div className="flex gap-2">
          <Input
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && navigate()}
            className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9 font-mono text-sm"
            data-testid="input-browser-url"
          />
          <Button
            onClick={navigate}
            disabled={loading || !url.trim()}
            className="bg-cyan-600 hover:bg-cyan-700 text-white h-9 px-4"
            data-testid="button-navigate"
          >
            <ArrowRight className="w-4 h-4 mr-1" />
            {loading ? 'Loading...' : 'Go'}
          </Button>
        </div>
      </Card>

      {pageInfo && (
        <Card className="bg-[#252526] border-[#3d3d3d] p-3 mb-4">
          <div className="flex flex-wrap gap-2">
            <Button
              onClick={viewSource}
              variant="outline"
              size="sm"
              className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-300 hover:bg-[#333]"
              data-testid="button-view-source"
            >
              <Code className="w-3 h-3 mr-1" /> View Source
            </Button>
            <Button
              onClick={viewLinks}
              variant="outline"
              size="sm"
              className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-300 hover:bg-[#333]"
              data-testid="button-view-links"
            >
              <Link className="w-3 h-3 mr-1" /> Links
            </Button>
            <Button
              onClick={viewForms}
              variant="outline"
              size="sm"
              className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-300 hover:bg-[#333]"
              data-testid="button-view-forms"
            >
              <FormInput className="w-3 h-3 mr-1" /> Forms
            </Button>
            <Button
              onClick={takeScreenshot}
              variant="outline"
              size="sm"
              className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-300 hover:bg-[#333]"
              data-testid="button-screenshot"
            >
              <Camera className="w-3 h-3 mr-1" /> Screenshot
            </Button>
          </div>
        </Card>
      )}

      <div className="flex-1 min-h-0">
        {!pageInfo ? (
          <div className="h-full flex items-center justify-center text-gray-500 text-sm" data-testid="text-no-page">
            No page loaded. Enter a URL and click Go.
          </div>
        ) : (
          <ScrollArea className="h-full">
            <div className="pr-2">
              {viewMode === 'info' && (
                <Card className="bg-[#252526] border-[#3d3d3d] p-4">
                  <div className="space-y-3">
                    <div>
                      <span className="text-xs text-gray-400">URL</span>
                      <p className="text-sm text-cyan-400 font-mono break-all">{pageInfo.url}</p>
                    </div>
                    {pageInfo.title && (
                      <div>
                        <span className="text-xs text-gray-400">Title</span>
                        <p className="text-sm text-gray-200">{pageInfo.title}</p>
                      </div>
                    )}
                    {pageInfo.statusCode && (
                      <div>
                        <span className="text-xs text-gray-400">Status</span>
                        <Badge className={pageInfo.statusCode < 400 ? 'bg-green-500/20 text-green-400 border-green-500/30' : 'bg-red-500/20 text-red-400 border-red-500/30'}>
                          {pageInfo.statusCode}
                        </Badge>
                      </div>
                    )}
                  </div>
                </Card>
              )}
              {viewMode === 'source' && (
                <pre className="bg-[#252526] border border-[#3d3d3d] rounded p-4 text-xs text-cyan-400 font-mono whitespace-pre-wrap break-all">
                  {sourceContent || 'No source available'}
                </pre>
              )}
              {viewMode === 'links' && (
                <div className="space-y-1">
                  {linksData.length === 0 ? (
                    <p className="text-sm text-gray-500">No links found</p>
                  ) : (
                    linksData.map((link, idx) => (
                      <div key={idx} className="bg-[#252526] border border-[#3d3d3d] rounded px-3 py-2 text-xs text-cyan-400 font-mono break-all">
                        {link}
                      </div>
                    ))
                  )}
                </div>
              )}
              {viewMode === 'forms' && (
                <div className="space-y-2">
                  {formsData.length === 0 ? (
                    <p className="text-sm text-gray-500">No forms found</p>
                  ) : (
                    formsData.map((form, idx) => (
                      <Card key={idx} className="bg-[#252526] border-[#3d3d3d] p-3">
                        <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap">
                          {JSON.stringify(form, null, 2)}
                        </pre>
                      </Card>
                    ))
                  )}
                </div>
              )}
            </div>
          </ScrollArea>
        )}
      </div>

      <div className="mt-3 flex items-center gap-2 text-xs text-gray-500">
        <div className={`w-2 h-2 rounded-full ${status.available ? 'bg-green-400' : 'bg-red-400'}`} />
        {status.available ? 'Browser ready' : 'Browser unavailable'}
      </div>
    </div>
  );
}
