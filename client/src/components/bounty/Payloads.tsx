import { useState, useEffect } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Plus, Copy, Trash2, X, Search, Code2, Check } from 'lucide-react';
import { csrfFetch } from '@/services/api';

interface Payload {
  id: string;
  name: string;
  category: string;
  payload: string;
  description: string;
  tags: string[];
  usageCount?: number;
  createdAt?: string;
}

const CATEGORIES = ['All', 'XSS', 'SQLi', 'RCE', 'LFI', 'SSRF', 'XXE', 'CSRF', 'Auth Bypass', 'IDOR'];

function getCategoryColor(category: string): string {
  switch (category.toLowerCase()) {
    case 'xss': return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'sqli': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    case 'rce': return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
    case 'lfi': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'ssrf': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'xxe': return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
    case 'csrf': return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'auth bypass': return 'bg-pink-500/20 text-pink-400 border-pink-500/30';
    case 'idor': return 'bg-teal-500/20 text-teal-400 border-teal-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
}

export function Payloads() {
  const [payloads, setPayloads] = useState<Payload[]>([]);
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    category: 'XSS',
    payload: '',
    description: '',
    tags: '',
  });

  useEffect(() => {
    fetchPayloads();
  }, [selectedCategory, searchQuery]);

  const fetchPayloads = async () => {
    try {
      const params = new URLSearchParams();
      if (selectedCategory !== 'All') params.set('category', selectedCategory);
      if (searchQuery) params.set('search', searchQuery);
      const response = await fetch(`/api/bounty/payloads?${params}`);
      const data = await response.json();
      if (data.success) {
        setPayloads(data.payloads || []);
      }
    } catch (error) {
      console.error('Failed to fetch payloads:', error);
    }
  };

  const createPayload = async () => {
    if (!formData.name || !formData.payload) return;
    try {
      const response = await csrfFetch('/api/bounty/payloads', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...formData,
          tags: formData.tags.split(',').map(t => t.trim()).filter(Boolean),
        }),
      });
      const data = await response.json();
      if (data.success) {
        setShowForm(false);
        setFormData({ name: '', category: 'XSS', payload: '', description: '', tags: '' });
        fetchPayloads();
      }
    } catch (error) {
      console.error('Failed to create payload:', error);
    }
  };

  const deletePayload = async (id: string) => {
    try {
      const response = await csrfFetch(`/api/bounty/payloads/${id}`, { method: 'DELETE' });
      const data = await response.json();
      if (data.success) {
        setDeleteConfirmId(null);
        fetchPayloads();
      }
    } catch (error) {
      console.error('Failed to delete payload:', error);
    }
  };

  const copyPayload = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (error) {
      console.error('Failed to copy:', error);
    }
  };

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] overflow-hidden">
      <ScrollArea className="flex-1">
        <div className="p-6">
          <div className="mb-6">
            <div className="flex items-center gap-3 mb-2">
              <Code2 className="w-6 h-6 text-cyan-400" />
              <h1 className="text-2xl font-bold text-gray-100">Payload Library</h1>
            </div>
            <p className="text-sm text-gray-400">Manage and organize your exploit payloads</p>
          </div>

          <Card className="bg-[#252526] border-[#3d3d3d] p-4 mb-4">
            <div className="flex items-center gap-3 mb-3">
              <div className="flex-1 relative">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                <Input
                  placeholder="Search payloads..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9 pl-10"
                  data-testid="input-search-payloads"
                />
              </div>
              <Button
                onClick={() => setShowForm(!showForm)}
                className="bg-cyan-600 hover:bg-cyan-700 text-white h-9"
                data-testid="button-add-payload"
              >
                {showForm ? <X className="w-4 h-4 mr-2" /> : <Plus className="w-4 h-4 mr-2" />}
                {showForm ? 'Cancel' : 'Add Payload'}
              </Button>
            </div>
            <div className="flex flex-wrap gap-2">
              {CATEGORIES.map(cat => (
                <Button
                  key={cat}
                  variant={selectedCategory === cat ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setSelectedCategory(cat)}
                  className={selectedCategory === cat
                    ? 'bg-cyan-600 hover:bg-cyan-700 text-white h-7 text-xs'
                    : 'bg-[#1e1e1e] border-[#3d3d3d] text-gray-400 hover:text-gray-200 hover:bg-[#333] h-7 text-xs'
                  }
                  data-testid={`button-category-${cat.toLowerCase().replace(' ', '-')}`}
                >
                  {cat}
                </Button>
              ))}
            </div>
          </Card>

          {showForm && (
            <Card className="bg-[#252526] border-[#3d3d3d] p-6 mb-4">
              <h3 className="text-sm font-semibold text-gray-200 mb-4">Add New Payload</h3>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-xs text-gray-400 mb-2">Name</Label>
                    <Input
                      placeholder="Payload name..."
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-10"
                      data-testid="input-payload-name"
                    />
                  </div>
                  <div>
                    <Label className="text-xs text-gray-400 mb-2">Category</Label>
                    <Select value={formData.category} onValueChange={(v) => setFormData({ ...formData, category: v })}>
                      <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-10" data-testid="select-payload-category">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {CATEGORIES.filter(c => c !== 'All').map(c => (
                          <SelectItem key={c} value={c}>{c}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div>
                  <Label className="text-xs text-gray-400 mb-2">Payload</Label>
                  <Textarea
                    placeholder="Enter payload code..."
                    value={formData.payload}
                    onChange={(e) => setFormData({ ...formData, payload: e.target.value })}
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 min-h-[100px] font-mono text-sm"
                    data-testid="input-payload-code"
                  />
                </div>
                <div>
                  <Label className="text-xs text-gray-400 mb-2">Description</Label>
                  <Input
                    placeholder="Brief description..."
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-10"
                    data-testid="input-payload-description"
                  />
                </div>
                <div>
                  <Label className="text-xs text-gray-400 mb-2">Tags (comma-separated)</Label>
                  <Input
                    placeholder="reflected, stored, dom..."
                    value={formData.tags}
                    onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-10"
                    data-testid="input-payload-tags"
                  />
                </div>
                <Button
                  onClick={createPayload}
                  disabled={!formData.name || !formData.payload}
                  className="w-full bg-cyan-600 hover:bg-cyan-700 text-white h-10"
                  data-testid="button-submit-payload"
                >
                  <Plus className="w-4 h-4 mr-2" />
                  Add Payload
                </Button>
              </div>
            </Card>
          )}

          <div className="space-y-3">
            {payloads.length === 0 ? (
              <div className="text-center py-16 text-gray-500 text-sm" data-testid="text-no-payloads">
                No payloads found. Add your first payload above.
              </div>
            ) : (
              payloads.map(pl => (
                <Card
                  key={pl.id}
                  className="bg-[#252526] border-[#3d3d3d] p-4"
                  data-testid={`card-payload-${pl.id}`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <h4 className="font-semibold text-gray-200">{pl.name}</h4>
                      <Badge className={getCategoryColor(pl.category)}>{pl.category}</Badge>
                      {pl.usageCount !== undefined && (
                        <span className="text-xs text-gray-500" data-testid={`text-usage-${pl.id}`}>
                          Used {pl.usageCount}x
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyPayload(pl.id, pl.payload)}
                        className={`h-8 px-2 text-xs ${copiedId === pl.id ? 'text-green-400' : 'text-gray-400 hover:text-cyan-400'}`}
                        data-testid={`button-copy-${pl.id}`}
                      >
                        {copiedId === pl.id ? (
                          <><Check className="w-4 h-4 mr-1" />Copied</>
                        ) : (
                          <><Copy className="w-4 h-4 mr-1" />Copy</>
                        )}
                      </Button>
                      {deleteConfirmId === pl.id ? (
                        <div className="flex items-center gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => deletePayload(pl.id)}
                            className="text-red-400 hover:text-red-300 h-8 px-2 text-xs"
                            data-testid={`button-confirm-delete-${pl.id}`}
                          >
                            Confirm
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setDeleteConfirmId(null)}
                            className="text-gray-400 hover:text-gray-200 h-8 w-8 p-0"
                            data-testid={`button-cancel-delete-${pl.id}`}
                          >
                            <X className="w-4 h-4" />
                          </Button>
                        </div>
                      ) : (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setDeleteConfirmId(pl.id)}
                          className="text-gray-400 hover:text-red-400 h-8 w-8 p-0"
                          data-testid={`button-delete-${pl.id}`}
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      )}
                    </div>
                  </div>

                  <div className="bg-[#1e1e1e] border border-[#3d3d3d] rounded p-3 mb-2 overflow-x-auto">
                    <pre className="text-sm font-mono text-cyan-300 whitespace-pre-wrap break-all" data-testid={`text-payload-code-${pl.id}`}>
                      {pl.payload}
                    </pre>
                  </div>

                  {pl.description && (
                    <p className="text-xs text-gray-400 mb-2">{pl.description}</p>
                  )}

                  {pl.tags && pl.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {pl.tags.map((tag, i) => (
                        <Badge
                          key={i}
                          variant="outline"
                          className="text-[10px] text-gray-400 border-gray-600 h-5"
                        >
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  )}
                </Card>
              ))
            )}
          </div>
        </div>
      </ScrollArea>
    </div>
  );
}