import { useState, useRef, useEffect } from 'react';
import { api } from '../lib/api';
import { Spinner } from './ui';

function Message({ msg }) {
  const isUser = msg.role === 'user';
  return (
    <div className={`flex gap-2.5 ${isUser ? 'flex-row-reverse' : 'flex-row'}`}>
      {/* Avatar */}
      <div className={`w-6 h-6 rounded-full shrink-0 flex items-center justify-center text-[10px] font-bold mt-0.5 shadow-2xs
        ${isUser ? 'bg-slate-900 text-white' : 'bg-emerald-600 text-white'}`}>
        {isUser ? 'U' : 'AI'}
      </div>

      {/* Bubble */}
      <div className={`max-w-[82%] px-3.5 py-2.5 rounded-xl text-xs leading-relaxed shadow-2xs
        ${isUser
          ? 'bg-slate-900 text-white rounded-tr-xs'
          : 'bg-slate-100 border border-slate-200/80 text-slate-800 rounded-tl-xs'}`}>
        {msg.streaming
          ? <span>{msg.content}<span className="inline-block w-1.5 h-3 bg-emerald-600 ml-0.5 animate-pulse" /></span>
          : <pre className="whitespace-pre-wrap font-sans text-xs">{msg.content}</pre>
        }
      </div>
    </div>
  );
}

const STARTERS = [
  'Explain CVE-2021-44228 (Log4Shell)',
  'What is a typosquatting attack?',
  'How does EPSS scoring work?',
  'What is SLSA Level 2?',
];

export default function AiChatbot({ repoId }) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [apiAvailable, setApiAvailable] = useState(null); // null=unknown, true/false
  const [llmInfo, setLlmInfo] = useState(null);
  const bottomRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    if (open && inputRef.current) inputRef.current.focus();
    if (open && apiAvailable === null) checkAvailability();
  }, [open]);

  async function checkAvailability() {
    try {
      const info = await api.aiModelInfo();
      setLlmInfo(info?.llm || null);
      setApiAvailable(true);
    } catch {
      setApiAvailable(false);
    }
  }

  async function send(text) {
    const content = (text || input).trim();
    if (!content || loading) return;
    setInput('');

    const userMsg = { role: 'user', content };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setLoading(true);

    const assistantIdx = newMessages.length;
    setMessages(prev => [...prev, { role: 'assistant', content: '', streaming: true }]);

    try {
      const { reply } = await api.aiChat(
        newMessages.map(m => ({ role: m.role, content: m.content })),
        repoId
      );
      setMessages(prev =>
        prev.map((m, i) => i === assistantIdx ? { role: 'assistant', content: reply, streaming: false } : m)
      );
    } catch (err) {
      const errMsg = err.message.includes('AI features disabled')
        ? 'AI features need GEMINI_API_KEY set in backend .env.'
        : `Error: ${err.message}`;
      setMessages(prev =>
        prev.map((m, i) => i === assistantIdx ? { role: 'assistant', content: errMsg, streaming: false } : m)
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      {/* Floating trigger button — Obsidian Slate (NO BLUE) */}
      <button
        onClick={() => setOpen(o => !o)}
        className="fixed bottom-6 right-6 z-50 w-12 h-12 rounded-full bg-slate-900 text-white flex items-center justify-center shadow-lg hover:bg-slate-800 transition-all duration-200 cursor-pointer hover:scale-105 active:scale-95"
        title="AI Security Assistant"
        aria-label="Open AI Security Assistant"
      >
        <span className="text-lg font-bold">◈</span>
      </button>

      {/* Chat panel — Crisp White Light Theme */}
      {open && (
        <div className="fixed bottom-20 right-6 z-50 w-88 h-[500px] flex flex-col rounded-2xl overflow-hidden border border-slate-200 bg-white shadow-2xl">

          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3.5 border-b border-slate-100 bg-slate-50">
            <div className="flex items-center gap-2">
              <span className="text-slate-900 font-bold text-xs tracking-tight">◈ AI Security Assistant</span>
              {llmInfo?.model && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200 font-medium">
                  {llmInfo.model}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2.5">
              {messages.length > 0 && (
                <button onClick={() => setMessages([])} className="text-[10px] font-mono text-slate-500 hover:text-slate-800 cursor-pointer">
                  clear
                </button>
              )}
              <button onClick={() => setOpen(false)} className="text-slate-400 hover:text-slate-700 text-lg leading-none cursor-pointer">×</button>
            </div>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto px-4 py-4 space-y-3.5 bg-white">
            {messages.length === 0 && (
              <div className="space-y-2.5">
                <p className="text-[11px] font-mono text-slate-400 text-center mt-2">Ask questions about software supply chain security</p>
                {STARTERS.map(s => (
                  <button key={s} onClick={() => send(s)}
                    className="w-full text-left text-xs text-slate-700 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2.5 hover:bg-slate-100 hover:border-slate-300 transition-colors cursor-pointer font-medium">
                    {s}
                  </button>
                ))}
                {repoId && (
                  <button onClick={() => send('What are the biggest security risks in this repository?')}
                    className="w-full text-left text-xs text-emerald-800 bg-emerald-50 border border-emerald-200 rounded-lg px-3 py-2.5 hover:bg-emerald-100 transition-colors cursor-pointer font-medium">
                    ◎ Analyse this repository's risks
                  </button>
                )}
              </div>
            )}
            {messages.map((msg, i) => <Message key={i} msg={msg} />)}
            <div ref={bottomRef} />
          </div>

          {/* Input */}
          <div className="px-3.5 py-3 border-t border-slate-100 bg-slate-50">
            <div className="flex gap-2">
              <input
                ref={inputRef}
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && !e.shiftKey && (e.preventDefault(), send())}
                placeholder="Ask a security question…"
                disabled={loading}
                className="flex-1 bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-slate-900 transition-colors shadow-2xs"
              />
              <button
                onClick={() => send()}
                disabled={loading || !input.trim()}
                className="w-8 h-8 rounded-lg bg-slate-900 text-white flex items-center justify-center hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors shrink-0 shadow-2xs cursor-pointer font-bold"
              >
                {loading ? <Spinner size={12} color="#ffffff" /> : '↑'}
              </button>
            </div>
            <p className="text-[9px] text-slate-400 mt-2 text-center font-mono">
              Powered by Google Gemini{llmInfo?.model ? ` (${llmInfo.model})` : ''} · SecureChain Intelligent Assistant
            </p>
          </div>
        </div>
      )}
    </>
  );
}

