import React, { useState } from 'react';
import { Bot, Send, Sparkles } from 'lucide-react';

export default function AiAnalystPage() {
  const [messages, setMessages] = useState([
    { sender: 'bot', text: 'Hello! I am your DigitalGuard AI Security Assistant. Ask me natural language questions about your security status, recent anomalies, or recommended mitigation policies.' }
  ]);
  const [input, setInput] = useState('');

  const handleSend = () => {
    if (!input.trim()) return;
    const newMsgs = [...messages, { sender: 'user', text: input }];
    setMessages(newMsgs);
    setInput('');

    setTimeout(() => {
      setMessages([...newMsgs, { 
        sender: 'bot', 
        text: `DigitalGuard AI Analysis: Processing your query "${input}". All 14 connected devices are currently protected. The Tor Exit Node anomaly (185.220.101.45) detected at 11:20 AM was successfully contained with zero data loss.` 
      }]);
    }, 400);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', height: 'calc(100vh - 120px)' }}>
      <div className="glass-panel" style={{ padding: '1.25rem' }}>
        <h2 style={{ fontSize: '1.15rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Bot size={20} style={{ color: 'var(--accent-cyan)' }} /> AI Security Analyst Assistant
        </h2>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Natural language investigator assistant for instant incident synthesis and security querying</p>
      </div>

      <div className="glass-panel" style={{ flex: 1, padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem', overflow: 'hidden' }}>
        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {messages.map((m, i) => (
            <div key={i} style={{
              alignSelf: m.sender === 'user' ? 'flex-end' : 'flex-start',
              maxWidth: '75%',
              background: m.sender === 'user' ? 'rgba(0, 240, 255, 0.15)' : 'rgba(255, 255, 255, 0.04)',
              border: m.sender === 'user' ? '1px solid var(--accent-cyan)' : '1px solid var(--border-subtle)',
              padding: '0.85rem 1.1rem',
              borderRadius: '12px',
              fontSize: '0.85rem',
              lineHeight: '1.6'
            }}>
              {m.text}
            </div>
          ))}
        </div>

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <input
            type="text"
            placeholder="Ask AI Analyst a question..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            className="input-field"
            style={{ flex: 1 }}
          />
          <button onClick={handleSend} className="btn-cyan">
            <Send size={16} /> Send
          </button>
        </div>
      </div>
    </div>
  );
}
