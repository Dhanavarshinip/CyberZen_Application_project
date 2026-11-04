import React, { useState } from 'react';
import { 
  Bot, 
  Send, 
  FileText, 
  Copy, 
  Check, 
  Sparkles, 
  ShieldAlert, 
  User, 
  Search, 
  HelpCircle 
} from 'lucide-react';
import { GenAiAssistant } from '../services/genAiAssistant';
import { apiClient } from '../services/apiClient';

export default function GenAiReportView({ riskScore, incidentData, telemetryLogs }) {
  const [activeSubTab, setActiveSubTab] = useState('report'); // 'report' or 'chat'
  const [copied, setCopied] = useState(false);
  const [messages, setMessages] = useState([
    {
      sender: 'bot',
      text: 'Hello, Investigator! I am your CyberThreat AI Grounded SecOps Assistant. I have correlated incoming telemetry into the Temporal Knowledge Graph and Incident Reconstructor. How can I assist your investigation today?'
    }
  ]);
  const [userInput, setUserInput] = useState('');

  const reportContent = GenAiAssistant.generateIncidentReport(riskScore, incidentData, telemetryLogs);

  const handleCopyReport = () => {
    navigator.clipboard.writeText(reportContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSendMessage = async (textToSend) => {
    const query = textToSend || userInput;
    if (!query.trim()) return;

    const newMsgs = [...messages, { sender: 'user', text: query }];
    setMessages(newMsgs);
    setUserInput('');

    // Try backend AI Investigator first
    try {
      const backendRes = await apiClient.queryInvestigator(query, incidentData?.incidentId);
      if (backendRes && backendRes.answer) {
        setMessages([...newMsgs, { sender: 'bot', text: backendRes.answer }]);
        return;
      }
    } catch (err) {
      console.warn('[Investigator UI] Using local assistant fallback:', err);
    }

    // Local deterministic fallback
    setTimeout(() => {
      const answer = GenAiAssistant.queryAssistant(query, telemetryLogs, incidentData);
      setMessages([...newMsgs, { sender: 'bot', text: answer }]);
    }, 300);
  };


  const quickPrompts = [
    "What was the initial attack vector / Patient Zero?",
    "Which external IP addresses are malicious?",
    "What is the current incident blast radius?",
    "What RL mitigations are recommended?"
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Header & Subtab Switcher */}
      <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Bot size={20} style={{ color: 'var(--accent-cyan)' }} /> Generative AI SecOps Assistant & Incident Synthesizer
          </h2>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            LLM multi-vector correlation converts technical telemetry evidence into readable reports and allows natural language querying.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', background: 'rgba(0,0,0,0.3)', padding: '0.3rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
          <button 
            onClick={() => setActiveSubTab('report')}
            style={{
              padding: '0.4rem 1rem',
              fontSize: '0.8rem',
              borderRadius: '6px',
              border: 'none',
              cursor: 'pointer',
              background: activeSubTab === 'report' ? 'var(--accent-cyan)' : 'transparent',
              color: activeSubTab === 'report' ? '#050b14' : 'var(--text-secondary)',
              fontWeight: activeSubTab === 'report' ? 700 : 500
            }}
          >
            <FileText size={14} style={{ display: 'inline', marginRight: '4px' }} /> Automated Incident Report
          </button>

          <button 
            onClick={() => setActiveSubTab('chat')}
            style={{
              padding: '0.4rem 1rem',
              fontSize: '0.8rem',
              borderRadius: '6px',
              border: 'none',
              cursor: 'pointer',
              background: activeSubTab === 'chat' ? 'var(--accent-cyan)' : 'transparent',
              color: activeSubTab === 'chat' ? '#050b14' : 'var(--text-secondary)',
              fontWeight: activeSubTab === 'chat' ? 700 : 500
            }}
          >
            <Sparkles size={14} style={{ display: 'inline', marginRight: '4px' }} /> Natural Language Query Chat
          </button>
        </div>
      </div>

      {/* Subtab 1: Automated Incident Report Builder */}
      {activeSubTab === 'report' && (
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FileText size={18} style={{ color: 'var(--accent-cyan)' }} /> Compiled SecOps Incident Synthesis Document
            </h3>
            <button onClick={handleCopyReport} className="btn-secondary" style={{ fontSize: '0.8rem' }}>
              {copied ? <><Check size={14} style={{ color: '#10b981' }} /> Report Copied!</> : <><Copy size={14} /> Copy Markdown Report</>}
            </button>
          </div>

          <div style={{
            background: 'rgba(10, 13, 20, 0.95)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '8px',
            padding: '1.5rem',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.85rem',
            lineHeight: '1.7',
            whiteSpace: 'pre-wrap',
            color: '#e2e8f0',
            maxHeight: '600px',
            overflowY: 'auto'
          }}>
            {reportContent}
          </div>
        </div>
      )}

      {/* Subtab 2: Natural Language Investigator Chatbot */}
      {activeSubTab === 'chat' && (
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem', height: '620px' }}>
          
          {/* Quick Prompt Chips */}
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Quick Prompts:</span>
            {quickPrompts.map((prompt, idx) => (
              <button
                key={idx}
                onClick={() => handleSendMessage(prompt)}
                style={{
                  background: 'rgba(0, 240, 255, 0.08)',
                  border: '1px solid rgba(0, 240, 255, 0.2)',
                  color: 'var(--accent-cyan)',
                  padding: '0.25rem 0.65rem',
                  borderRadius: '15px',
                  fontSize: '0.75rem',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease'
                }}
              >
                {prompt}
              </button>
            ))}
          </div>

          {/* Chat Messages Log */}
          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '1rem', paddingRight: '0.5rem' }}>
            {messages.map((msg, idx) => (
              <div 
                key={idx} 
                style={{
                  alignSelf: msg.sender === 'user' ? 'flex-end' : 'flex-start',
                  maxWidth: '80%',
                  background: msg.sender === 'user' ? 'linear-gradient(135deg, rgba(0, 240, 255, 0.2) 0%, rgba(0, 168, 255, 0.2) 100%)' : 'rgba(24, 32, 53, 0.8)',
                  border: msg.sender === 'user' ? '1px solid rgba(0, 240, 255, 0.4)' : '1px solid var(--border-subtle)',
                  padding: '0.85rem 1.1rem',
                  borderRadius: msg.sender === 'user' ? '14px 14px 2px 14px' : '14px 14px 14px 2px',
                  fontSize: '0.85rem',
                  lineHeight: '1.6',
                  color: 'var(--text-primary)'
                }}
              >
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.25rem', fontWeight: 600 }}>
                  {msg.sender === 'user' ? 'SecOps Investigator' : 'Aegis GenAI Assistant'}
                </div>
                <div>{msg.text}</div>
              </div>
            ))}
          </div>

          {/* Input Bar */}
          <div style={{ display: 'flex', gap: '0.75rem', marginTop: 'auto' }}>
            <input
              type="text"
              placeholder="Ask natural language questions about the incident, patient zero, or rogue IPs..."
              value={userInput}
              onChange={(e) => setUserInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
              style={{
                flex: 1,
                padding: '0.75rem 1rem',
                borderRadius: '8px',
                border: '1px solid var(--border-subtle)',
                background: 'rgba(10, 13, 20, 0.8)',
                color: 'var(--text-primary)',
                fontSize: '0.85rem',
                outline: 'none'
              }}
            />
            <button onClick={() => handleSendMessage()} className="btn-primary" style={{ fontSize: '0.85rem' }}>
              <Send size={16} /> Send Query
            </button>
          </div>

        </div>
      )}

    </div>
  );
}
