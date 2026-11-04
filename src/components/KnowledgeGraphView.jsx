import React, { useState } from 'react';
import { 
  Share2, 
  Users, 
  Laptop, 
  Server, 
  Globe, 
  AlertTriangle, 
  Info, 
  ShieldAlert 
} from 'lucide-react';

export default function KnowledgeGraphView({ graphData, onSelectEntity }) {
  const [selectedNode, setSelectedNode] = useState(null);

  const getNodeColor = (node) => {
    if (node.status === 'compromised') return '#f43f5e';
    if (node.status === 'suspicious') return '#f97316';
    
    switch (node.type) {
      case 'USER': return '#3b82f6';
      case 'DEVICE': return '#8b5cf6';
      case 'APPLICATION': return '#10b981';
      case 'NETWORK_IP': return '#f59e0b';
      default: return '#00f0ff';
    }
  };

  const getNodeIcon = (type) => {
    switch (type) {
      case 'USER': return <Users size={16} />;
      case 'DEVICE': return <Laptop size={16} />;
      case 'APPLICATION': return <Server size={16} />;
      case 'NETWORK_IP': return <Globe size={16} />;
      default: return <Share2 size={16} />;
    }
  };

  // Fixed visual layout coordinates for nodes
  const layoutCoords = {
    "usr_1": { x: 180, y: 140 },
    "usr_2": { x: 180, y: 260 },
    "usr_3": { x: 180, y: 380 },
    "usr_4": { x: 180, y: 480 },

    "dev_mac_01": { x: 400, y: 120 },
    "dev_win_02": { x: 400, y: 240 },
    "dev_lin_03": { x: 400, y: 360 },
    "dev_iphone_04": { x: 400, y: 480 },

    "app_k8s": { x: 680, y: 120 },
    "app_fin_db": { x: 680, y: 240 },
    "app_slack": { x: 680, y: 360 },
    "app_vault": { x: 680, y: 480 },

    "185.220.101.45": { x: 920, y: 150 },
    "91.218.114.12": { x: 920, y: 300 },
    "45.142.120.9": { x: 920, y: 450 }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Header Info */}
      <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Share2 size={20} style={{ color: 'var(--accent-cyan)' }} /> Incident Correlation Knowledge Graph
          </h2>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            Directed entity correlation linking Users, Devices, Sessions, Applications, and Network Infrastructure to reconstruct breach topology.
          </p>
        </div>

        {/* Legend */}
        <div style={{ display: 'flex', gap: '1rem', background: 'rgba(0,0,0,0.3)', padding: '0.5rem 0.85rem', borderRadius: '8px', border: '1px solid var(--border-subtle)', fontSize: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#3b82f6' }}></span> User
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#8b5cf6' }}></span> Device
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#10b981' }}></span> Application
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#f59e0b' }}></span> Network IP
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#f43f5e' }}></span> Compromised
          </div>
        </div>
      </div>

      {/* Main Interactive Graph Canvas */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedNode ? '1fr 340px' : '1fr', gap: '1.5rem' }}>
        
        <div className="graph-container">
          <svg style={{ width: '100%', height: '100%', cursor: 'grab' }}>
            
            {/* Draw Relationship Links */}
            {graphData.links.map((link, idx) => {
              const srcCoord = layoutCoords[link.source] || { x: 200 + (idx * 40) % 600, y: 150 + (idx * 60) % 300 };
              const tgtCoord = layoutCoords[link.target] || { x: 400 + (idx * 50) % 500, y: 200 + (idx * 70) % 300 };
              
              const isCritical = link.severity === 'critical' || link.severity === 'high';

              return (
                <g key={idx}>
                  <line
                    x1={srcCoord.x}
                    y1={srcCoord.y}
                    x2={tgtCoord.x}
                    y2={tgtCoord.y}
                    stroke={isCritical ? '#f43f5e' : 'rgba(255, 255, 255, 0.15)'}
                    strokeWidth={isCritical ? 2.5 : 1}
                    strokeDasharray={isCritical ? '4,4' : 'none'}
                  />
                  {isCritical && (
                    <circle
                      r={3}
                      fill="#f43f5e"
                    >
                      <animateMotion
                        path={`M ${srcCoord.x} ${srcCoord.y} L ${tgtCoord.x} ${tgtCoord.y}`}
                        dur="3s"
                        repeatCount="indefinite"
                      />
                    </circle>
                  )}
                </g>
              );
            })}

            {/* Draw Graph Nodes */}
            {graphData.nodes.map((node) => {
              const coord = layoutCoords[node.id] || { x: 300, y: 250 };
              const color = getNodeColor(node);
              const isSelected = selectedNode && selectedNode.id === node.id;

              return (
                <g 
                  key={node.id} 
                  transform={`translate(${coord.x}, ${coord.y})`}
                  onClick={() => setSelectedNode(node)}
                  style={{ cursor: 'pointer' }}
                >
                  {/* Halo pulse if compromised */}
                  {node.status === 'compromised' && (
                    <circle r={32} fill="none" stroke="#f43f5e" strokeWidth={1.5} opacity={0.6} className="animate-pulse-glow" />
                  )}

                  {/* Node Circle */}
                  <circle
                    r={isSelected ? 26 : 22}
                    fill="var(--bg-secondary)"
                    stroke={color}
                    strokeWidth={isSelected ? 3 : 2}
                  />

                  {/* Icon label */}
                  <foreignObject x={-10} y={-10} width={20} height={20} style={{ pointerEvents: 'none' }}>
                    <div style={{ color: color, display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                      {getNodeIcon(node.type)}
                    </div>
                  </foreignObject>

                  {/* Label Text */}
                  <text
                    y={36}
                    textAnchor="middle"
                    fill="var(--text-primary)"
                    fontSize="11"
                    fontWeight="600"
                  >
                    {node.label}
                  </text>
                  <text
                    y={48}
                    textAnchor="middle"
                    fill="var(--text-muted)"
                    fontSize="9"
                    className="font-mono"
                  >
                    {node.subtext}
                  </text>
                </g>
              );
            })}

          </svg>
        </div>

        {/* Node Inspection Sidebar */}
        {selectedNode && (
          <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                {getNodeIcon(selectedNode.type)} Node Inspector
              </h3>
              <button onClick={() => setSelectedNode(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '1.2rem' }}>
                ×
              </button>
            </div>

            <div style={{ background: 'rgba(0,0,0,0.3)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.85rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Entity Name:</span>
                <span style={{ fontWeight: 600 }}>{selectedNode.label}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Entity Type:</span>
                <span className="font-mono">{selectedNode.type}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Compromise Status:</span>
                <span className={`badge badge-${selectedNode.status === 'compromised' ? 'critical' : selectedNode.status === 'suspicious' ? 'high' : 'low'}`}>
                  {selectedNode.status}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Calculated Entity Risk:</span>
                <span className="font-mono" style={{ color: getNodeColor(selectedNode), fontWeight: 700 }}>
                  {selectedNode.risk}/100
                </span>
              </div>
            </div>

            {/* Connected Neighbors List */}
            <div>
              <h4 style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                Correlated Graph Links:
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', fontSize: '0.8rem' }}>
                {graphData.links.filter(l => l.source === selectedNode.id || l.target === selectedNode.id).map((link, idx) => (
                  <div key={idx} style={{ background: 'rgba(255,255,255,0.03)', padding: '0.5rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ color: 'var(--text-primary)' }}>
                      {link.source === selectedNode.id ? `➔ ${link.target}` : `⬅ ${link.source}`}
                    </span>
                    <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)' }}>
                      {link.relation}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

      </div>

    </div>
  );
}
