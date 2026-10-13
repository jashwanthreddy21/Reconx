import React, { useState, useMemo, useRef, useEffect } from 'react';
import {
  Asset,
  DnsRecord,
  WebEndpoint,
  NetworkService,
  AssetType
} from '../../types';
import {
  Globe,
  Server,
  Layers,
  Cpu,
  Shield,
  Search,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Download,
  Filter,
  Info,
  X
} from 'lucide-react';

interface GraphNode {
  id: string;
  name: string;
  type: AssetType;
  x: number;
  y: number;
  vx?: number;
  vy?: number;
  source: string;
  status?: string;
  details: Record<string, any>;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: 'SUBDOMAIN_OF' | 'RESOLVES_TO' | 'SERVES' | 'EXPOSES' | 'USES_TECHNOLOGY';
}

interface Props {
  assets: Asset[];
  dnsRecords: DnsRecord[];
  endpoints: WebEndpoint[];
  services: NetworkService[];
}

export const AttackSurfaceGraph: React.FC<Props> = ({
  assets,
  dnsRecords,
  endpoints,
  services,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  // Filters
  const [selectedTypes, setSelectedTypes] = useState<Record<AssetType, boolean>>({
    root_domain: true,
    subdomain: true,
    ip_address: true,
    endpoint: true,
    service: true,
    technology: true,
  });

  // Construct Nodes and Edges
  const { nodes, edges } = useMemo(() => {
    const rawNodes: GraphNode[] = [];
    const rawEdges: GraphEdge[] = [];
    const nodeMap = new Map<string, GraphNode>();

    // 1. Root domains
    const roots = assets.filter((a) => a.assetType === 'root_domain');
    const subdomains = assets.filter((a) => a.assetType === 'subdomain');
    const ips = assets.filter((a) => a.assetType === 'ip_address');
    const eps = assets.filter((a) => a.assetType === 'endpoint');
    const svcs = assets.filter((a) => a.assetType === 'service');
    const techs = assets.filter((a) => a.assetType === 'technology');

    // Layout rings: concentric orbital radial layout for attack surface visualization
    const centerX = 500;
    const centerY = 380;

    roots.forEach((r, i) => {
      const node: GraphNode = {
        id: r.id,
        name: r.canonicalName,
        type: 'root_domain',
        x: centerX + (i - (roots.length - 1) / 2) * 120,
        y: centerY,
        source: r.discoverySource,
        status: r.status,
        details: r.metadata || {},
      };
      rawNodes.push(node);
      nodeMap.set(node.id, node);
    });

    // Subdomains ring (Radius 180)
    subdomains.forEach((s, i) => {
      const angle = (i / Math.max(1, subdomains.length)) * 2 * Math.PI;
      const radius = 180;
      const node: GraphNode = {
        id: s.id,
        name: s.canonicalName,
        type: 'subdomain',
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
        source: s.discoverySource,
        status: s.status,
        details: s.metadata || {},
      };
      rawNodes.push(node);
      nodeMap.set(node.id, node);

      // Connect to root
      const rootParent = roots[0];
      if (rootParent) {
        rawEdges.push({
          id: `edge_sub_${s.id}`,
          source: s.id,
          target: rootParent.id,
          type: 'SUBDOMAIN_OF',
        });
      }
    });

    // IPs ring (Radius 300)
    ips.forEach((ip, i) => {
      const angle = (i / Math.max(1, ips.length)) * 2 * Math.PI + 0.3;
      const radius = 300;
      const node: GraphNode = {
        id: ip.id,
        name: ip.canonicalName,
        type: 'ip_address',
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
        source: ip.discoverySource,
        status: ip.status,
        details: ip.metadata || {},
      };
      rawNodes.push(node);
      nodeMap.set(node.id, node);

      // Connect IP to relevant domain/subdomain based on DNS
      const dnsA = dnsRecords.find((d) => d.recordType === 'A' && d.value === ip.canonicalName);
      if (dnsA) {
        const matchingDomain = rawNodes.find((n) => n.name === dnsA.hostname);
        if (matchingDomain) {
          rawEdges.push({
            id: `edge_res_${matchingDomain.id}_${ip.id}`,
            source: matchingDomain.id,
            target: ip.id,
            type: 'RESOLVES_TO',
          });
        }
      } else if (subdomains[0]) {
        rawEdges.push({
          id: `edge_res_def_${ip.id}`,
          source: subdomains[0].id,
          target: ip.id,
          type: 'RESOLVES_TO',
        });
      }
    });

    // Endpoints ring (Radius 400)
    eps.slice(0, 8).forEach((ep, i) => {
      const angle = (i / Math.max(1, Math.min(8, eps.length))) * 2 * Math.PI + 0.6;
      const radius = 390;
      const node: GraphNode = {
        id: ep.id,
        name: ep.canonicalName,
        type: 'endpoint',
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
        source: ep.discoverySource,
        status: ep.status,
        details: ep.metadata || {},
      };
      rawNodes.push(node);
      nodeMap.set(node.id, node);

      // Connect to parent hostname or root
      const parent = rawNodes.find((n) => ep.canonicalName.includes(n.name) && n.type !== 'endpoint') || roots[0];
      if (parent) {
        rawEdges.push({
          id: `edge_serv_${node.id}_${parent.id}`,
          source: parent.id,
          target: node.id,
          type: 'SERVES',
        });
      }
    });

    // Services (Radius 470)
    svcs.slice(0, 8).forEach((svc, i) => {
      const angle = (i / Math.max(1, Math.min(8, svcs.length))) * 2 * Math.PI + 0.9;
      const radius = 460;
      const node: GraphNode = {
        id: svc.id,
        name: svc.canonicalName,
        type: 'service',
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
        source: svc.discoverySource,
        status: svc.status,
        details: svc.metadata || {},
      };
      rawNodes.push(node);
      nodeMap.set(node.id, node);

      const targetIp = ips[0] || roots[0];
      if (targetIp) {
        rawEdges.push({
          id: `edge_exp_${targetIp.id}_${node.id}`,
          source: targetIp.id,
          target: node.id,
          type: 'EXPOSES',
        });
      }
    });

    // Technologies (Radius 530)
    techs.slice(0, 8).forEach((t, i) => {
      const angle = (i / Math.max(1, Math.min(8, techs.length))) * 2 * Math.PI + 1.2;
      const radius = 530;
      const node: GraphNode = {
        id: t.id,
        name: t.canonicalName,
        type: 'technology',
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
        source: t.discoverySource,
        status: t.status,
        details: t.metadata || {},
      };
      rawNodes.push(node);
      nodeMap.set(node.id, node);

      const targetEp = rawNodes.find((n) => n.type === 'endpoint') || roots[0];
      if (targetEp) {
        rawEdges.push({
          id: `edge_tech_${targetEp.id}_${node.id}`,
          source: targetEp.id,
          target: node.id,
          type: 'USES_TECHNOLOGY',
        });
      }
    });

    return { nodes: rawNodes, edges: rawEdges };
  }, [assets, dnsRecords, endpoints, services]);

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    return nodes.filter((n) => {
      if (!selectedTypes[n.type]) return false;
      if (searchQuery.trim() && !n.name.toLowerCase().includes(searchQuery.toLowerCase())) {
        return false;
      }
      return true;
    });
  }, [nodes, selectedTypes, searchQuery]);

  const visibleNodeIds = useMemo(() => new Set(filteredNodes.map((n) => n.id)), [filteredNodes]);

  const filteredEdges = useMemo(() => {
    return edges.filter((e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target));
  }, [edges, visibleNodeIds]);

  // Mouse wheel zoom
  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom((prev) => Math.min(Math.max(0.4, prev * delta), 3.0));
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).tagName === 'svg' || (e.target as HTMLElement).tagName === 'rect') {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDragging) {
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    }
  };

  const handleMouseUp = () => setIsDragging(false);

  const resetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setSelectedNode(null);
  };

  const exportGraphJson = () => {
    const data = {
      nodes: filteredNodes,
      edges: filteredEdges,
      exportedAt: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `reconx-graph-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getNodeColor = (type: AssetType) => {
    switch (type) {
      case 'root_domain':
        return '#3B82F6'; // Blue
      case 'subdomain':
        return '#22D3EE'; // Cyan
      case 'ip_address':
        return '#10B981'; // Green
      case 'endpoint':
        return '#A855F7'; // Purple
      case 'service':
        return '#F59E0B'; // Amber
      case 'technology':
        return '#EC4899'; // Pink
      default:
        return '#6B7280';
    }
  };

  const getNodeIcon = (type: AssetType) => {
    switch (type) {
      case 'root_domain':
        return Globe;
      case 'subdomain':
        return Globe;
      case 'ip_address':
        return Server;
      case 'endpoint':
        return Layers;
      case 'service':
        return Cpu;
      case 'technology':
        return Shield;
      default:
        return Info;
    }
  };

  return (
    <div className="relative w-full h-[640px] bg-slate-950 border border-slate-800 rounded-xl overflow-hidden select-none">
      {/* Top Toolbar */}
      <div className="absolute top-3 left-3 right-3 z-10 flex flex-wrap items-center justify-between gap-2 pointer-events-none">
        <div className="flex items-center gap-2 pointer-events-auto bg-slate-900/90 backdrop-blur border border-slate-800 rounded-lg p-1.5 shadow-lg">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search assets..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1 text-xs bg-slate-950 border border-slate-700 rounded-md text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-44"
            />
          </div>

          <div className="h-4 w-px bg-slate-700" />

          {/* Quick type toggles */}
          <div className="flex items-center gap-1">
            {(['root_domain', 'subdomain', 'ip_address', 'endpoint', 'service', 'technology'] as AssetType[]).map((t) => (
              <button
                key={t}
                onClick={() => setSelectedTypes((prev) => ({ ...prev, [t]: !prev[t] }))}
                className={`px-2 py-0.5 rounded text-[10px] font-medium transition-all ${
                  selectedTypes[t]
                    ? 'bg-slate-800 text-slate-200 border border-slate-700'
                    : 'bg-transparent text-slate-600 line-through'
                }`}
                style={{
                  borderLeftColor: selectedTypes[t] ? getNodeColor(t) : undefined,
                  borderLeftWidth: selectedTypes[t] ? '3px' : undefined,
                }}
              >
                {t.replace('_', ' ')}
              </button>
            ))}
          </div>
        </div>

        {/* View Controls */}
        <div className="flex items-center gap-1 pointer-events-auto bg-slate-900/90 backdrop-blur border border-slate-800 rounded-lg p-1.5 shadow-lg">
          <button
            onClick={() => setZoom((z) => Math.min(z * 1.2, 3))}
            title="Zoom In"
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={() => setZoom((z) => Math.max(z * 0.8, 0.4))}
            title="Zoom Out"
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={resetView}
            title="Fit to Screen"
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
          <div className="h-4 w-px bg-slate-700" />
          <button
            onClick={exportGraphJson}
            title="Export Graph JSON"
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded flex items-center gap-1 text-xs"
          >
            <Download className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* SVG Interactive Canvas */}
      <div
        ref={containerRef}
        onWheel={handleWheel}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        className="w-full h-full cursor-grab active:cursor-grabbing"
      >
        <svg className="w-full h-full">
          <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" strokeWidth="0.5" />
            </pattern>
            {/* Glow filters */}
            <filter id="glow-blue" x="-20%" y="-20%" width="140%" height="140%">
              <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#3B82F6" floodOpacity="0.6" />
            </filter>
            <filter id="glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
              <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#22D3EE" floodOpacity="0.6" />
            </filter>
          </defs>

          <rect width="100%" height="100%" fill="url(#grid)" />

          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* Concentric orbital guides */}
            <circle cx="500" cy="380" r="180" fill="none" stroke="#1e293b" strokeDasharray="4 4" />
            <circle cx="500" cy="380" r="300" fill="none" stroke="#1e293b" strokeDasharray="4 4" />
            <circle cx="500" cy="380" r="390" fill="none" stroke="#1e293b" strokeDasharray="4 4" />
            <circle cx="500" cy="380" r="460" fill="none" stroke="#1e293b" strokeDasharray="4 4" />
            <circle cx="500" cy="380" r="530" fill="none" stroke="#1e293b" strokeDasharray="4 4" />

            {/* Edges */}
            {filteredEdges.map((e) => {
              const src = nodes.find((n) => n.id === e.source);
              const tgt = nodes.find((n) => n.id === e.target);
              if (!src || !tgt) return null;

              const isHighlighted =
                selectedNode && (selectedNode.id === src.id || selectedNode.id === tgt.id);

              return (
                <g key={e.id}>
                  <line
                    x1={src.x}
                    y1={src.y}
                    x2={tgt.x}
                    y2={tgt.y}
                    stroke={isHighlighted ? '#38bdf8' : '#334155'}
                    strokeWidth={isHighlighted ? 2.5 : 1.2}
                    strokeOpacity={isHighlighted ? 0.9 : 0.6}
                  />
                  {/* Small edge label if highlighted */}
                  {isHighlighted && (
                    <text
                      x={(src.x + tgt.x) / 2}
                      y={(src.y + tgt.y) / 2 - 4}
                      fill="#94a3b8"
                      fontSize="9"
                      textAnchor="middle"
                      className="select-none font-mono"
                    >
                      {e.type}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Nodes */}
            {filteredNodes.map((n) => {
              const isSelected = selectedNode?.id === n.id;
              const color = getNodeColor(n.type);

              return (
                <g
                  key={n.id}
                  transform={`translate(${n.x}, ${n.y})`}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNode(n);
                  }}
                  className="cursor-pointer group"
                >
                  <circle
                    r={n.type === 'root_domain' ? 24 : 16}
                    fill="#0f172a"
                    stroke={color}
                    strokeWidth={isSelected ? 3.5 : 2}
                    filter={isSelected ? 'url(#glow-cyan)' : undefined}
                    className="transition-all"
                  />
                  {/* Small pulse ring */}
                  <circle
                    r={n.type === 'root_domain' ? 14 : 9}
                    fill={color}
                    fillOpacity="0.3"
                  />

                  {/* Label */}
                  <text
                    y={n.type === 'root_domain' ? 36 : 26}
                    textAnchor="middle"
                    fill={isSelected ? '#ffffff' : '#cbd5e1'}
                    fontSize="11"
                    fontWeight={n.type === 'root_domain' ? '600' : '400'}
                    className="select-none"
                    style={{ pointerEvents: 'none' }}
                  >
                    {n.name.length > 22 ? `${n.name.substring(0, 20)}...` : n.name}
                  </text>
                  <text
                    y={n.type === 'root_domain' ? 48 : 36}
                    textAnchor="middle"
                    fill="#64748b"
                    fontSize="8"
                    className="select-none uppercase font-mono"
                    style={{ pointerEvents: 'none' }}
                  >
                    {n.type.replace('_', ' ')}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {/* Side Detail Inspector Panel */}
      {selectedNode && (
        <div className="absolute top-16 right-4 w-80 bg-slate-900/95 backdrop-blur-md border border-slate-700/80 rounded-xl p-4 shadow-2xl z-20 text-slate-200">
          <div className="flex items-start justify-between gap-2 border-b border-slate-800 pb-3 mb-3">
            <div>
              <div className="flex items-center gap-1.5 mb-1">
                <span
                  className="w-2.5 h-2.5 rounded-full"
                  style={{ backgroundColor: getNodeColor(selectedNode.type) }}
                />
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                  {selectedNode.type.replace('_', ' ')}
                </span>
              </div>
              <h4 className="text-sm font-semibold text-white break-all leading-snug">
                {selectedNode.name}
              </h4>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="space-y-2.5 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-500">Discovery Tool:</span>
              <span className="font-mono text-cyan-400">{selectedNode.source}</span>
            </div>
            {selectedNode.status && (
              <div className="flex justify-between">
                <span className="text-slate-500">Observed State:</span>
                <span className="capitalize text-emerald-400">{selectedNode.status}</span>
              </div>
            )}
            <div className="flex justify-between">
              <span className="text-slate-500">Connected Edges:</span>
              <span className="font-mono text-slate-300">
                {edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id).length}
              </span>
            </div>

            {/* Evidence block */}
            <div className="mt-3 pt-3 border-t border-slate-800">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide block mb-1">
                Raw Observation Evidence
              </span>
              <pre className="p-2 bg-slate-950 rounded text-[10px] font-mono text-slate-300 overflow-x-auto border border-slate-800 max-h-36">
                {JSON.stringify(selectedNode.details, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Legend at bottom left */}
      <div className="absolute bottom-3 left-3 bg-slate-900/80 backdrop-blur border border-slate-800/80 rounded-lg px-3 py-2 flex items-center gap-4 text-[11px] text-slate-400 pointer-events-none">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-blue-500" /> Root Domain
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" /> Subdomain
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" /> IP Address
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-purple-500" /> Endpoint
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500" /> Service
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-pink-500" /> Tech
        </div>
      </div>
    </div>
  );
};
