import React, { useState, useRef, useMemo } from 'react';
import {
  ShieldAlert,
  Search,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  CheckSquare,
  Square,
  AlertTriangle,
  Image as ImageIcon,
  FileCode,
} from 'lucide-react';
import {
  Asset,
  AssetType,
  DnsRecord,
  WebEndpoint,
  NetworkService,
  Finding,
  AssetRelationship,
  AssetEvidence,
  Assessment,
} from '../../types';

interface AttackSurfaceGraphProps {
  assets: Asset[];
  dnsRecords: DnsRecord[];
  endpoints: WebEndpoint[];
  services: NetworkService[];
  findings?: Finding[];
  relationships?: AssetRelationship[];
  evidences?: AssetEvidence[];
  assessments?: Assessment[];
  selectedAssessmentFilter?: string;
}

interface PositionedNode {
  id: string;
  label: string;
  type: AssetType;
  riskLevel: string;
  confidence: number;
  x: number;
  y: number;
  parentId?: string;
  childrenIds: string[];
  details: Record<string, any>;
  isExposedRisk?: boolean;
  riskReason?: string;
  evidenceCount?: number;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  evidence: string;
  confidence: number;
  isSuspicious?: boolean;
}

export const AttackSurfaceGraph: React.FC<AttackSurfaceGraphProps> = ({
  assets,
  dnsRecords,
  endpoints = [],
  services = [],
  relationships = [],
  evidences = [],
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [zoom, setZoom] = useState(0.95);
  const [pan, setPan] = useState({ x: 50, y: 35 });
  const [isDraggingCanvas, setIsDraggingCanvas] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const [nodeOffsets, setNodeOffsets] = useState<Record<string, { x: number; y: number }>>({});
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [collapsedNodes, setCollapsedNodes] = useState<Record<string, boolean>>({});
  const [highlightRiskyOnly, setHighlightRiskyOnly] = useState(false);

  const [selectedTypes, setSelectedTypes] = useState<Record<AssetType, boolean>>({
    root_domain: true,
    subdomain: true,
    ip_address: true,
    port: true,
    service: true,
    endpoint: true,
    technology: true,
  });

  const svgRef = useRef<SVGSVGElement>(null);

  const toggleType = (type: AssetType) => {
    setSelectedTypes((prev) => ({ ...prev, [type]: !prev[type] }));
  };

  const toggleCollapse = (nodeId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setCollapsedNodes((prev) => ({ ...prev, [nodeId]: !prev[nodeId] }));
  };

  const { nodes, edges } = useMemo(() => {
    const rawNodes: PositionedNode[] = [];
    const rawEdges: GraphEdge[] = [];

    const filteredAssets = assets.filter((a) => {
      if (!selectedTypes[a.assetType]) return false;
      if (
        highlightRiskyOnly &&
        !a.isExposedRisk &&
        !a.isPotentiallyExposed &&
        a.riskLevel !== 'critical' &&
        a.riskLevel !== 'high'
      ) {
        return false;
      }
      if (
        searchQuery &&
        !a.canonicalName.toLowerCase().includes(searchQuery.toLowerCase()) &&
        !(a.discoverySource || '').toLowerCase().includes(searchQuery.toLowerCase())
      ) {
        return false;
      }
      return true;
    });

    const columns: Record<AssetType, Asset[]> = {
      root_domain: [],
      subdomain: [],
      ip_address: [],
      port: [],
      service: [],
      endpoint: [],
      technology: [],
    };

    filteredAssets.forEach((a) => {
      if (columns[a.assetType]) {
        columns[a.assetType].push(a);
      }
    });

    const colX: Record<AssetType, number> = {
      root_domain: 110,
      subdomain: 340,
      ip_address: 580,
      port: 800,
      service: 1020,
      endpoint: 1240,
      technology: 1460,
    };

    (Object.keys(columns) as AssetType[]).forEach((type) => {
      const list = columns[type];
      const x = colX[type];
      const spacingY = Math.max(82, Math.min(130, 740 / Math.max(1, list.length)));

      list.forEach((asset, idx) => {
        const y = 90 + idx * spacingY;
        const offset = nodeOffsets[asset.id] || { x: 0, y: 0 };
        const assetEvidences = evidences.filter((e) => e.assetId === asset.id);

        rawNodes.push({
          id: asset.id,
          label: asset.canonicalName,
          type: asset.assetType,
          riskLevel: asset.riskLevel || 'informational',
          confidence: asset.confidenceScore ?? 85,
          x: x + offset.x,
          y: y + offset.y,
          childrenIds: [],
          isExposedRisk: Boolean(asset.isExposedRisk || asset.isPotentiallyExposed),
          riskReason: asset.riskReason || asset.exposureReasons?.join('; '),
          evidenceCount: assetEvidences.length || (asset.sources?.length ?? 1),
          details: {
            sources: asset.sources || [asset.discoverySource],
            firstSeen: asset.firstSeen,
            lastSeen: asset.lastSeen,
            ipAddress: asset.ipAddress,
            metadata: asset.metadata,
            status: asset.status,
          },
        });
      });
    });

    const nodeMap = new Map(rawNodes.map((n) => [n.id, n]));
    const addedEdgeKeys = new Set<string>();

    // 1. Connect via explicit correlated relationships
    relationships.forEach((rel) => {
      if (nodeMap.has(rel.sourceAssetId) && nodeMap.has(rel.targetAssetId)) {
        const key = `${rel.sourceAssetId}->${rel.targetAssetId}`;
        if (!addedEdgeKeys.has(key)) {
          addedEdgeKeys.add(key);
          const parent = nodeMap.get(rel.sourceAssetId)!;
          if (!parent.childrenIds.includes(rel.targetAssetId)) {
            parent.childrenIds.push(rel.targetAssetId);
          }
          rawEdges.push({
            id: rel.id || `edge_${key}`,
            source: rel.sourceAssetId,
            target: rel.targetAssetId,
            relationship: rel.relationshipType,
            evidence: rel.evidenceSummary || rel.evidenceSnippet || `Verified by ${rel.sourceTool}`,
            confidence: rel.confidenceScore,
            isSuspicious: rel.isSuspicious,
          });
        }
      }
    });

    // 2. Fallback hierarchy edges if relationships aren't passed directly
    const rootNodes = rawNodes.filter((n) => n.type === 'root_domain');
    if (rootNodes.length > 0) {
      const rootNode = rootNodes[0];
      rawNodes
        .filter((n) => n.type === 'subdomain')
        .forEach((sub) => {
          const key = `${rootNode.id}->${sub.id}`;
          if (!addedEdgeKeys.has(key)) {
            addedEdgeKeys.add(key);
            rootNode.childrenIds.push(sub.id);
            rawEdges.push({
              id: `edge_${key}`,
              source: rootNode.id,
              target: sub.id,
              relationship: 'HAS_SUBDOMAIN',
              evidence: `Discovered under root scope ${rootNode.label}`,
              confidence: sub.confidence,
            });
          }
        });
    }

    // 3. Connect DNS records (Subdomain -> IP)
    dnsRecords.forEach((dns) => {
      if (dns.recordType === 'A' || dns.recordType === 'AAAA') {
        const subNode = rawNodes.find(
          (n) => n.label.toLowerCase() === dns.hostname.toLowerCase()
        );
        const ipNode = rawNodes.find(
          (n) => n.label === dns.value && n.type === 'ip_address'
        );
        if (subNode && ipNode) {
          const key = `${subNode.id}->${ipNode.id}`;
          if (!addedEdgeKeys.has(key)) {
            addedEdgeKeys.add(key);
            if (!subNode.childrenIds.includes(ipNode.id)) {
              subNode.childrenIds.push(ipNode.id);
            }
            rawEdges.push({
              id: `dns_${dns.id}`,
              source: subNode.id,
              target: ipNode.id,
              relationship: 'RESOLVES_TO',
              evidence: `DNS ${dns.recordType} Record (${dns.hostname} -> ${dns.value})`,
              confidence: 96,
            });
          }
        }
      }
    });

    // 4. Filter out descendants of collapsed nodes
    const hiddenNodeIds = new Set<string>();
    const markChildrenHidden = (parentId: string) => {
      const parent = nodeMap.get(parentId);
      if (!parent) return;
      parent.childrenIds.forEach((cid) => {
        if (!hiddenNodeIds.has(cid)) {
          hiddenNodeIds.add(cid);
          markChildrenHidden(cid);
        }
      });
    };

    Object.entries(collapsedNodes).forEach(([nid, isCollapsed]) => {
      if (isCollapsed) markChildrenHidden(nid);
    });

    const visibleNodes = rawNodes.filter((n) => !hiddenNodeIds.has(n.id));
    const visibleIds = new Set(visibleNodes.map((n) => n.id));
    const visibleEdges = rawEdges.filter(
      (e) => visibleIds.has(e.source) && visibleIds.has(e.target)
    );

    return { nodes: visibleNodes, edges: visibleEdges, servicesCount: services.length, endpointsCount: endpoints.length };
  }, [
    assets,
    dnsRecords,
    endpoints,
    services,
    relationships,
    evidences,
    selectedTypes,
    searchQuery,
    collapsedNodes,
    nodeOffsets,
    highlightRiskyOnly,
  ]);

  const connectedNodeIds = useMemo(() => {
    if (!selectedNodeId) return new Set<string>();
    const set = new Set<string>([selectedNodeId]);
    edges.forEach((e) => {
      if (e.source === selectedNodeId) set.add(e.target);
      if (e.target === selectedNodeId) set.add(e.source);
    });
    return set;
  }, [selectedNodeId, edges]);

  const handleMouseDown = (e: React.MouseEvent) => {
    if (draggingNodeId) return;
    setIsDraggingCanvas(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (draggingNodeId) {
      const dx = e.movementX / zoom;
      const dy = e.movementY / zoom;
      setNodeOffsets((prev) => {
        const cur = prev[draggingNodeId] || { x: 0, y: 0 };
        return {
          ...prev,
          [draggingNodeId]: { x: cur.x + dx, y: cur.y + dy },
        };
      });
      return;
    }
    if (!isDraggingCanvas) return;
    setPan({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  };

  const handleMouseUp = () => {
    setIsDraggingCanvas(false);
    setDraggingNodeId(null);
  };

  const resetView = () => {
    setZoom(0.95);
    setPan({ x: 50, y: 35 });
    setNodeOffsets({});
    setCollapsedNodes({});
  };

  const exportSVG = () => {
    if (!svgRef.current) return;
    const serializer = new XMLSerializer();
    const svgString = serializer.serializeToString(svgRef.current);
    const blob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `reconx-attack-surface-${new Date().toISOString().slice(0, 10)}.svg`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const exportPNG = () => {
    if (!svgRef.current) return;
    const serializer = new XMLSerializer();
    const svgString = serializer.serializeToString(svgRef.current);
    const svgBlob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(svgBlob);
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = 1700;
      canvas.height = 950;
      const ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.fillStyle = '#090D16';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        const pngUrl = canvas.toDataURL('image/png');
        const link = document.createElement('a');
        link.href = pngUrl;
        link.download = `reconx-attack-surface-${new Date().toISOString().slice(0, 10)}.png`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      }
      URL.revokeObjectURL(url);
    };
    img.src = url;
  };

  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) || null,
    [nodes, selectedNodeId]
  );

  const selectedAssetEvidences = useMemo(() => {
    if (!selectedNode) return [];
    return evidences.filter((e) => e.assetId === selectedNode.id);
  }, [selectedNode, evidences]);

  const selectedNodeRelationships = useMemo(() => {
    if (!selectedNode) return [];
    return edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id);
  }, [selectedNode, edges]);

  const getNodeColors = (type: AssetType, riskLevel: string, isExposedRisk?: boolean) => {
    if (isExposedRisk || riskLevel === 'critical') {
      return { bg: '#2A1215', border: '#EF4444', text: '#FCA5A5', badge: '#EF4444' };
    }
    if (riskLevel === 'high') {
      return { bg: '#2A1A12', border: '#F97316', text: '#FDBA74', badge: '#F97316' };
    }
    switch (type) {
      case 'root_domain':
        return { bg: '#0F172A', border: '#10B981', text: '#6EE7B7', badge: '#10B981' };
      case 'subdomain':
        return { bg: '#0F172A', border: '#06B6D4', text: '#67E8F9', badge: '#06B6D4' };
      case 'ip_address':
        return { bg: '#0F172A', border: '#3B82F6', text: '#93C5FD', badge: '#3B82F6' };
      case 'port':
        return { bg: '#0F172A', border: '#F59E0B', text: '#FCD34D', badge: '#F59E0B' };
      case 'service':
        return { bg: '#0F172A', border: '#8B5CF6', text: '#C4B5FD', badge: '#8B5CF6' };
      case 'endpoint':
        return { bg: '#0F172A', border: '#EC4899', text: '#F9A8D4', badge: '#EC4899' };
      case 'technology':
        return { bg: '#0F172A', border: '#14B8A6', text: '#5EEAD4', badge: '#14B8A6' };
      default:
        return { bg: '#0F172A', border: '#64748B', text: '#CBD5E1', badge: '#64748B' };
    }
  };

  const typeConfig: { type: AssetType; label: string; color: string }[] = [
    { type: 'root_domain', label: 'Root Domains', color: 'text-emerald-400' },
    { type: 'subdomain', label: 'Subdomains', color: 'text-cyan-400' },
    { type: 'ip_address', label: 'IP Hosts', color: 'text-blue-400' },
    { type: 'port', label: 'Open Ports', color: 'text-amber-400' },
    { type: 'service', label: 'Services', color: 'text-violet-400' },
    { type: 'endpoint', label: 'Endpoints', color: 'text-pink-400' },
    { type: 'technology', label: 'Technologies', color: 'text-teal-400' },
  ];

  return (
    <div className="flex flex-col h-[700px] bg-[#0B0F19] border border-slate-800/80 rounded-xl overflow-hidden">
      {/* Top Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 bg-slate-900/90 border-b border-slate-800/80">
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search nodes, domains, IPs, ports..."
              className="bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500/60 w-60"
            />
          </div>

          <button
            onClick={() => setHighlightRiskyOnly(!highlightRiskyOnly)}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
              highlightRiskyOnly
                ? 'bg-red-500/15 border-red-500/40 text-red-300'
                : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
            Risky Paths Only
          </button>

          <div className="hidden xl:flex items-center gap-1.5 pl-2 border-l border-slate-800">
            {typeConfig.map(({ type, label, color }) => (
              <button
                key={type}
                onClick={() => toggleType(type)}
                className={`flex items-center gap-1 px-2 py-1 rounded text-[11px] font-mono border transition-colors ${
                  selectedTypes[type]
                    ? 'bg-slate-900 border-slate-700 text-slate-200'
                    : 'bg-slate-950/50 border-slate-800/50 text-slate-600'
                }`}
              >
                {selectedTypes[type] ? (
                  <CheckSquare className={`w-3 h-3 ${color}`} />
                ) : (
                  <Square className="w-3 h-3 text-slate-600" />
                )}
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* Zoom & Export Controls */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setZoom((z) => Math.min(2.2, +(z + 0.15).toFixed(2)))}
            className="p-1.5 bg-slate-950 hover:bg-slate-800 text-slate-300 rounded-lg border border-slate-800"
            title="Zoom In"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <span className="text-xs font-mono text-slate-400 px-1.5">{Math.round(zoom * 100)}%</span>
          <button
            onClick={() => setZoom((z) => Math.max(0.35, +(z - 0.15).toFixed(2)))}
            className="p-1.5 bg-slate-950 hover:bg-slate-800 text-slate-300 rounded-lg border border-slate-800"
            title="Zoom Out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={resetView}
            className="p-1.5 bg-slate-950 hover:bg-slate-800 text-slate-300 rounded-lg border border-slate-800"
            title="Reset Graph Layout"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
          <button
            onClick={exportPNG}
            className="flex items-center gap-1 px-2.5 py-1.5 bg-slate-950 hover:bg-slate-800 text-slate-300 rounded-lg border border-slate-800 text-xs font-medium"
            title="Export PNG Snapshot"
          >
            <ImageIcon className="w-3.5 h-3.5 text-emerald-400" />
            PNG
          </button>
          <button
            onClick={exportSVG}
            className="flex items-center gap-1 px-2.5 py-1.5 bg-slate-950 hover:bg-slate-800 text-slate-300 rounded-lg border border-slate-800 text-xs font-medium"
            title="Export Vector SVG"
          >
            <FileCode className="w-3.5 h-3.5 text-cyan-400" />
            SVG
          </button>
        </div>
      </div>

      {/* Main Graph Canvas + Side Inspector */}
      <div className="flex-1 flex overflow-hidden relative">
        <div
          className="flex-1 relative overflow-hidden cursor-grab active:cursor-grabbing select-none"
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        >
          <svg ref={svgRef} className="w-full h-full bg-[#070A12]">
            <defs>
              <pattern id="reconx-grid" width="36" height="36" patternUnits="userSpaceOnUse">
                <path
                  d="M 36 0 L 0 0 0 36"
                  fill="none"
                  stroke="#1E293B"
                  strokeWidth="0.6"
                  strokeOpacity="0.45"
                />
              </pattern>
              <marker
                id="arrow-normal"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="5"
                markerHeight="5"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#475569" />
              </marker>
              <marker
                id="arrow-active"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="5"
                markerHeight="5"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#10B981" />
              </marker>
              <marker
                id="arrow-risk"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="5"
                markerHeight="5"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#EF4444" />
              </marker>
            </defs>

            <rect width="100%" height="100%" fill="url(#reconx-grid)" />

            <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
              {/* Column Headers */}
              {[
                { label: 'ROOT DOMAIN', x: 110 },
                { label: 'SUBDOMAINS', x: 340 },
                { label: 'IP HOSTS', x: 580 },
                { label: 'OPEN PORTS', x: 800 },
                { label: 'SERVICES', x: 1020 },
                { label: 'WEB ENDPOINTS', x: 1240 },
                { label: 'TECHNOLOGIES', x: 1460 },
              ].map((col) => (
                <g key={col.label} transform={`translate(${col.x}, 32)`}>
                  <text
                    textAnchor="middle"
                    fill="#64748B"
                    fontSize="10"
                    fontWeight="700"
                    fontFamily="JetBrains Mono, monospace"
                    letterSpacing="0.08em"
                  >
                    {col.label}
                  </text>
                </g>
              ))}

              {/* Edges */}
              {edges.map((edge) => {
                const sourceNode = nodes.find((n) => n.id === edge.source);
                const targetNode = nodes.find((n) => n.id === edge.target);
                if (!sourceNode || !targetNode) return null;

                const isHighlighted =
                  selectedNodeId === edge.source || selectedNodeId === edge.target;
                const isRiskEdge =
                  edge.isSuspicious ||
                  sourceNode.isExposedRisk ||
                  targetNode.isExposedRisk ||
                  targetNode.riskLevel === 'critical';

                const startX = sourceNode.x + 80;
                const startY = sourceNode.y;
                const endX = targetNode.x - 80;
                const endY = targetNode.y;
                const midX = (startX + endX) / 2;

                const d = `M ${startX} ${startY} C ${midX} ${startY}, ${midX} ${endY}, ${endX} ${endY}`;

                return (
                  <g key={edge.id}>
                    <path
                      d={d}
                      fill="none"
                      stroke={
                        isRiskEdge ? '#EF4444' : isHighlighted ? '#10B981' : '#334155'
                      }
                      strokeWidth={isHighlighted || isRiskEdge ? 2 : 1.2}
                      strokeDasharray={isRiskEdge ? '5,3' : undefined}
                      markerEnd={
                        isRiskEdge
                          ? 'url(#arrow-risk)'
                          : isHighlighted
                          ? 'url(#arrow-active)'
                          : 'url(#arrow-normal)'
                      }
                      opacity={selectedNodeId && !isHighlighted ? 0.25 : 0.9}
                    />
                  </g>
                );
              })}

              {/* Nodes */}
              {nodes.map((node) => {
                const colors = getNodeColors(
                  node.type,
                  node.riskLevel,
                  node.isExposedRisk
                );
                const isSelected = selectedNodeId === node.id;
                const isConnected = connectedNodeIds.has(node.id);
                const isDimmed = selectedNodeId && !isConnected;
                const hasChildren = node.childrenIds.length > 0;
                const isCollapsed = !!collapsedNodes[node.id];

                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x - 80}, ${node.y - 24})`}
                    className="cursor-pointer"
                    opacity={isDimmed ? 0.3 : 1}
                    onMouseDown={(e) => {
                      e.stopPropagation();
                      setSelectedNodeId(node.id);
                      setDraggingNodeId(node.id);
                    }}
                  >
                    <rect
                      width="160"
                      height="48"
                      rx="8"
                      fill={colors.bg}
                      stroke={isSelected ? '#FFFFFF' : colors.border}
                      strokeWidth={isSelected ? 2.2 : 1.4}
                    />

                    <text
                      x="10"
                      y="16"
                      fill={colors.badge}
                      fontSize="9"
                      fontWeight="700"
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {node.type.replace('_', ' ').toUpperCase()}
                    </text>
                    <text
                      x="150"
                      y="16"
                      textAnchor="end"
                      fill="#94A3B8"
                      fontSize="9"
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {node.confidence}%
                    </text>

                    <text
                      x="10"
                      y="34"
                      fill={colors.text}
                      fontSize="11"
                      fontWeight="600"
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {node.label.length > 19
                        ? `${node.label.slice(0, 17)}..`
                        : node.label}
                    </text>

                    {(node.isExposedRisk ||
                      node.riskLevel === 'critical' ||
                      node.riskLevel === 'high') && (
                      <circle
                        cx="152"
                        cy="8"
                        r="4.5"
                        fill="#EF4444"
                        stroke="#090D16"
                        strokeWidth="1.5"
                      />
                    )}

                    {hasChildren && (
                      <g
                        transform="translate(152, 24)"
                        onClick={(e) => toggleCollapse(node.id, e)}
                      >
                        <circle
                          r="8"
                          fill="#1E293B"
                          stroke={colors.border}
                          strokeWidth="1.2"
                        />
                        <text
                          textAnchor="middle"
                          y="3"
                          fill="#E2E8F0"
                          fontSize="10"
                          fontWeight="700"
                          fontFamily="JetBrains Mono, monospace"
                        >
                          {isCollapsed ? '+' : '−'}
                        </text>
                      </g>
                    )}
                  </g>
                );
              })}
            </g>
          </svg>

          {/* Bottom Legend Bar */}
          <div className="absolute bottom-3 left-3 right-3 flex flex-wrap items-center justify-between gap-2 px-3 py-2 bg-slate-950/90 backdrop-blur border border-slate-800/80 rounded-lg text-[11px] text-slate-400">
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-mono uppercase text-slate-500 font-semibold">
                Nodes ({nodes.length}) • Edges ({edges.length})
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" />
                Exposed Risk Path
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" />
                Root Domain
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-500 inline-block" />
                Subdomain
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" />
                IP Host
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" />
                Port
              </span>
            </div>
            <div className="text-slate-500 font-mono">
              Drag node to reposition • Click +/- to fold branches
            </div>
          </div>
        </div>

        {/* Right Asset Detail Drawer */}
        {selectedNode && (
          <div className="w-80 lg:w-96 bg-slate-900/95 border-l border-slate-800 p-4 overflow-y-auto space-y-4">
            <div className="flex items-start justify-between gap-2">
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-slate-800 text-emerald-400">
                  {selectedNode.type.replace('_', ' ')}
                </span>
                <h3 className="text-sm font-mono font-bold text-white mt-1.5 break-all">
                  {selectedNode.label}
                </h3>
              </div>
              <button
                onClick={() => setSelectedNodeId(null)}
                className="text-xs text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-800"
              >
                Close
              </button>
            </div>

            {selectedNode.isExposedRisk && (
              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-300 space-y-1">
                <div className="font-semibold flex items-center gap-1.5 text-red-400">
                  <ShieldAlert className="w-4 h-4" />
                  Exposed Risk Indicator
                </div>
                <p>{selectedNode.riskReason || 'High-risk exposure pattern detected on asset.'}</p>
              </div>
            )}

            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-slate-500">Confidence Score</div>
                <div className="text-sm font-mono font-bold text-emerald-400 mt-0.5">
                  {selectedNode.confidence}%
                </div>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-slate-500">Risk Severity</div>
                <div className="text-sm font-mono font-bold text-white uppercase mt-0.5">
                  {selectedNode.riskLevel}
                </div>
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Discovery Sources
              </div>
              <div className="flex flex-wrap gap-1.5">
                {(selectedNode.details.sources || ['ReconX']).map((src: string) => (
                  <span
                    key={src}
                    className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-400"
                  >
                    {src}
                  </span>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Correlated Relationships ({selectedNodeRelationships.length})
              </div>
              <div className="space-y-1.5 max-h-44 overflow-y-auto pr-1">
                {selectedNodeRelationships.map((rel) => {
                  const otherId =
                    rel.source === selectedNode.id ? rel.target : rel.source;
                  const otherNode = nodes.find((n) => n.id === otherId);
                  return (
                    <div
                      key={rel.id}
                      onClick={() => otherNode && setSelectedNodeId(otherNode.id)}
                      className="p-2 rounded bg-slate-950 border border-slate-800/80 hover:border-slate-700 cursor-pointer text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-emerald-400 text-[10px]">
                          {rel.relationship}
                        </span>
                        <span className="font-mono text-slate-500 text-[10px]">
                          {rel.confidence}% conf
                        </span>
                      </div>
                      <div className="font-mono text-slate-200 truncate mt-0.5">
                        {otherNode?.label || otherId}
                      </div>
                      <div className="text-[11px] text-slate-500 truncate mt-0.5">
                        {rel.evidence}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {selectedAssetEvidences.length > 0 && (
              <div className="space-y-2">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Supporting Evidence ({selectedAssetEvidences.length})
                </div>
                <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                  {selectedAssetEvidences.map((ev) => (
                    <div
                      key={ev.id}
                      className="p-2 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono space-y-1"
                    >
                      <div className="flex items-center justify-between text-cyan-400">
                        <span>{ev.sourceTool}</span>
                        <span className="text-slate-500">
                          {new Date(ev.discoveredAt).toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="text-slate-300 break-all">{ev.rawOutputReference}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
