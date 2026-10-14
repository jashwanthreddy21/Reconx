import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as d3 from 'd3';
import { Finding, FindingSeverity, Asset, Assessment } from '../../types';
import {
  Flame,
  Search,
  Download,
  AlertTriangle,
  Shield,
  Layers,
  ArrowUpDown,
  Filter,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  Info,
  Maximize2,
  RefreshCw,
  Sparkles,
  X
} from 'lucide-react';

interface SubdomainFindingsHeatmapProps {
  assessment: Assessment;
  findings: Finding[];
  assets: Asset[];
  onSelectFinding?: (finding: Finding) => void;
  className?: string;
}

const SEVERITIES: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'informational'];

const SEVERITY_COLORS: Record<FindingSeverity, {
  label: string;
  base: string;
  glow: string;
  border: string;
  bgRgba: (alpha: number) => string;
  weight: number;
}> = {
  critical: {
    label: 'Critical',
    base: '#f43f5e',
    glow: 'rgba(244, 63, 94, 0.4)',
    border: 'rgba(244, 63, 94, 0.6)',
    bgRgba: (a) => `rgba(244, 63, 94, ${a})`,
    weight: 10,
  },
  high: {
    label: 'High',
    base: '#f97316',
    glow: 'rgba(249, 115, 22, 0.4)',
    border: 'rgba(249, 115, 22, 0.6)',
    bgRgba: (a) => `rgba(249, 115, 22, ${a})`,
    weight: 6,
  },
  medium: {
    label: 'Medium',
    base: '#f59e0b',
    glow: 'rgba(245, 158, 11, 0.4)',
    border: 'rgba(245, 158, 11, 0.6)',
    bgRgba: (a) => `rgba(245, 158, 11, ${a})`,
    weight: 3,
  },
  low: {
    label: 'Low',
    base: '#10b981',
    glow: 'rgba(16, 185, 129, 0.4)',
    border: 'rgba(16, 185, 129, 0.6)',
    bgRgba: (a) => `rgba(16, 185, 129, ${a})`,
    weight: 1,
  },
  informational: {
    label: 'Informational',
    base: '#06b6d4',
    glow: 'rgba(6, 182, 212, 0.4)',
    border: 'rgba(6, 182, 212, 0.6)',
    bgRgba: (a) => `rgba(6, 182, 212, ${a})`,
    weight: 0.5,
  },
};

interface HeatmapCell {
  subdomain: string;
  severity: FindingSeverity;
  count: number;
  findings: Finding[];
}

export const SubdomainFindingsHeatmap: React.FC<SubdomainFindingsHeatmapProps> = ({
  assessment,
  findings,
  assets,
  onSelectFinding,
  className = '',
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const tooltipRef = useRef<HTMLDivElement | null>(null);

  // Controls & Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<'risk' | 'count' | 'name'>('risk');
  const [selectedSeverityFilter, setSelectedSeverityFilter] = useState<'all' | FindingSeverity>('all');
  const [selectedCell, setSelectedCell] = useState<HeatmapCell | null>(null);
  const [viewMode, setViewMode] = useState<'severity' | 'category'>('severity');

  // Extract all relevant subdomains
  const rootDomain = assessment.scope.rootDomain || 'target.domain';

  const allSubdomains = useMemo(() => {
    const set = new Set<string>();
    set.add(rootDomain);

    // From assets
    assets.forEach((a) => {
      if (a.assetType === 'subdomain' || a.assetType === 'root_domain') {
        const clean = a.canonicalName.trim().toLowerCase();
        if (clean) set.add(clean);
      }
    });

    // From findings assetRef
    findings.forEach((f) => {
      if (f.assetRef) {
        let clean = f.assetRef.trim().toLowerCase();
        clean = clean.replace(/^https?:\/\//i, '');
        clean = clean.split('/')[0];
        clean = clean.split(':')[0];
        if (clean && clean.includes('.')) {
          set.add(clean);
        }
      }
    });

    return Array.from(set);
  }, [assets, findings, rootDomain]);

  // Map findings to subdomains
  const findingsBySubdomain = useMemo(() => {
    const map = new Map<string, Finding[]>();
    allSubdomains.forEach((s) => map.set(s, []));

    findings.forEach((f) => {
      let ref = (f.assetRef || '').trim().toLowerCase();
      ref = ref.replace(/^https?:\/\//i, '');
      ref = ref.split('/')[0];
      ref = ref.split(':')[0];

      let targetSubdomain = rootDomain;
      if (map.has(ref)) {
        targetSubdomain = ref;
      } else {
        // Try fuzzy subdomain matching
        const matched = allSubdomains.find(
          (s) => s === ref || ref.endsWith('.' + s) || s.endsWith('.' + ref)
        );
        if (matched) {
          targetSubdomain = matched;
        }
      }

      const list = map.get(targetSubdomain) || [];
      list.push(f);
      map.set(targetSubdomain, list);
    });

    return map;
  }, [allSubdomains, findings, rootDomain]);

  // Unique categories for Category View Mode
  const allCategories = useMemo(() => {
    const set = new Set<string>();
    findings.forEach((f) => {
      if (f.category) set.add(f.category);
    });
    if (set.size === 0) {
      set.add('Transport Layer Security');
      set.add('Attack Surface Exposure');
      set.add('Asset Inventory & DNS');
    }
    return Array.from(set).slice(0, 7);
  }, [findings]);

  // Subdomain stats & sorting
  const subdomainStats = useMemo(() => {
    return allSubdomains.map((subdomain) => {
      const subFindings = findingsBySubdomain.get(subdomain) || [];
      const counts: Record<FindingSeverity, number> = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0,
      };

      let riskScore = 0;
      subFindings.forEach((f) => {
        counts[f.severity] = (counts[f.severity] || 0) + 1;
        riskScore += SEVERITY_COLORS[f.severity]?.weight || 1;
      });

      return {
        subdomain,
        totalFindings: subFindings.length,
        riskScore,
        counts,
        findings: subFindings,
      };
    });
  }, [allSubdomains, findingsBySubdomain]);

  // Filtered and sorted subdomains list
  const filteredSubdomains = useMemo(() => {
    let list = subdomainStats.filter((item) => {
      if (searchQuery && !item.subdomain.toLowerCase().includes(searchQuery.toLowerCase())) {
        return false;
      }
      if (selectedSeverityFilter !== 'all') {
        return (item.counts[selectedSeverityFilter] || 0) > 0;
      }
      return true;
    });

    if (sortBy === 'risk') {
      list.sort((a, b) => b.riskScore - a.riskScore || b.totalFindings - a.totalFindings);
    } else if (sortBy === 'count') {
      list.sort((a, b) => b.totalFindings - a.totalFindings || b.riskScore - a.riskScore);
    } else {
      list.sort((a, b) => a.subdomain.localeCompare(b.subdomain));
    }

    return list;
  }, [subdomainStats, searchQuery, sortBy, selectedSeverityFilter]);

  // Aggregate KPI summary
  const kpis = useMemo(() => {
    const totalSubs = allSubdomains.length;
    const subsWithRisks = subdomainStats.filter((s) => s.totalFindings > 0).length;
    const highestRisk = [...subdomainStats].sort((a, b) => b.riskScore - a.riskScore)[0];
    const criticalCount = findings.filter((f) => f.severity === 'critical').length;
    const highCount = findings.filter((f) => f.severity === 'high').length;

    return {
      totalSubs,
      subsWithRisks,
      riskPercentage: totalSubs > 0 ? Math.round((subsWithRisks / totalSubs) * 100) : 0,
      highestRiskSubdomain: highestRisk?.totalFindings > 0 ? highestRisk.subdomain : 'None',
      highestRiskScore: highestRisk?.riskScore || 0,
      criticalCount,
      highCount,
    };
  }, [allSubdomains, subdomainStats, findings]);

  // Build matrix data for D3
  const matrixData: HeatmapCell[] = useMemo(() => {
    const data: HeatmapCell[] = [];
    filteredSubdomains.forEach((item) => {
      SEVERITIES.forEach((sev) => {
        const cellFindings = item.findings.filter((f) => f.severity === sev);
        data.push({
          subdomain: item.subdomain,
          severity: sev,
          count: cellFindings.length,
          findings: cellFindings,
        });
      });
    });
    return data;
  }, [filteredSubdomains]);

  // Category matrix data
  const categoryMatrixData = useMemo(() => {
    const data: Array<{
      subdomain: string;
      category: string;
      count: number;
      findings: Finding[];
      highestSeverity: FindingSeverity;
    }> = [];

    filteredSubdomains.forEach((item) => {
      allCategories.forEach((cat) => {
        const catFindings = item.findings.filter((f) => f.category === cat);
        let highestSev: FindingSeverity = 'informational';
        if (catFindings.some((f) => f.severity === 'critical')) highestSev = 'critical';
        else if (catFindings.some((f) => f.severity === 'high')) highestSev = 'high';
        else if (catFindings.some((f) => f.severity === 'medium')) highestSev = 'medium';
        else if (catFindings.some((f) => f.severity === 'low')) highestSev = 'low';

        data.push({
          subdomain: item.subdomain,
          category: cat,
          count: catFindings.length,
          findings: catFindings,
          highestSeverity: highestSev,
        });
      });
    });
    return data;
  }, [filteredSubdomains, allCategories]);

  // Max finding count in any single cell for color scaling
  const maxCellCount = useMemo(() => {
    const max = d3.max(matrixData, (d) => d.count) || 1;
    return Math.max(max, 3);
  }, [matrixData]);

  // Render D3 Heatmap SVG
  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const containerWidth = containerRef.current.clientWidth || 800;
    const margin = {
      top: 45,
      right: 70,
      bottom: 25,
      left: Math.min(Math.max(160, containerWidth * 0.28), 240),
    };

    const rowHeight = 44;
    const subdomainsList = filteredSubdomains.map((s) => s.subdomain);
    const height = Math.max(subdomainsList.length * rowHeight + margin.top + margin.bottom, 220);
    const width = containerWidth;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    svg
      .attr('width', width)
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('style', 'max-width: 100%; height: auto;');

    const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    if (viewMode === 'severity') {
      // Scale bands
      const xScale = d3.scaleBand<FindingSeverity>()
        .domain(SEVERITIES)
        .range([0, innerWidth])
        .padding(0.08);

      const yScale = d3.scaleBand<string>()
        .domain(subdomainsList)
        .range([0, innerHeight])
        .padding(0.12);

      // Defs for gradients & filters
      const defs = svg.append('defs');
      
      // Glow filters for severity highlights
      SEVERITIES.forEach((sev) => {
        const filter = defs.append('filter')
          .attr('id', `glow-${sev}`)
          .attr('x', '-20%')
          .attr('y', '-20%')
          .attr('width', '140%')
          .attr('height', '140%');
        filter.append('feGaussianBlur')
          .attr('stdDeviation', '3')
          .attr('result', 'blur');
        filter.append('feComposite')
          .attr('in', 'SourceGraphic')
          .attr('in2', 'blur')
          .attr('operator', 'over');
      });

      // Background grid lines
      g.append('g')
        .attr('class', 'grid-rows')
        .selectAll('line')
        .data(subdomainsList)
        .enter()
        .append('line')
        .attr('x1', 0)
        .attr('x2', innerWidth)
        .attr('y1', (d) => (yScale(d) || 0) + yScale.bandwidth() / 2)
        .attr('y2', (d) => (yScale(d) || 0) + yScale.bandwidth() / 2)
        .attr('stroke', '#1e293b')
        .attr('stroke-dasharray', '2,4')
        .attr('stroke-width', 1);

      // X Axis (Severity Headers)
      const xAxis = g.append('g')
        .attr('class', 'x-axis')
        .attr('transform', `translate(0, -10)`);

      xAxis.selectAll('.col-header')
        .data(SEVERITIES)
        .enter()
        .append('g')
        .attr('class', 'col-header')
        .attr('transform', (d) => `translate(${(xScale(d) || 0) + xScale.bandwidth() / 2}, 0)`)
        .each(function (sev) {
          const colG = d3.select(this);
          const meta = SEVERITY_COLORS[sev];

          // Indicator pill/circle
          colG.append('circle')
            .attr('r', 4.5)
            .attr('cy', -14)
            .attr('fill', meta.base)
            .attr('filter', `url(#glow-${sev})`);

          // Text label
          colG.append('text')
            .attr('text-anchor', 'middle')
            .attr('y', -2)
            .attr('fill', meta.base)
            .attr('font-size', '11px')
            .attr('font-family', 'ui-monospace, monospace')
            .attr('font-weight', '600')
            .attr('letter-spacing', '0.05em')
            .text(meta.label.toUpperCase());
        });

      // Y Axis (Subdomain Labels)
      const yAxis = g.append('g').attr('class', 'y-axis');

      yAxis.selectAll('.row-label')
        .data(subdomainsList)
        .enter()
        .append('g')
        .attr('class', 'row-label cursor-pointer')
        .attr('transform', (d) => `translate(-12, ${(yScale(d) || 0) + yScale.bandwidth() / 2})`)
        .on('click', (_, subdomain) => {
          setSearchQuery(subdomain === searchQuery ? '' : subdomain);
        })
        .each(function (subdomain) {
          const rowG = d3.select(this);
          const isRoot = subdomain === rootDomain;

          // Domain text (right aligned to column)
          const textEl = rowG.append('text')
            .attr('text-anchor', 'end')
            .attr('dy', '0.35em')
            .attr('fill', isRoot ? '#38bdf8' : '#cbd5e1')
            .attr('font-size', '11.5px')
            .attr('font-family', 'ui-monospace, monospace')
            .attr('font-weight', isRoot ? '700' : '500')
            .text(subdomain.length > 28 ? subdomain.slice(0, 26) + '…' : subdomain);

          // Add title for tooltip
          textEl.append('title').text(subdomain);

          // Subdomain icon indicator
          rowG.append('circle')
            .attr('cx', 6)
            .attr('cy', 0)
            .attr('r', 2.5)
            .attr('fill', isRoot ? '#38bdf8' : '#64748b');
        });

      // Heatmap Cells
      const cellGroup = g.append('g').attr('class', 'cells');

      const cells = cellGroup.selectAll('.cell')
        .data(matrixData)
        .enter()
        .append('g')
        .attr('class', 'cell cursor-pointer')
        .attr('transform', (d) => `translate(${xScale(d.severity) || 0}, ${yScale(d.subdomain) || 0})`);

      // Cell rectangle
      cells.append('rect')
        .attr('width', xScale.bandwidth())
        .attr('height', yScale.bandwidth())
        .attr('rx', 6)
        .attr('ry', 6)
        .attr('fill', (d) => {
          if (d.count === 0) return '#0b1120';
          const meta = SEVERITY_COLORS[d.severity];
          // Scale opacity by count
          const alpha = Math.min(0.22 + (d.count / maxCellCount) * 0.65, 0.92);
          return meta.bgRgba(alpha);
        })
        .attr('stroke', (d) => {
          if (d.count === 0) return '#1e293b';
          const meta = SEVERITY_COLORS[d.severity];
          return meta.border;
        })
        .attr('stroke-width', (d) => (d.count > 0 ? 1.5 : 1))
        .attr('stroke-dasharray', (d) => (d.count === 0 ? '3,3' : 'none'))
        .style('transition', 'all 0.15s ease-in-out')
        .on('mouseover', function (event, d) {
          d3.select(this)
            .attr('stroke', '#ffffff')
            .attr('stroke-width', 2)
            .style('filter', d.count > 0 ? `drop-shadow(0 0 8px ${SEVERITY_COLORS[d.severity].glow})` : 'none');

          // Tooltip handling
          if (tooltipRef.current) {
            const meta = SEVERITY_COLORS[d.severity];
            tooltipRef.current.innerHTML = `
              <div class="p-3 max-w-xs text-xs space-y-1.5 font-sans">
                <div class="flex items-center justify-between border-b border-slate-700/80 pb-1.5">
                  <span class="font-mono font-semibold text-white truncate">${d.subdomain}</span>
                  <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase" style="background:${meta.glow}; color:${meta.base}; border:1px solid ${meta.border}">
                    ${meta.label}
                  </span>
                </div>
                <div class="flex items-center justify-between text-slate-300">
                  <span>Frequency / Findings:</span>
                  <span class="font-mono font-bold text-white">${d.count} observation${d.count === 1 ? '' : 's'}</span>
                </div>
                ${
                  d.count > 0
                    ? `<div class="mt-2 pt-1 border-t border-slate-800/80 space-y-1">
                        ${d.findings
                          .slice(0, 3)
                          .map(
                            (f) =>
                              `<div class="text-[11px] text-slate-300 truncate flex items-center gap-1.5">
                                <span class="w-1.5 h-1.5 rounded-full" style="background:${meta.base}"></span>
                                <span>${f.title}</span>
                              </div>`
                          )
                          .join('')}
                        ${
                          d.findings.length > 3
                            ? `<div class="text-[10px] text-cyan-400 font-mono">+${d.findings.length - 3} more finding${
                                d.findings.length - 3 > 1 ? 's' : ''
                              }</div>`
                            : ''
                        }
                       </div>
                       <div class="text-[10px] text-slate-400 pt-1 flex items-center gap-1 italic">
                         <span>Click to inspect details in drawer</span>
                       </div>`
                    : '<div class="text-[11px] text-slate-500 italic">No security findings observed in this tier.</div>'
                }
              </div>
            `;
            tooltipRef.current.style.opacity = '1';
            tooltipRef.current.style.left = `${event.pageX + 12}px`;
            tooltipRef.current.style.top = `${event.pageY - 28}px`;
          }
        })
        .on('mousemove', function (event) {
          if (tooltipRef.current) {
            tooltipRef.current.style.left = `${event.pageX + 12}px`;
            tooltipRef.current.style.top = `${event.pageY - 28}px`;
          }
        })
        .on('mouseout', function (_, d) {
          d3.select(this)
            .attr('stroke', d.count > 0 ? SEVERITY_COLORS[d.severity].border : '#1e293b')
            .attr('stroke-width', d.count > 0 ? 1.5 : 1)
            .style('filter', 'none');

          if (tooltipRef.current) {
            tooltipRef.current.style.opacity = '0';
          }
        })
        .on('click', (_, d) => {
          setSelectedCell(d);
        });

      // Cell Content: Count badge / Number
      cells.each(function (d) {
        if (d.count > 0) {
          const cellEl = d3.select(this);
          const meta = SEVERITY_COLORS[d.severity];

          cellEl.append('text')
            .attr('x', xScale.bandwidth() / 2)
            .attr('y', yScale.bandwidth() / 2 + 4)
            .attr('text-anchor', 'middle')
            .attr('fill', '#ffffff')
            .attr('font-size', '12px')
            .attr('font-weight', '700')
            .attr('font-family', 'ui-monospace, monospace')
            .attr('pointer-events', 'none')
            .text(d.count);

          // Small pulse indicator if critical and > 0
          if (d.severity === 'critical') {
            cellEl.append('circle')
              .attr('cx', xScale.bandwidth() - 8)
              .attr('cy', 8)
              .attr('r', 2.5)
              .attr('fill', meta.base)
              .attr('pointer-events', 'none');
          }
        } else {
          // Subtle dash for empty
          const cellEl = d3.select(this);
          cellEl.append('text')
            .attr('x', xScale.bandwidth() / 2)
            .attr('y', yScale.bandwidth() / 2 + 3)
            .attr('text-anchor', 'middle')
            .attr('fill', '#334155')
            .attr('font-size', '11px')
            .attr('font-family', 'ui-monospace, monospace')
            .attr('pointer-events', 'none')
            .text('—');
        }
      });

      // Right total risk score column
      const rightCol = g.append('g')
        .attr('class', 'right-col')
        .attr('transform', `translate(${innerWidth + 14}, 0)`);

      // Column header
      rightCol.append('text')
        .attr('x', 0)
        .attr('y', -12)
        .attr('fill', '#94a3b8')
        .attr('font-size', '10px')
        .attr('font-family', 'ui-monospace, monospace')
        .attr('font-weight', '600')
        .text('RISK');

      // Row values
      subdomainsList.forEach((subdomain) => {
        const item = filteredSubdomains.find((s) => s.subdomain === subdomain);
        const y = (yScale(subdomain) || 0) + yScale.bandwidth() / 2 + 4;
        const total = item?.totalFindings || 0;
        const score = item?.riskScore || 0;

        const rowG = rightCol.append('g');

        rowG.append('text')
          .attr('x', 0)
          .attr('y', y)
          .attr('fill', score > 10 ? '#f43f5e' : score > 5 ? '#f97316' : score > 0 ? '#f59e0b' : '#64748b')
          .attr('font-size', '11px')
          .attr('font-weight', '700')
          .attr('font-family', 'ui-monospace, monospace')
          .text(total > 0 ? `${score} pts` : 'clean');
      });

    } else {
      // ----------------------------------------------------
      // MODE 2: CATEGORY VIEW MATRIX
      // ----------------------------------------------------
      const xScale = d3.scaleBand<string>()
        .domain(allCategories)
        .range([0, innerWidth])
        .padding(0.08);

      const yScale = d3.scaleBand<string>()
        .domain(subdomainsList)
        .range([0, innerHeight])
        .padding(0.12);

      // X Axis (Category Headers)
      const xAxis = g.append('g')
        .attr('class', 'x-axis')
        .attr('transform', `translate(0, -8)`);

      xAxis.selectAll('.cat-header')
        .data(allCategories)
        .enter()
        .append('text')
        .attr('class', 'cat-header')
        .attr('x', (d) => (xScale(d) || 0) + xScale.bandwidth() / 2)
        .attr('y', -6)
        .attr('text-anchor', 'middle')
        .attr('fill', '#38bdf8')
        .attr('font-size', '10px')
        .attr('font-family', 'ui-monospace, monospace')
        .attr('font-weight', '600')
        .text((d) => (d.length > 14 ? d.slice(0, 12) + '…' : d));

      // Y Axis
      const yAxis = g.append('g').attr('class', 'y-axis');
      yAxis.selectAll('.row-label')
        .data(subdomainsList)
        .enter()
        .append('text')
        .attr('x', -12)
        .attr('y', (d) => (yScale(d) || 0) + yScale.bandwidth() / 2 + 4)
        .attr('text-anchor', 'end')
        .attr('fill', '#cbd5e1')
        .attr('font-size', '11px')
        .attr('font-family', 'ui-monospace, monospace')
        .text((d) => (d.length > 28 ? d.slice(0, 26) + '…' : d));

      // Category Cells
      const cells = g.append('g')
        .attr('class', 'category-cells')
        .selectAll('.cat-cell')
        .data(categoryMatrixData)
        .enter()
        .append('g')
        .attr('class', 'cat-cell cursor-pointer')
        .attr('transform', (d) => `translate(${xScale(d.category) || 0}, ${yScale(d.subdomain) || 0})`);

      cells.append('rect')
        .attr('width', xScale.bandwidth())
        .attr('height', yScale.bandwidth())
        .attr('rx', 6)
        .attr('ry', 6)
        .attr('fill', (d) => {
          if (d.count === 0) return '#0b1120';
          const meta = SEVERITY_COLORS[d.highestSeverity];
          return meta.bgRgba(0.45);
        })
        .attr('stroke', (d) => (d.count > 0 ? SEVERITY_COLORS[d.highestSeverity].border : '#1e293b'))
        .attr('stroke-width', (d) => (d.count > 0 ? 1.5 : 1))
        .on('mouseover', function (event, d) {
          d3.select(this).attr('stroke', '#ffffff').attr('stroke-width', 2);
          if (tooltipRef.current) {
            tooltipRef.current.innerHTML = `
              <div class="p-3 text-xs space-y-1">
                <div class="font-mono text-white font-semibold">${d.subdomain}</div>
                <div class="text-cyan-400 font-semibold">${d.category}</div>
                <div class="text-slate-300">${d.count} finding${d.count === 1 ? '' : 's'}</div>
              </div>
            `;
            tooltipRef.current.style.opacity = '1';
            tooltipRef.current.style.left = `${event.pageX + 12}px`;
            tooltipRef.current.style.top = `${event.pageY - 24}px`;
          }
        })
        .on('mouseout', function (_, d) {
          d3.select(this)
            .attr('stroke', d.count > 0 ? SEVERITY_COLORS[d.highestSeverity].border : '#1e293b')
            .attr('stroke-width', d.count > 0 ? 1.5 : 1);
          if (tooltipRef.current) tooltipRef.current.style.opacity = '0';
        })
        .on('click', (_, d) => {
          if (d.count > 0) {
            setSelectedCell({
              subdomain: d.subdomain,
              severity: d.highestSeverity,
              count: d.count,
              findings: d.findings,
            });
          }
        });

      cells.each(function (d) {
        const cellEl = d3.select(this);
        cellEl.append('text')
          .attr('x', xScale.bandwidth() / 2)
          .attr('y', yScale.bandwidth() / 2 + 4)
          .attr('text-anchor', 'middle')
          .attr('fill', d.count > 0 ? '#ffffff' : '#334155')
          .attr('font-size', '11px')
          .attr('font-weight', '700')
          .attr('font-family', 'ui-monospace, monospace')
          .text(d.count > 0 ? d.count : '—');
      });
    }
  }, [
    filteredSubdomains,
    matrixData,
    categoryMatrixData,
    maxCellCount,
    rootDomain,
    viewMode,
    allCategories,
  ]);

  // Export SVG to download
  const handleExportSvg = () => {
    if (!svgRef.current) return;
    const svgContent = new XMLSerializer().serializeToString(svgRef.current);
    const blob = new Blob([svgContent], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `reconx-subdomain-heatmap-${assessment.scope.rootDomain}.svg`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Tooltip Portal / Floating Element */}
      <div
        ref={tooltipRef}
        className="fixed z-50 pointer-events-none transition-opacity duration-150 opacity-0 bg-[#0F172A] border border-slate-700/90 rounded-xl shadow-2xl backdrop-blur-md"
        style={{ transform: 'translate(0, 0)' }}
      />

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 shadow-lg">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs">Evaluated Subdomains</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-xl font-bold font-mono text-white">{kpis.totalSubs}</div>
          <div className="text-[10px] text-slate-500 mt-1 font-mono">
            {kpis.subsWithRisks} with findings ({kpis.riskPercentage}%)
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 shadow-lg">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs">Critical &amp; High Density</span>
            <Flame className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono text-rose-400 flex items-center gap-1.5">
            <span>{kpis.criticalCount + kpis.highCount}</span>
            <span className="text-xs font-normal text-slate-400">
              ({kpis.criticalCount} crit / {kpis.highCount} high)
            </span>
          </div>
          <div className="text-[10px] text-slate-500 mt-1 font-mono">Immediate remediation focus</div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 shadow-lg">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs">Highest Risk Subdomain</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-sm font-bold font-mono text-amber-300 truncate" title={kpis.highestRiskSubdomain}>
            {kpis.highestRiskSubdomain}
          </div>
          <div className="text-[10px] text-slate-500 mt-1 font-mono">
            Cumulative risk score: {kpis.highestRiskScore}
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 shadow-lg">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs">Surface Health Status</span>
            <Shield className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-sm font-bold font-mono text-emerald-400">
            {kpis.totalSubs - kpis.subsWithRisks} Clean Surfaces
          </div>
          <div className="text-[10px] text-slate-500 mt-1 font-mono">
            {Math.round(((kpis.totalSubs - kpis.subsWithRisks) / Math.max(kpis.totalSubs, 1)) * 100)}% hardened
          </div>
        </div>
      </div>

      {/* Main Heatmap Container */}
      <div className="bg-[#111827] border border-slate-800 rounded-2xl shadow-xl overflow-hidden">
        {/* Controls Toolbar */}
        <div className="p-4 sm:p-5 border-b border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Flame className="w-5 h-5 text-rose-500" />
              <h3 className="text-base font-semibold text-white">
                Subdomain Severity &amp; Frequency Heatmap
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                D3.js Dynamic Matrix
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Visual correlation of finding severity density across all discovered subdomains. Hover for telemetry and click to inspect details.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {/* View Mode Toggle */}
            <div className="flex items-center bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
              <button
                onClick={() => setViewMode('severity')}
                className={`px-3 py-1 rounded-lg font-medium transition-all ${
                  viewMode === 'severity'
                    ? 'bg-blue-600/30 text-cyan-300 font-semibold border border-blue-500/40'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Severity Matrix
              </button>
              <button
                onClick={() => setViewMode('category')}
                className={`px-3 py-1 rounded-lg font-medium transition-all ${
                  viewMode === 'category'
                    ? 'bg-blue-600/30 text-cyan-300 font-semibold border border-blue-500/40'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Category Matrix
              </button>
            </div>

            {/* Export SVG */}
            <button
              onClick={handleExportSvg}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-300 hover:text-white rounded-xl text-xs font-mono font-medium transition-all cursor-pointer"
              title="Download vector graphic of heatmap"
            >
              <Download className="w-3.5 h-3.5" /> Export SVG
            </button>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="px-4 py-3 bg-slate-950/60 border-b border-slate-800/60 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-3">
            {/* Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
              <input
                type="text"
                placeholder="Filter subdomains..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1 text-xs bg-slate-900 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-44"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2 top-1.5 text-slate-400 hover:text-white"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>

            {/* Severity Filter */}
            <select
              value={selectedSeverityFilter}
              onChange={(e) => setSelectedSeverityFilter(e.target.value as any)}
              className="px-2.5 py-1 text-xs bg-slate-900 border border-slate-700 rounded-lg text-slate-300 focus:outline-none"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical Only</option>
              <option value="high">High Only</option>
              <option value="medium">Medium Only</option>
              <option value="low">Low Only</option>
              <option value="informational">Informational Only</option>
            </select>

            {/* Sort Order */}
            <div className="flex items-center gap-1.5 text-slate-400">
              <ArrowUpDown className="w-3.5 h-3.5" />
              <span>Sort:</span>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="px-2 py-1 text-xs bg-slate-900 border border-slate-700 rounded-lg text-slate-300 focus:outline-none"
              >
                <option value="risk">Risk Score (High to Low)</option>
                <option value="count">Findings Count</option>
                <option value="name">Alphabetical (A-Z)</option>
              </select>
            </div>
          </div>

          {/* Color Scale Legend */}
          <div className="flex items-center gap-3 font-mono text-[10px] text-slate-400">
            <span className="text-slate-500">Density:</span>
            <div className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-sm bg-[#0b1120] border border-slate-700" />
              <span>0</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-sm bg-rose-500/30 border border-rose-500/50" />
              <span>1</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-sm bg-rose-500/60 border border-rose-500/80" />
              <span>2+</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-sm bg-rose-500/90 border border-rose-500" />
              <span>High Density</span>
            </div>
          </div>
        </div>

        {/* Heatmap D3 Viewport */}
        <div ref={containerRef} className="p-4 sm:p-6 overflow-x-auto min-h-[260px] bg-slate-950/40">
          {filteredSubdomains.length === 0 ? (
            <div className="py-16 text-center space-y-2">
              <AlertTriangle className="w-8 h-8 text-amber-500 mx-auto" />
              <div className="text-sm font-semibold text-white">No subdomains match current filters</div>
              <p className="text-xs text-slate-400">Try clearing your search query or severity filter.</p>
              <button
                onClick={() => {
                  setSearchQuery('');
                  setSelectedSeverityFilter('all');
                }}
                className="mt-2 text-xs text-cyan-400 hover:underline inline-block font-mono"
              >
                Reset Filters
              </button>
            </div>
          ) : (
            <svg ref={svgRef} className="mx-auto block" />
          )}
        </div>
      </div>

      {/* Selected Cell Detail Drawer / Inspection Modal */}
      {selectedCell && (
        <div className="bg-[#111827] border border-slate-700/80 rounded-2xl p-5 shadow-2xl space-y-4 animate-in fade-in slide-in-from-top-2 duration-200">
          <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-3">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span
                  className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase"
                  style={{
                    backgroundColor: SEVERITY_COLORS[selectedCell.severity].glow,
                    color: SEVERITY_COLORS[selectedCell.severity].base,
                    border: `1px solid ${SEVERITY_COLORS[selectedCell.severity].border}`,
                  }}
                >
                  {selectedCell.severity} SEVERITY
                </span>
                <span className="text-xs text-slate-400">•</span>
                <span className="text-xs text-slate-400 font-mono">
                  {selectedCell.count} Finding{selectedCell.count === 1 ? '' : 's'} Observed
                </span>
              </div>
              <h4 className="text-base font-bold text-white font-mono flex items-center gap-2">
                <span>{selectedCell.subdomain}</span>
                {selectedCell.subdomain === rootDomain && (
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                    ROOT
                  </span>
                )}
              </h4>
            </div>

            <button
              onClick={() => setSelectedCell(null)}
              className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {selectedCell.count === 0 ? (
            <div className="py-6 text-center text-xs text-slate-400 flex flex-col items-center gap-2">
              <CheckCircle2 className="w-6 h-6 text-emerald-400" />
              <span>No findings observed for this severity tier on this subdomain surface.</span>
            </div>
          ) : (
            <div className="space-y-3">
              {selectedCell.findings.map((f) => (
                <div
                  key={f.id}
                  className="p-4 bg-slate-950 rounded-xl border border-slate-800 hover:border-slate-700 transition-all space-y-2"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="space-y-0.5">
                      <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wide">
                        {f.category || 'Reconnaissance Finding'}
                      </span>
                      <h5 className="text-sm font-semibold text-white">{f.title}</h5>
                    </div>
                    <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                      {f.sourceTool}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">{f.description}</p>

                  {f.evidence && (
                    <div className="p-2.5 bg-slate-900/80 rounded-lg border border-slate-800/80 text-[11px] font-mono text-slate-300 overflow-x-auto">
                      <div className="text-[9px] uppercase text-slate-500 font-bold mb-1">
                        Observable Evidence:
                      </div>
                      <code>{f.evidence}</code>
                    </div>
                  )}

                  {f.remediation && (
                    <div className="p-2.5 bg-blue-950/30 rounded-lg border border-blue-900/40 text-[11px] text-blue-200">
                      <span className="font-semibold text-cyan-300">Remediation: </span>
                      {f.remediation}
                    </div>
                  )}

                  {onSelectFinding && (
                    <div className="pt-1 flex justify-end">
                      <button
                        onClick={() => onSelectFinding(f)}
                        className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 hover:underline cursor-pointer"
                      >
                        Inspect in Full Detail <ExternalLink className="w-3 h-3" />
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
