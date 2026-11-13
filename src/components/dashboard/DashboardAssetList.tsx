import React, { useMemo, useState } from 'react';
import {
  Assessment,
  Asset,
  AssetType,
  FindingSeverity,
  GeoRegionId,
  IpGeoLocation,
} from '../../types';
import {
  GEO_REGION_OPTIONS,
} from '../../services/ipGeolocationService';
import {
  Globe,
  Search,
  MapPin,
  Download,
  ExternalLink,
  Loader2,
  X,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';

export interface DashboardAssetRow {
  id: string;
  asset: Asset;
  assessment: Assessment;
  resolvedIp: string | null;
  geo: IpGeoLocation | null;
  geoRegionId: GeoRegionId;
  geoRegionLabel: string;
  severity: FindingSeverity;
  riskReason: string;
}

interface Props {
  rows: DashboardAssetRow[];
  loading: boolean;
  resolvingGeo: boolean;
  selectedGeoRegion: GeoRegionId | 'all';
  onGeoRegionChange: (region: GeoRegionId | 'all') => void;
  onSelectAssessment: (assessmentId: string) => void;
}

const SEVERITY_STYLES: Record<FindingSeverity, string> = {
  critical: 'text-rose-400',
  high: 'text-orange-400',
  medium: 'text-amber-400',
  low: 'text-cyan-400',
  informational: 'text-slate-400',
};

const ASSET_TYPE_LABELS: Record<AssetType, string> = {
  root_domain: 'Root Domain',
  subdomain: 'Subdomain',
  ip_address: 'IP Address',
  port: 'Network Port',
  endpoint: 'Web Endpoint',
  service: 'Network Service',
  technology: 'Technology',
};

export const DashboardAssetList: React.FC<Props> = ({
  rows,
  loading,
  resolvingGeo,
  selectedGeoRegion,
  onGeoRegionChange,
  onSelectAssessment,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [assetTypeFilter, setAssetTypeFilter] = useState<string>('all');
  const [externalOnly, setExternalOnly] = useState<boolean>(false);
  const [showAllRows, setShowAllRows] = useState<boolean>(false);

  // Region counts before geo-region filter so operators can see distribution across regions
  const regionCounts = useMemo(() => {
    const counts: Record<string, number> = { all: 0 };
    for (const opt of GEO_REGION_OPTIONS) {
      counts[opt.id] = 0;
    }
    rows.forEach((row) => {
      if (externalOnly && !row.geo?.isExternal) return;
      if (assetTypeFilter !== 'all' && row.asset.assetType !== assetTypeFilter) return;
      counts.all += 1;
      counts[row.geoRegionId] = (counts[row.geoRegionId] || 0) + 1;
    });
    return counts;
  }, [rows, externalOnly, assetTypeFilter]);

  const externalIpStats = useMemo(() => {
    const uniqueCountries = new Set<string>();
    const uniqueExternalIps = new Set<string>();
    rows.forEach((row) => {
      if (row.geo?.isExternal && row.resolvedIp) {
        uniqueExternalIps.add(row.resolvedIp);
        if (row.geo.country && row.geo.country !== 'Unknown') {
          uniqueCountries.add(`${row.geo.countryCode} · ${row.geo.country}`);
        }
      }
    });
    return {
      externalIpCount: uniqueExternalIps.size,
      countriesCount: uniqueCountries.size,
    };
  }, [rows]);

  const filteredRows = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    return rows.filter((row) => {
      if (selectedGeoRegion !== 'all' && row.geoRegionId !== selectedGeoRegion) {
        return false;
      }
      if (externalOnly && !row.geo?.isExternal) {
        return false;
      }
      if (assetTypeFilter !== 'all' && row.asset.assetType !== assetTypeFilter) {
        return false;
      }
      if (q) {
        const hay = [
          row.asset.canonicalName,
          row.resolvedIp || '',
          row.geo?.country || '',
          row.geo?.countryCode || '',
          row.geo?.city || '',
          row.geo?.isp || '',
          row.geoRegionLabel,
          row.assessment.name,
          row.assessment.scope?.rootDomain || '',
        ]
          .join(' ')
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [rows, selectedGeoRegion, externalOnly, assetTypeFilter, searchTerm]);

  const visibleRows = showAllRows ? filteredRows : filteredRows.slice(0, 15);
  const hasActiveFilters =
    selectedGeoRegion !== 'all' ||
    externalOnly ||
    assetTypeFilter !== 'all' ||
    searchTerm.trim().length > 0;

  const handleResetFilters = () => {
    onGeoRegionChange('all');
    setExternalOnly(false);
    setAssetTypeFilter('all');
    setSearchTerm('');
  };

  const handleExportGeoCsv = () => {
    const headers = [
      'Asset Identifier',
      'Asset Type',
      'Resolved IP',
      'IP Scope',
      'Country Code',
      'Country of Origin',
      'City',
      'Geographic Region',
      'ISP / Network',
      'Risk Tier',
      'Assessment',
    ];
    const csvRows = filteredRows.map((r) => [
      r.asset.canonicalName,
      r.asset.assetType,
      r.resolvedIp || '',
      r.geo ? (r.geo.isExternal ? 'External' : 'Internal') : 'Unresolved',
      r.geo?.countryCode || '',
      r.geo?.country || '',
      r.geo?.city || '',
      r.geoRegionLabel,
      r.geo?.isp || '',
      r.severity.toUpperCase(),
      r.assessment.name,
    ]);
    const csvContent = [
      headers.join(','),
      ...csvRows.map((line) =>
        line.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(',')
      ),
    ].join('\r\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `reconx-geolocated-assets-${Date.now()}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-[#111827] rounded-xl border border-slate-800 overflow-hidden shadow-lg">
      {/* Header */}
      <div className="p-4 border-b border-slate-800 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <Globe className="w-4 h-4 text-cyan-400 shrink-0" />
            <h3 className="text-sm font-semibold text-white">
              Discovered Asset Inventory &amp; External IP Geolocation
            </h3>
            <span className="text-xs font-mono tabular-nums text-slate-400">
              · {filteredRows.length} assets
            </span>
            <span className="text-xs font-mono tabular-nums text-slate-400">
              · {externalIpStats.externalIpCount} external IPs across {externalIpStats.countriesCount}{' '}
              {externalIpStats.countriesCount === 1 ? 'country' : 'countries'}
            </span>
            {resolvingGeo && (
              <span className="inline-flex items-center gap-1.5 text-xs font-mono text-cyan-400">
                <Loader2 className="w-3.5 h-3.5 animate-spin" /> Resolving IP origins...
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Physical country of origin and regional attribution for discovered external IP addresses and IP-backed infrastructure assets.
          </p>
        </div>

        {/* Search, Type, External-Only Toggle, and Export */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5 pointer-events-none" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter host, IP, country, city..."
              aria-label="Filter dashboard assets by host, IP, country, or city"
              className="pl-8 pr-7 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-52"
            />
            {searchTerm && (
              <button
                type="button"
                onClick={() => setSearchTerm('')}
                className="absolute right-2 top-2 text-slate-400 hover:text-white cursor-pointer"
                aria-label="Clear asset filter search"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <select
            value={assetTypeFilter}
            onChange={(e) => setAssetTypeFilter(e.target.value)}
            aria-label="Filter dashboard assets by type"
            className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="all">All Asset Types</option>
            <option value="ip_address">IP Addresses</option>
            <option value="subdomain">Subdomains</option>
            <option value="endpoint">Web Endpoints</option>
            <option value="service">Network Services</option>
            <option value="port">Open Ports</option>
            <option value="root_domain">Root Domains</option>
          </select>

          <button
            type="button"
            onClick={() => setExternalOnly((prev) => !prev)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              externalOnly
                ? 'bg-cyan-600/20 text-cyan-300 border-cyan-500/50'
                : 'bg-slate-900 text-slate-300 border-slate-700 hover:bg-slate-800'
            }`}
          >
            External IPs Only
          </button>

          <button
            type="button"
            onClick={handleExportGeoCsv}
            disabled={filteredRows.length === 0}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 border border-slate-700 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Geographic Region Filter Bar */}
      <div className="px-4 py-2.5 bg-slate-900/40 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 mr-1 whitespace-nowrap">
            <MapPin className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span>Geographic Region:</span>
          </div>

          {GEO_REGION_OPTIONS.map((region) => {
            const count = regionCounts[region.id] || 0;
            const isActive = selectedGeoRegion === region.id;
            // Always show All, core geo continents, or any region that currently has > 0 assets
            const isCore =
              region.id === 'all' ||
              region.id === 'north-america' ||
              region.id === 'europe' ||
              region.id === 'asia-pacific';
            if (!isCore && count === 0 && !isActive) return null;

            return (
              <button
                key={region.id}
                type="button"
                onClick={() => onGeoRegionChange(region.id)}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  isActive
                    ? 'bg-blue-600/25 text-white border border-blue-500/60'
                    : 'bg-slate-800/60 text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-700/60'
                }`}
              >
                <span>{region.shortLabel}</span>
                <span className="font-mono tabular-nums text-[11px] text-slate-400">
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        {hasActiveFilters && (
          <button
            type="button"
            onClick={handleResetFilters}
            className="text-xs text-cyan-400 hover:text-cyan-300 hover:underline font-medium whitespace-nowrap shrink-0 cursor-pointer"
          >
            Reset Geo Filters
          </button>
        )}
      </div>

      {/* Data Table / States */}
      {loading && rows.length === 0 ? (
        <div className="p-6 space-y-2.5">
          {Array.from({ length: 4 }).map((_, idx) => (
            <div
              key={idx}
              className="h-10 rounded-lg bg-slate-900/80 border border-slate-800/60 animate-pulse"
            />
          ))}
        </div>
      ) : rows.length === 0 ? (
        <div className="p-10 text-center space-y-2">
          <Globe className="w-6 h-6 text-slate-500 mx-auto" />
          <div className="text-sm font-semibold text-white">
            No Discovered Assets Available
          </div>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Run an assessment scan or load the Demo Lab fixture above to populate external IP addresses and geolocate their physical country of origin.
          </p>
        </div>
      ) : filteredRows.length === 0 ? (
        <div className="p-10 text-center space-y-3">
          <MapPin className="w-6 h-6 text-cyan-400 mx-auto" />
          <div className="text-sm font-semibold text-white">
            No Assets in Selected Geographic Filter
          </div>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            No discovered assets matched the active geographic region or search filter criteria.
          </p>
          <button
            type="button"
            onClick={handleResetFilters}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-xs font-medium cursor-pointer"
          >
            Reset Geo Filters
          </button>
        </div>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/60 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="px-4 py-2.5 font-medium">Asset Identifier</th>
                  <th className="px-4 py-2.5 font-medium">Type</th>
                  <th className="px-4 py-2.5 font-medium">External / Resolved IP</th>
                  <th className="px-4 py-2.5 font-medium">Country of Origin</th>
                  <th className="px-4 py-2.5 font-medium">Geographic Region</th>
                  <th className="px-4 py-2.5 font-medium">Risk Tier</th>
                  <th className="px-4 py-2.5 font-medium text-right">Assessment</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {visibleRows.map((row) => {
                  const geo = row.geo;
                  return (
                    <tr
                      key={row.id}
                      onClick={() => onSelectAssessment(row.assessment.id)}
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                    >
                      <td className="px-4 py-2.5">
                        <div className="font-mono font-medium text-white group-hover:text-cyan-300 transition-colors break-all">
                          {row.asset.canonicalName}
                        </div>
                        <div className="text-[11px] text-slate-500 flex items-center gap-1.5">
                          <span>{row.assessment.scope?.rootDomain}</span>
                          <span aria-hidden="true">·</span>
                          <span>{row.asset.discoverySource}</span>
                        </div>
                      </td>

                      <td className="px-4 py-2.5 text-slate-300 whitespace-nowrap">
                        {ASSET_TYPE_LABELS[row.asset.assetType] || row.asset.assetType}
                      </td>

                      <td className="px-4 py-2.5 font-mono tabular-nums whitespace-nowrap">
                        {row.resolvedIp ? (
                          <span className={geo?.isExternal ? 'text-cyan-300' : 'text-slate-400'}>
                            {row.resolvedIp}
                          </span>
                        ) : (
                          <span className="text-slate-500">—</span>
                        )}
                      </td>

                      <td className="px-4 py-2.5">
                        {geo ? (
                          geo.isExternal ? (
                            <div>
                              <div className="text-white font-medium flex items-center gap-1.5 whitespace-nowrap">
                                <span className="font-mono text-cyan-400 font-semibold">
                                  {geo.countryCode}
                                </span>
                                <span aria-hidden="true" className="text-slate-600">
                                  ·
                                </span>
                                <span>{geo.country}</span>
                              </div>
                              {(geo.city || geo.isp) && (
                                <div className="text-[11px] text-slate-500 truncate max-w-[230px]">
                                  {[geo.city, geo.isp].filter(Boolean).join(' · ')}
                                </div>
                              )}
                            </div>
                          ) : (
                            <div>
                              <div className="text-slate-300 whitespace-nowrap">
                                Private / Lab Network
                              </div>
                              <div className="text-[11px] text-slate-500">
                                RFC1918 Internal Scope
                              </div>
                            </div>
                          )
                        ) : (
                          <span className="text-slate-500">No IP associated</span>
                        )}
                      </td>

                      <td className="px-4 py-2.5 text-slate-300 whitespace-nowrap">
                        {row.geoRegionLabel}
                      </td>

                      <td className="px-4 py-2.5 font-mono whitespace-nowrap capitalize">
                        <span className={`font-semibold ${SEVERITY_STYLES[row.severity]}`}>
                          {row.severity}
                        </span>
                      </td>

                      <td className="px-4 py-2.5 text-right whitespace-nowrap">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAssessment(row.assessment.id);
                          }}
                          className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 hover:underline cursor-pointer"
                        >
                          <span className="truncate max-w-[140px]">{row.assessment.name}</span>
                          <ExternalLink className="w-3 h-3 shrink-0" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {filteredRows.length > 15 && (
            <div className="px-4 py-2.5 bg-slate-900/40 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
              <span className="font-mono tabular-nums">
                Showing {visibleRows.length} of {filteredRows.length} matching assets
              </span>
              <button
                type="button"
                onClick={() => setShowAllRows((prev) => !prev)}
                className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-medium cursor-pointer"
              >
                {showAllRows ? (
                  <>
                    <span>Show Top 15</span>
                    <ChevronUp className="w-3.5 h-3.5" />
                  </>
                ) : (
                  <>
                    <span>Show All {filteredRows.length} Assets</span>
                    <ChevronDown className="w-3.5 h-3.5" />
                  </>
                )}
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
};
