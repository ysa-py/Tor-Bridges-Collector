export type TransportType = 'snowflake' | 'webtunnel' | 'obfs4' | 'meek_lite' | 'vanilla' | 'all';

export interface BridgeItem {
  id?: string;
  line: string;
  transport: TransportType;
  score: number;
  tested: boolean | null;
  first_seen: string;
  last_seen: string;
  latency_ms: number | null;
  score_reasons: string[];
  recommended_priority: 'high' | 'medium' | 'low';
  ip?: string;
  port?: number;
  fingerprint?: string;
}

export interface TransportStat {
  transport: string;
  success_rate: number;
  total_tested: number;
  working: number;
  blocked: number;
  weight: number;
  scorer_score: number;
  iran_dpi_resistance: string;
  survives_nic: boolean;
}

export interface DashboardSummary {
  timestamp: string;
  bridges: {
    total: number;
    tested: number;
    iran_reachable: number;
    nin_survival: number;
  };
  dpi: {
    threat_level: string;
    active_evasion: string;
    last_assessment: string | null;
  };
  gateway: {
    primary_provider: string;
    fallback_used: boolean;
    health_status: string;
  };
  pipeline: {
    run_id: string;
    duration_seconds: number;
    errors: number;
    warnings: number;
  };
}

export interface EvasionIntelligence {
  dpi_report: {
    threat_level: string;
    evasion_mode: string;
    ja3_rotation_active: boolean;
    ech_status: string;
    siam_resistance_score: number;
    quantum_shield: boolean;
  };
  model_metadata: {
    version: number;
    trained_at: string;
    samples: number;
    working: number;
    status: string;
  };
  nin_summary: {
    total_tested: number;
    nin_eligible: number;
    recommended_order: string[];
    pack_path: string;
    note: string;
  };
}

export interface TelemetryLog {
  timestamp: string;
  level: 'INFO' | 'WARN' | 'ERROR' | 'DEBUG';
  component: string;
  message: string;
  details?: Record<string, any>;
}

export interface DpiBlockingEvent {
  id: string;
  timestamp: string;
  probe_id: string;
  city: string;
  isp: string;
  asn: string;
  event_type: string;
  dpi_engine: string;
  target_bridge: string;
  mitigation: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'RESOLVED';
  latency_anomaly_ms?: number;
  latitude?: number;
  longitude?: number;
  dpi_risk_score?: number;
}

export interface ProbeTestResult {
  bridge_line: string;
  status: 'reachable' | 'blocked' | 'timeout' | 'invalid';
  latency_ms?: number;
  transport_detected: string;
  dpi_verdict: string;
  nin_bypass_capable: boolean;
  notes: string;
  checked_at: string;
}

export interface ExportPack {
  filename: string;
  name: string;
  description: string;
  count: number;
  updated_at: string;
  category: 'nin' | 'dpi' | 'general' | 'ech' | 'siam';
  download_url: string;
}
