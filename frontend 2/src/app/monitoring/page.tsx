"use client";

import React, { useState, useEffect, Suspense } from "react";
import Link from "next/link";
import { useSearchParams, useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import {
  GatewayResponseDTO,
  SensorResponseDTO,
  RegisterSensorResponseDTO,
  SensorHealthDTO,
  MonitoredSAStateDTO,
  MonitoringEventItemDTO,
} from "@/lib/api/types";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  CopyableValue,
} from "@/components/ui/table";
import { InspectorDrawer } from "@/components/ui/inspector-drawer";
import { Section } from "@/components/ui/section";
import { Tabs } from "@/components/ui/tabs";
import { Stat, StatGrid } from "@/components/ui/stat";
import { EmptyState } from "@/components/ui/empty-state";
import { Button, ButtonLink } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { StatusBadge } from "@/components/ui/badge";
import {
  Radio,
  Activity,
  Server,
  Cpu,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  PlusCircle,
  Copy,
  Check,
  Zap,
  GitBranch,
  Layers,
  ChevronRight,
  Eye,
  EyeOff,
  ExternalLink,
  FileKey2,
  X,
} from "lucide-react";

function MonitoringContent() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const searchParams = useSearchParams();

  // Navigation tab state
  const [activeTab, setActiveTab] = useState<"fleet" | "gateways" | "sensors" | "sa_states" | "timeline">("fleet");

  // Registration modal states
  const [isRegisterGwOpen, setIsRegisterGwOpen] = useState(false);
  const [isRegisterSensorOpen, setIsRegisterSensorOpen] = useState(false);
  const [issuedTokenModal, setIssuedTokenModal] = useState<RegisterSensorResponseDTO | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [showRawToken, setShowRawToken] = useState(false);
  const [showHistorical, setShowHistorical] = useState(false);

  // Inspector drawers
  const [selectedEvent, setSelectedEvent] = useState<MonitoringEventItemDTO | null>(null);
  const [selectedGatewayDetails, setSelectedGatewayDetails] = useState<GatewayResponseDTO | null>(null);

  // Gateway form state
  const [gwName, setGwName] = useState("");
  const [gwIp, setGwIp] = useState("");
  const [gwScope, setGwScope] = useState("");
  const [gwOperator, setGwOperator] = useState("operator-admin");
  const [gwAuthRef, setGwAuthRef] = useState("CHG-2026-MON-01");

  // Sensor form state
  const [sensorName, setSensorName] = useState("");
  const [sensorType, setSensorType] = useState<"GATEWAY_COLLECTOR" | "CAPTURE_SENSOR">("GATEWAY_COLLECTOR");
  const [sensorGwId, setSensorGwId] = useState("");
  const [sensorScope, setSensorScope] = useState("");
  const [sensorFreshness, setSensorFreshness] = useState(60);

  // Filter state for timeline & SAs
  const [filterEventKind, setFilterEventKind] = useState<string>("");
  const [filterGatewayId, setFilterGatewayId] = useState<string>("");
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [liveEventCount, setLiveEventCount] = useState<number>(0);

  // Initialize from URL search parameters if provided
  useEffect(() => {
    const tabParam = searchParams.get("tab");
    if (tabParam && ["fleet", "gateways", "sensors", "sa_states", "timeline"].includes(tabParam)) {
      setActiveTab(tabParam as any);
    }
    const gwParam = searchParams.get("gateway");
    if (gwParam) {
      setFilterGatewayId(gwParam);
    }
  }, [searchParams]);

  // ---------------------------------------------------------------------------
  // Queries
  // ---------------------------------------------------------------------------

  const { data: gateways = [], refetch: refetchGateways } = useQuery({
    queryKey: ["monitoring", "gateways"],
    queryFn: () => api.monitoring.listGateways(),
    refetchInterval: wsConnected ? 30000 : 10000,
  });

  const { data: sensors = [], refetch: refetchSensors } = useQuery({
    queryKey: ["monitoring", "sensors"],
    queryFn: () => api.monitoring.listSensors(),
    refetchInterval: wsConnected ? 30000 : 10000,
  });

  const { data: healthList = [], refetch: refetchHealth } = useQuery({
    queryKey: ["monitoring", "health"],
    queryFn: () => api.monitoring.getHealth(),
    refetchInterval: wsConnected ? 30000 : 5000,
  });

  const { data: saStates = [], refetch: refetchSAs } = useQuery({
    queryKey: ["monitoring", "sa-states", filterGatewayId],
    queryFn: () => api.monitoring.getSAStates(filterGatewayId || undefined),
    refetchInterval: wsConnected ? 30000 : 5000,
  });

  const { data: timelineData, refetch: refetchTimeline } = useQuery({
    queryKey: ["monitoring", "timeline", filterEventKind, filterGatewayId],
    queryFn: () => api.monitoring.getTimeline({
      gateway_id: filterGatewayId || undefined,
      event_kind: filterEventKind || undefined,
      limit: 100,
    }),
    refetchInterval: wsConnected ? 30000 : 10000,
  });

  // ---------------------------------------------------------------------------
  // WebSocket live telemetry subscription
  // ---------------------------------------------------------------------------

  useEffect(() => {
    let ws: WebSocket | null = null;
    let pingInterval: ReturnType<typeof setInterval> | null = null;
    let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
    let invalidationTimer: ReturnType<typeof setTimeout> | null = null;
    let isMounted = true;

    const triggerInvalidations = () => {
      if (invalidationTimer) return;
      invalidationTimer = setTimeout(() => {
        invalidationTimer = null;
        if (!isMounted) return;
        queryClient.invalidateQueries({ queryKey: ["monitoring", "health"] });
        queryClient.invalidateQueries({ queryKey: ["monitoring", "sa-states"] });
        queryClient.invalidateQueries({ queryKey: ["monitoring", "timeline"] });
      }, 300);
    };

    const connect = () => {
      if (!isMounted) return;
      try {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        let host = window.location.hostname + ":8002";
        if (process.env.NEXT_PUBLIC_API_URL) {
          try {
            host = new URL(process.env.NEXT_PUBLIC_API_URL).host;
          } catch {}
        }
        const wsUrl = process.env.NEXT_PUBLIC_WS_URL
          ? `${process.env.NEXT_PUBLIC_WS_URL.replace(/\/ws\/?$/, "").replace(/\/$/, "")}/monitoring/ws`
          : `${protocol}//${host}/api/v1/monitoring/ws`;
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          if (!isMounted) return;
          setWsConnected(true);
          pingInterval = setInterval(() => {
            if (ws && ws.readyState === WebSocket.OPEN) {
              ws.send("PING");
            }
          }, 15000);
        };

        ws.onmessage = (event) => {
          if (event.data === "PONG") return;
          try {
            const payload = JSON.parse(event.data);
            if (payload.type === "MONITORING_EVENT") {
              setLiveEventCount((prev) => prev + 1);
              triggerInvalidations();
            }
          } catch {
            // ignore non-json
          }
        };

        ws.onclose = () => {
          if (!isMounted) return;
          setWsConnected(false);
          if (pingInterval) clearInterval(pingInterval);
          reconnectTimeout = setTimeout(connect, 5000);
        };

        ws.onerror = () => {
          if (!isMounted) return;
          setWsConnected(false);
        };
      } catch {
        if (!isMounted) return;
        setWsConnected(false);
        reconnectTimeout = setTimeout(connect, 5000);
      }
    };

    connect();

    return () => {
      isMounted = false;
      if (pingInterval) clearInterval(pingInterval);
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (invalidationTimer) clearTimeout(invalidationTimer);
      if (ws) {
        ws.onopen = null;
        ws.onmessage = null;
        ws.onerror = null;
        ws.onclose = null;
        if (ws.readyState === WebSocket.OPEN) {
          ws.close();
        } else if (ws.readyState === WebSocket.CONNECTING) {
          ws.onopen = () => {
            try { ws?.close(); } catch {}
          };
        }
      }
    };
  }, [queryClient]);

  // ---------------------------------------------------------------------------
  // Mutations
  // ---------------------------------------------------------------------------

  const registerGatewayMutation = useMutation({
    mutationFn: (data: any) => api.monitoring.registerGateway(data),
    onSuccess: () => {
      refetchGateways();
      setIsRegisterGwOpen(false);
      setGwName("");
      setGwIp("");
      setGwScope("");
    },
  });

  const registerSensorMutation = useMutation({
    mutationFn: (data: any) => api.monitoring.registerSensor(data),
    onSuccess: (res: RegisterSensorResponseDTO) => {
      refetchSensors();
      refetchHealth();
      setIsRegisterSensorOpen(false);
      setIssuedTokenModal(res);
      setSensorName("");
      setSensorScope("");
    },
  });

  const revokeSensorMutation = useMutation({
    mutationFn: (sensorId: string) => api.monitoring.revokeSensor(sensorId),
    onSuccess: () => {
      refetchSensors();
      refetchHealth();
    },
  });

  const [pulseMessage, setPulseMessage] = useState<string | null>(null);

  const pulseMutation = useMutation({
    mutationFn: () => api.monitoring.triggerPulse(),
    onSuccess: () => {
      refetchGateways();
      refetchSensors();
      refetchHealth();
      refetchSAs();
      refetchTimeline();
      setPulseMessage("Live telemetry pulse sent! WebSocket broadcast received.");
      setTimeout(() => setPulseMessage(null), 4000);
    },
    onError: (err: any) => {
      setPulseMessage(`Failed to send pulse: ${err?.message || "Error"}`);
      setTimeout(() => setPulseMessage(null), 4000);
    },
  });

  // Calculate fleet stats
  const totalGateways = (gateways || []).length;
  const totalSensors = (sensors || []).length;
  const activeSensorsCount = (sensors || []).filter((s) => s.status === "ACTIVE").length;
  const revokedSensorsCount = (sensors || []).filter((s) => s.status === "REVOKED" || s.status === "DISABLED").length;
  const healthyCount = (healthList || []).filter((h) => h.current_health === "HEALTHY").length;
  const degradedCount = (healthList || []).filter((h) => h.current_health === "DEGRADED").length;
  const staleCount = (healthList || []).filter((h) => h.current_health === "STALE").length;
  const unknownCount = (healthList || []).filter((h) => h.current_health === "UNKNOWN").length;
  const activeSAsCount = (saStates || []).filter((sa) => sa.state === "ESTABLISHED" && !sa.is_stale).length;
  const staleSAsCount = (saStates || []).filter((sa) => sa.is_stale).length;

  const handleTabChange = (id: string) => {
    setActiveTab(id as any);
    router.replace(`/monitoring?tab=${id}`, { scroll: false });
  };

  const healthBadgeClass = (health: string) => {
    switch (health) {
      case "HEALTHY":
        return "bg-positive-bg text-positive border-positive-border";
      case "DEGRADED":
        return "bg-medium-bg text-medium border-medium-border";
      case "STALE":
        return "bg-high-bg text-high border-high-border";
      case "DISABLED":
      case "UNAVAILABLE":
        return "bg-critical-bg text-critical border-critical-border";
      default:
        return "bg-info-bg text-info border-info-border";
    }
  };

  const saBadgeClass = (sa: MonitoredSAStateDTO) => {
    if (sa.is_stale) return "bg-high-bg text-high border-high-border";
    if (sa.state === "ESTABLISHED") return "bg-positive-bg text-positive border-positive-border";
    if (sa.state === "REKEYED") return "bg-low-bg text-low border-low-border";
    return "bg-info-bg text-info border-info-border";
  };

  const sensorStatusClass = (status: string) =>
    status === "ACTIVE"
      ? "bg-positive-bg text-positive border-positive-border"
      : "bg-critical-bg text-critical border-critical-border";

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Page Header */}
      <div className="grid gap-4 border-b border-line pb-4 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end">
        <div className="min-w-0 space-y-1">
          <h1 className="text-xl font-semibold text-ink tracking-tight">
            {activeTab === "timeline" ? "Live Monitoring → Event Timeline" :
             activeTab === "gateways" ? "Live Monitoring → Gateway Registry" :
             activeTab === "sensors" ? "Live Monitoring → Sensor Fleet" :
             activeTab === "sa_states" ? "Live Monitoring → Projected SAs" :
             "Live Monitoring → Fleet Health & Freshness"}
          </h1>
          <p className="text-[13px] text-ink-2">
            Real-time IKE/IPsec state projections, sensor fleet health, and immutable audit telemetry.
          </p>
        </div>

        {/* Live WebSocket Status & Actions */}
        <div className="flex items-center gap-2">
          <div
            role="status"
            aria-live="polite"
            className="flex h-9 min-w-[8.5rem] shrink-0 items-center justify-center gap-2 border border-line bg-panel px-2.5 font-mono text-[.62rem] leading-tight"
          >
            <span
              className={`w-2 h-2 ${
                wsConnected
                  ? healthyCount > 0
                    ? "bg-positive"
                    : "bg-medium"
                  : "bg-ink-3"
              }`}
            />
            <span
              className={
                wsConnected
                  ? healthyCount > 0
                    ? "text-positive min-w-0 text-center font-semibold leading-tight"
                    : "text-medium min-w-0 text-center font-semibold leading-tight"
                  : "text-ink-3 min-w-0 text-center leading-tight"
              }
            >
              {wsConnected
                ? healthyCount > 0
                  ? `LIVE STREAMING (${liveEventCount})`
                  : `WS CONNECTED · SENSORS STALE (${liveEventCount})`
                : "POLLING LOOP (10s)"}
            </span>
          </div>

          <Button
            variant="primary"
            size="sm"
            onClick={() => pulseMutation.mutate()}
            disabled={pulseMutation.isPending}
            title="Send genuine heartbeat and IKE SA telemetry events to verify live WebSocket streaming"
          >
            <Zap className={`w-3.5 h-3.5 ${pulseMutation.isPending ? "animate-spin" : ""}`} />
            <span>{pulseMutation.isPending ? "SENDING…" : "TEST LIVE PULSE"}</span>
          </Button>

          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              refetchGateways();
              refetchSensors();
              refetchHealth();
              refetchSAs();
              refetchTimeline();
            }}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Architecture Disclosure: Live Telemetry vs Live Packet Capture */}
      <div className="border border-line bg-panel-2 p-4 space-y-3">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-ink">
            <ShieldCheck className="w-4 h-4 text-accent" />
            <span>Continuous Telemetry vs. Live Packet Capture</span>
          </div>
          <span className="text-[11px] font-mono uppercase tracking-wide text-ink-3 whitespace-nowrap">
            RFC 7296 / NTRO Audit Disclosure
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-[13px] text-ink-2 leading-relaxed">
          <div>
            <span className="font-semibold text-ink block mb-1">Live Monitoring (Stream Active):</span>
            Ingests authenticated heartbeat telemetry, health metrics, and projected IPsec Security Association states from distributed gateway collectors over WebSocket/REST APIs. Retains verifiable historical state transitions without artificial synthetic data.
          </div>
          <div>
            <span className="font-semibold text-ink block mb-1">Live Packet Capture (Host Requirements):</span>
            Direct raw packet capture requires the privileged Linux Capture Daemon running with kernel <code className="bg-panel-3 px-1 py-0.5 font-mono font-semibold">CAP_NET_ADMIN</code> / eBPF / strongSwan XFRM access. Windows development hosts operate in offline PCAP forensics mode and receive remote sensor telemetry.
          </div>
        </div>
      </div>

      {/* Pulse Feedback Banner */}
      {pulseMessage && (
        <div role="status" className="flex items-center justify-between gap-3 border border-positive-border bg-positive-bg px-3 py-2.5 text-xs font-mono text-positive">
          <div className="flex items-center gap-2 font-semibold">
            <Check className="w-4 h-4" />
            <span>{pulseMessage}</span>
          </div>
          <button onClick={() => setPulseMessage(null)} className="text-ink-3 hover:text-ink" aria-label="Dismiss notification">×</button>
        </div>
      )}

      {/* Telemetry Freshness & Setup Warning Banner */}
      {healthyCount === 0 && (
        <div role="status" className="border border-medium-border bg-medium-bg p-4 space-y-3">
          <div className="flex items-center gap-2 font-semibold text-medium">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Telemetry Inactive: No Gateway Currently Connected</span>
          </div>
          <p className="text-[13px] leading-relaxed text-ink-2">
            {staleCount > 0
              ? `${staleCount} registered sensor(s) have exceeded the 60-second freshness heartbeat threshold. Feeds are currently dormant.`
              : "No telemetry sensors are currently reporting to the TunnelTrace API. The browser WebSocket is connected, waiting for gateway heartbeats."}
            {" "}Projected SA records shown below represent retained historical states under the non-deletion invariant; they do not indicate currently established live tunnels.
          </p>
          <div className="border border-line bg-panel-3 p-3 space-y-1">
            <div className="text-[11px] text-ink-3">Launch standalone collector on your strongSwan / Linux router:</div>
            <code className="block select-all font-mono text-xs text-positive">
              python scripts/gateway_collector.py --gateway &quot;edge-router&quot; --interface eth0
            </code>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-[13px]">
            <span className="font-semibold text-ink">Alternative:</span>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setIsRegisterGwOpen(true)}
            >
              <PlusCircle className="w-3.5 h-3.5" />
              Register Gateway
            </Button>
            <button
              onClick={() => {
                setActiveTab("sensors");
                router.replace("/monitoring?tab=sensors", { scroll: false });
              }}
              className="font-semibold text-accent-ink underline hover:text-accent-press dark:hover:text-accent"
            >
              Register a new sensor token in Sensor Fleet →
            </button>
          </div>
        </div>
      )}

      {/* Fleet Health Stats */}
      <StatGrid className="lg:grid-cols-6">
        <Stat label="Monitored Gateways" value={totalGateways} hint="Bound boundaries" />
        <Stat
          label="Sensors Active"
          value={activeSensorsCount}
          hint={revokedSensorsCount > 0 ? `${revokedSensorsCount} revoked/disabled` : `${totalSensors} total collectors`}
        />
        <Stat label="Healthy Sensors" value={healthyCount} tone="positive" hint="0 drops / 0 gaps" />
        <Stat
          label="Stale / Degraded"
          value={staleCount + degradedCount}
          tone="medium"
          hint={`${staleCount} stale, ${degradedCount} degraded`}
        />
        <Stat
          label="Established SAs"
          value={activeSAsCount}
          tone="low"
          hint={activeSAsCount > 0 ? "Live IPsec tunnels" : "0 active tunnels observed"}
        />
        <Stat label="Historical SAs (Retained)" value={staleSAsCount} tone="info" hint="Past observed states" />
      </StatGrid>

      {/* Tabs Navigation */}
      <Tabs
        active={activeTab}
        onChange={handleTabChange}
        items={[
          { id: "fleet", label: "Fleet Health & Freshness" },
          { id: "sa_states", label: "Projected SAs", count: saStates.length },
          { id: "timeline", label: "Event Timeline" },
          { id: "gateways", label: "Gateways", count: gateways.length },
          { id: "sensors", label: "Sensors", count: sensors.length },
        ]}
      />

      {/* TAB 1: FLEET HEALTH & FRESHNESS */}
      {activeTab === "fleet" && (
        <Section
          index="§1"
          title="Sensor Fleet Telemetry Freshness"
          actions={
            <Button variant="primary" size="sm" onClick={() => setIsRegisterSensorOpen(true)}>
              <PlusCircle className="w-3.5 h-3.5" />
              Register Sensor
            </Button>
          }
        >
          {!healthList.some((h) => h.current_health === "HEALTHY") && !showHistorical ? (
            <div className="space-y-4">
              <EmptyState
                icon={<Radio />}
                title="No Gateway Currently Connected"
                description="Continuous monitoring requires an active strongSwan gateway streaming live telemetry over WebSockets. No active probes are currently transmitting fresh observations."
                action={
                  <div className="flex flex-wrap items-center justify-center gap-2">
                    <Button variant="primary" size="sm" onClick={() => setIsRegisterGwOpen(true)}>
                      <PlusCircle className="w-3.5 h-3.5" />
                      Register Gateway
                    </Button>
                    <Button variant="secondary" size="sm" onClick={() => setIsRegisterSensorOpen(true)}>
                      <PlusCircle className="w-3.5 h-3.5" />
                      Register Sensor
                    </Button>
                  </div>
                }
              />
              <div className="max-w-xl mx-auto w-full border border-line bg-panel-3 p-3 space-y-1.5">
                <div className="text-[11px] font-semibold text-ink-2 uppercase tracking-wide">
                  Deploy Collector on strongSwan Gateway (5-Minute Setup):
                </div>
                <div className="flex items-center justify-between gap-2 bg-ground border border-line px-2.5 py-2 font-mono text-xs select-all">
                  <code className="text-positive">python scripts/gateway_collector.py --gateway-url http://localhost:8002</code>
                  <CopyableValue value="python scripts/gateway_collector.py --gateway-url http://localhost:8002" label="Collector command" />
                </div>
              </div>
              {healthList.length > 0 && (
                <div className="pt-1 text-center">
                  <button
                    onClick={() => setShowHistorical(true)}
                    className="text-xs font-mono text-accent-ink hover:underline inline-flex items-center gap-1"
                  >
                    <span>View historical retained observations ({healthList.length})</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              {!healthList.some((h) => h.current_health === "HEALTHY") && (
                <div className="flex items-center justify-between gap-3 border border-medium-border bg-medium-bg px-3 py-2.5 text-xs font-mono text-medium">
        <div className="flex flex-wrap items-center gap-2 lg:justify-end">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span>Viewing historical retained observations (no gateway actively streaming).</span>
                  </div>
                  <button
                    onClick={() => setShowHistorical(false)}
                    className="text-[11px] font-bold text-ink hover:underline"
                  >
                    Hide Historical
                  </button>
                </div>
              )}
              {healthList.length === 0 ? (
                <EmptyState
                  icon={<Radio />}
                  title="No Sensors Registered"
                  description="No sensors registered yet. Register a sensor to attach telemetry collectors."
                  action={
                    <Button variant="primary" size="sm" onClick={() => setIsRegisterSensorOpen(true)}>
                      <PlusCircle className="w-3.5 h-3.5" />
                      Register Sensor
                    </Button>
                  }
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Sensor</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Gateway Boundary</TableHead>
                      <TableHead>Health State</TableHead>
                      <TableHead>Freshness & Latency</TableHead>
                      <TableHead>Drops / Gaps</TableHead>
                      <TableHead>Last Observation</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {healthList.map((h) => {
                      const isDisabled = h.current_health === "DISABLED" || h.current_health === "UNAVAILABLE";

                      return (
                        <TableRow key={h.sensor_id}>
                          <TableCell mono className="font-semibold text-ink">
                            {h.sensor_name}
                          </TableCell>
                          <TableCell mono className="text-ink-3">
                            {h.sensor_type}
                          </TableCell>
                          <TableCell mono>
                            <div>{h.gateway_name}</div>
                            <div className="text-[11px] text-ink-3">{h.authorized_scope}</div>
                          </TableCell>
                          <TableCell>
                            <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-[11px] font-mono uppercase font-semibold border ${healthBadgeClass(h.current_health)}`}>
                              <span className="w-1.5 h-1.5 bg-current" />
                              {h.current_health}
                            </span>
                            <div className="text-[11px] text-ink-3 mt-1 max-w-xs truncate">
                              {h.health_reason}
                            </div>
                          </TableCell>
                          <TableCell mono>
                            <div>Window: {h.freshness_window_seconds}s</div>
                            <div className="text-[11px] text-ink-3">
                              Skew: {h.clock_skew_seconds > 0 ? `+${h.clock_skew_seconds.toFixed(2)}s` : `${h.clock_skew_seconds.toFixed(2)}s`}
                            </div>
                          </TableCell>
                          <TableCell mono>
                            <div className={h.total_drops_reported > 0 ? "text-medium font-semibold" : "text-ink-3"}>
                              Drops: {h.total_drops_reported}
                            </div>
                            <div className={h.sequence_gaps_count > 0 ? "text-medium font-semibold" : "text-ink-3"}>
                              Gaps: {h.sequence_gaps_count}
                            </div>
                          </TableCell>
                          <TableCell mono className="text-ink-3">
                            {h.last_received_at ? new Date(h.last_received_at).toLocaleTimeString() : "Never"}
                          </TableCell>
                          <TableCell className="text-right">
                            <button
                              onClick={() => revokeSensorMutation.mutate(h.sensor_id)}
                              disabled={isDisabled}
                              className="px-2 py-1 text-xs font-mono text-critical hover:bg-critical-bg disabled:opacity-30"
                            >
                              Revoke
                            </button>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              )}
            </div>
          )}
        </Section>
      )}
      {/* TAB 2: PROJECTED SECURITY ASSOCIATIONS (NON-DELETION INVARIANT) */}
      {activeTab === "sa_states" && (
        <Section
          index="§2"
          title="Active & Retained Security Association Projections"
          description="Rebuildable projections of active IKE and Child SAs. Under sensor staleness, SAs are retained with warning, never deleted."
        >
          {saStates.length === 0 ? (
            <EmptyState
              fill
              icon={<GitBranch />}
              title="No Security Associations Currently Projected"
              description="Telemetry from IKE daemons will populate active tunnels here."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Gateway / Type</TableHead>
                  <TableHead>Initiator SPI / Child In</TableHead>
                  <TableHead>Responder SPI / Child Out</TableHead>
                  <TableHead>Endpoints</TableHead>
                  <TableHead>Cipher Suite</TableHead>
                  <TableHead>Lifecycle State</TableHead>
                  <TableHead>Last Event At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {saStates.map((sa) => {
                  const isStale = sa.is_stale;

                  return (
                    <TableRow key={sa.id} className={isStale ? "bg-high-bg" : ""}>
                      <TableCell mono>
                        <div className="font-semibold text-ink">{sa.gateway_name}</div>
                        <div className="text-[11px] text-ink-3 uppercase">{sa.sa_type}</div>
                      </TableCell>
                      <TableCell mono>
                        <CopyableValue value={sa.initiator_spi} label={sa.initiator_spi} />
                        {sa.child_spi_in && (
                          <div className="text-[11px] text-ink-3 mt-0.5">
                            In: {sa.child_spi_in}
                          </div>
                        )}
                      </TableCell>
                      <TableCell mono>
                        {sa.responder_spi ? (
                          <CopyableValue value={sa.responder_spi} label={sa.responder_spi} />
                        ) : (
                          <span className="text-ink-3">—</span>
                        )}
                        {sa.child_spi_out && (
                          <div className="text-[11px] text-ink-3 mt-0.5">
                            Out: {sa.child_spi_out}
                          </div>
                        )}
                      </TableCell>
                      <TableCell mono>
                        <div>{sa.local_endpoint || "0.0.0.0"}</div>
                        <div className="text-[11px] text-ink-3">↔ {sa.remote_endpoint || "0.0.0.0"}</div>
                      </TableCell>
                      <TableCell mono className="text-ink-2">
                        {sa.cipher_suite || "Unknown"}
                      </TableCell>
                      <TableCell>
                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-[11px] font-mono uppercase font-semibold border ${saBadgeClass(sa)}`}>
                          <span className="w-1.5 h-1.5 bg-current" />
                          {isStale ? "STALE (RETAINED)" : sa.state}
                        </span>
                        {isStale && (
                          <div className="text-[11px] text-high mt-1 max-w-xs truncate">
                            {sa.staleness_reason || "Heartbeat timeout"}
                          </div>
                        )}
                      </TableCell>
                      <TableCell mono className="text-ink-3">
                        {new Date(sa.last_event_at).toLocaleTimeString()}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </Section>
      )}

      {/* TAB 3: IMMUTABLE AUDIT TIMELINE */}
      {activeTab === "timeline" && (
        <Section
          index="§3"
          title="Immutable Telemetry Event Stream"
          description="Append-only evidence log ingested from authorized telemetry sensors."
          actions={
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1.5">
                <label htmlFor="timeline-filter-gateway" className="text-xs font-mono text-ink-3">Gateway:</label>
                <Select
                  id="timeline-filter-gateway"
                  value={filterGatewayId}
                  onChange={(e) => setFilterGatewayId(e.target.value)}
                  className="w-44"
                >
                  <option value="">All Gateways</option>
                  {gateways.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name} ({g.gateway_ip})
                    </option>
                  ))}
                </Select>
              </div>

              <div className="flex items-center gap-1.5">
                <label htmlFor="timeline-filter-kind" className="text-xs font-mono text-ink-3">Kind:</label>
                <Select
                  id="timeline-filter-kind"
                  value={filterEventKind}
                  onChange={(e) => setFilterEventKind(e.target.value)}
                  className="w-56"
                >
                  <option value="">All Events</option>
                  <option value="GATEWAY_IKE_SA_ESTABLISHED">GATEWAY_IKE_SA_ESTABLISHED</option>
                  <option value="GATEWAY_IKE_SA_FAILED">GATEWAY_IKE_SA_FAILED</option>
                  <option value="GATEWAY_CHILD_SA_ESTABLISHED">GATEWAY_CHILD_SA_ESTABLISHED</option>
                  <option value="GATEWAY_CHILD_SA_REKEYED">GATEWAY_CHILD_SA_REKEYED</option>
                  <option value="GATEWAY_CHILD_SA_DELETED">GATEWAY_CHILD_SA_DELETED</option>
                  <option value="GATEWAY_HEARTBEAT">GATEWAY_HEARTBEAT</option>
                  <option value="CAPTURE_DROPS_RECORDED">CAPTURE_DROPS_RECORDED</option>
                  <option value="CAPTURE_FAILED">CAPTURE_FAILED</option>
                </Select>
              </div>

              {(filterGatewayId || filterEventKind) && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setFilterGatewayId("");
                    setFilterEventKind("");
                  }}
                >
                  Reset Filters
                </Button>
              )}
            </div>
          }
        >
          {!timelineData || timelineData.items.length === 0 ? (
            <EmptyState
              icon={<Layers />}
              title="No events recorded matching current filters"
              description="Sensors remain active and listening. This reflects an absence of state transitions in the query window, not a telemetry failure."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Source Time (UTC)</TableHead>
                  <TableHead>Event Kind</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Initiator SPI / Interface</TableHead>
                  <TableHead>Packets / Drops</TableHead>
                  <TableHead>Raw Reason / Detail</TableHead>
                  <TableHead className="text-right">Inspect</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {timelineData.items.map((item) => {
                  const isFailure = item.event_kind.includes("FAILED");
                  const isDrop = item.event_kind.includes("DROPS");
                  return (
                    <TableRow key={item.id} className={isFailure ? "bg-critical-bg" : ""}>
                      <TableCell mono className="text-ink-3">
                        {new Date(item.source_timestamp).toISOString().replace("T", " ").substring(0, 19)}
                      </TableCell>
                      <TableCell mono className="font-semibold">
                        <span
                          className={
                            isFailure
                              ? "text-critical"
                              : isDrop
                              ? "text-medium"
                              : "text-ink"
                          }
                        >
                          {item.event_kind}
                        </span>
                      </TableCell>
                      <TableCell mono className="text-ink-3">
                        {item.authorized_scope}
                      </TableCell>
                      <TableCell mono>
                        {item.initiator_spi ? (
                          <CopyableValue value={item.initiator_spi} label={item.initiator_spi} />
                        ) : (
                          item.interface_name || "—"
                        )}
                      </TableCell>
                      <TableCell mono>
                        {item.packet_count !== null && item.packet_count !== undefined ? (
                          <div>Pkts: {item.packet_count}</div>
                        ) : null}
                        {item.drop_count !== null && item.drop_count !== undefined && item.drop_count > 0 ? (
                          <div className="text-medium font-semibold">Drops: {item.drop_count}</div>
                        ) : null}
                        {item.packet_count === null && item.drop_count === null && "—"}
                      </TableCell>
                      <TableCell mono className="text-ink-3 max-w-xs truncate">
                        {item.failure_reason || item.raw_source_status || item.cipher_suite || "—"}
                      </TableCell>
                      <TableCell className="text-right">
                        <button
                          onClick={() => setSelectedEvent(item)}
                          className="p-1 text-ink-3 hover:text-ink"
                          aria-label="Inspect event"
                          title="Inspect event"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </Section>
      )}

      {/* TAB 4: AUTHORIZED GATEWAYS */}
      {activeTab === "gateways" && (
        <Section
          index="§4"
          title="Authorized VPN Gateway Boundaries"
          description="Approved network boundaries with operator attestation and authorization references."
          actions={
            <Button variant="primary" size="sm" onClick={() => setIsRegisterGwOpen(true)}>
              <PlusCircle className="w-3.5 h-3.5" />
              Register Gateway
            </Button>
          }
        >
          {gateways.length === 0 ? (
            <EmptyState
              icon={<Server />}
              title="No Authorized Gateways Configured"
              description="Register a gateway to authorize an IPsec boundary for monitoring."
              action={
                <Button variant="primary" size="sm" onClick={() => setIsRegisterGwOpen(true)}>
                  <PlusCircle className="w-3.5 h-3.5" />
                  Register Gateway
                </Button>
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Gateway Name</TableHead>
                  <TableHead>Primary IP</TableHead>
                  <TableHead>Authorized Scope</TableHead>
                  <TableHead>Operator</TableHead>
                  <TableHead>Authorization Ref</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Registered At</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {gateways.map((gw) => (
                  <TableRow
                    key={gw.id}
                    onClick={() => setSelectedGatewayDetails(gw)}
                  >
                    <TableCell mono className="font-semibold">
                      <div className="flex items-center gap-1.5">
                        <Server className="w-3.5 h-3.5 text-accent" />
                        <span>{gw.name}</span>
                      </div>
                    </TableCell>
                    <TableCell mono>
                      <CopyableValue value={gw.gateway_ip} label={gw.gateway_ip} />
                    </TableCell>
                    <TableCell mono className="text-ink-3">
                      {gw.authorized_scope}
                    </TableCell>
                    <TableCell mono className="text-ink-3">
                      {gw.operator_id}
                    </TableCell>
                    <TableCell mono className="text-ink-3">
                      {gw.authorization_reference}
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={gw.status} />
                    </TableCell>
                    <TableCell mono className="text-ink-3">
                      {new Date(gw.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => setSelectedGatewayDetails(gw)}
                      >
                        <Eye className="w-3.5 h-3.5" />
                        Inspect
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Section>
      )}

      {/* TAB 5: SENSOR FLEET REGISTRY */}
      {activeTab === "sensors" && (
        <Section
          index="§5"
          title="Registered Telemetry Sensors & Collectors"
          description="Sensor authentication credentials and bound scopes. Tokens are hashed with SHA-256 upon issuance."
          actions={
            <Button variant="primary" size="sm" onClick={() => setIsRegisterSensorOpen(true)}>
              <PlusCircle className="w-3.5 h-3.5" />
              Register Sensor
            </Button>
          }
        >
          {sensors.length === 0 ? (
            <EmptyState
              icon={<Cpu />}
              title="No Sensors Registered"
              description="Register a sensor to issue a collector credential."
              action={
                <Button variant="primary" size="sm" onClick={() => setIsRegisterSensorOpen(true)}>
                  <PlusCircle className="w-3.5 h-3.5" />
                  Register Sensor
                </Button>
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Sensor Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Token Prefix</TableHead>
                  <TableHead>Bound Scope</TableHead>
                  <TableHead>Freshness Window</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sensors.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell mono className="font-semibold text-ink">
                      {s.sensor_name}
                    </TableCell>
                    <TableCell mono className="text-ink-3">
                      {s.sensor_type}
                    </TableCell>
                    <TableCell mono className="text-ink-3">
                      {s.token_prefix}
                    </TableCell>
                    <TableCell mono className="text-ink-3">
                      {s.authorized_scope}
                    </TableCell>
                    <TableCell mono>
                      {s.freshness_window_seconds}s
                    </TableCell>
                    <TableCell>
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-mono uppercase font-semibold border ${sensorStatusClass(s.status)}`}>
                        <span className="w-1.5 h-1.5 bg-current" />
                        {s.status}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      {s.status === "ACTIVE" ? (
                        <button
                          onClick={() => revokeSensorMutation.mutate(s.id)}
                          className="px-2 py-1 text-xs font-mono text-critical hover:bg-critical-bg"
                        >
                          Revoke
                        </button>
                      ) : (
                        <span className="text-[11px] font-mono text-ink-3">Revoked</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Section>
      )}
      {/* MODAL: REGISTER GATEWAY */}
      {isRegisterGwOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-md border border-line bg-panel p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-line pb-3">
              <h3 className="text-sm font-semibold text-ink">
                Register Authorized VPN Gateway
              </h3>
              <button
                onClick={() => setIsRegisterGwOpen(false)}
                className="text-ink-3 hover:text-ink"
                aria-label="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3">
              <Field label="Gateway Name">
                <Input
                  value={gwName}
                  onChange={(e) => setGwName(e.target.value)}
                  placeholder="e.g. DC-Gateway-Primary"
                  mono
                />
              </Field>

              <Field label="Primary IP Address">
                <Input
                  value={gwIp}
                  onChange={(e) => setGwIp(e.target.value)}
                  placeholder="e.g. 198.51.100.1"
                  mono
                />
              </Field>

              <Field label="Authorized CIDR Scope">
                <Input
                  value={gwScope}
                  onChange={(e) => setGwScope(e.target.value)}
                  placeholder="e.g. 198.51.100.0/24"
                  mono
                />
              </Field>

              <Field label="Authorization Reference">
                <Input
                  value={gwAuthRef}
                  onChange={(e) => setGwAuthRef(e.target.value)}
                  placeholder="e.g. CHG-2026-MON-01"
                  mono
                />
              </Field>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-line">
              <Button variant="secondary" size="sm" onClick={() => setIsRegisterGwOpen(false)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={() =>
                  registerGatewayMutation.mutate({
                    name: gwName,
                    gateway_ip: gwIp,
                    authorized_scope: gwScope,
                    operator_id: gwOperator,
                    authorization_reference: gwAuthRef,
                  })
                }
                disabled={!gwName || !gwIp || !gwScope || registerGatewayMutation.isPending}
              >
                {registerGatewayMutation.isPending ? "Registering…" : "Confirm Gateway"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: REGISTER SENSOR */}
      {isRegisterSensorOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-md border border-line bg-panel p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-line pb-3">
              <h3 className="text-sm font-semibold text-ink">
                Register Telemetry Sensor
              </h3>
              <button
                onClick={() => setIsRegisterSensorOpen(false)}
                className="text-ink-3 hover:text-ink"
                aria-label="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3">
              <Field label="Sensor Name">
                <Input
                  value={sensorName}
                  onChange={(e) => setSensorName(e.target.value)}
                  placeholder="e.g. collector-dc-swanctl"
                  mono
                />
              </Field>

              <Field label="Target Gateway">
                <Select
                  value={sensorGwId}
                  onChange={(e) => {
                    setSensorGwId(e.target.value);
                    const selected = gateways.find((g) => g.id === e.target.value);
                    if (selected) setSensorScope(selected.authorized_scope);
                  }}
                >
                  <option value="">Select bound gateway…</option>
                  {gateways.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name} ({g.gateway_ip})
                    </option>
                  ))}
                </Select>
              </Field>

              <Field label="Sensor Type">
                <Select
                  value={sensorType}
                  onChange={(e) => setSensorType(e.target.value as any)}
                >
                  <option value="GATEWAY_COLLECTOR">GATEWAY_COLLECTOR (Daemon IKE/Child SAs)</option>
                  <option value="CAPTURE_SENSOR">CAPTURE_SENSOR (PCAP & Drop Probes)</option>
                </Select>
              </Field>

              <Field label="Bound Scope">
                <Input
                  value={sensorScope}
                  onChange={(e) => setSensorScope(e.target.value)}
                  placeholder="Must match gateway scope exactly"
                  mono
                />
              </Field>

              <Field label="Freshness Window (seconds)">
                <Input
                  type="number"
                  value={sensorFreshness}
                  onChange={(e) => setSensorFreshness(Number(e.target.value))}
                  min={10}
                  max={86400}
                  mono
                />
              </Field>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-line">
              <Button variant="secondary" size="sm" onClick={() => setIsRegisterSensorOpen(false)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={() =>
                  registerSensorMutation.mutate({
                    sensor_name: sensorName,
                    sensor_type: sensorType,
                    gateway_id: sensorGwId,
                    authorized_scope: sensorScope,
                    freshness_window_seconds: sensorFreshness,
                  })
                }
                disabled={!sensorName || !sensorGwId || !sensorScope || registerSensorMutation.isPending}
              >
                {registerSensorMutation.isPending ? "Registering…" : "Issue Sensor Token"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: SENSOR TOKEN ISSUED (DISPLAYED ONCE) */}
      {issuedTokenModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4">
          <div className="w-full max-w-lg border border-medium-border bg-panel p-5 space-y-4">
            <div className="flex items-center gap-2 text-medium">
              <AlertTriangle className="w-5 h-5" />
              <h3 className="text-sm font-semibold">
                Sensor Authentication Credential Issued
              </h3>
            </div>

            <p className="text-xs text-ink-2 font-mono">
              Save this authentication token now. For zero-trust security, this token is hashed with SHA-256 and will{" "}
              <strong className="text-medium">never be displayed again</strong>.
            </p>

            <div className="border border-line bg-panel-3 font-mono text-xs break-all flex items-center justify-between gap-3 p-3">
              <span className="text-accent-ink font-semibold">
                {showRawToken
                  ? issuedTokenModal.raw_token
                  : issuedTokenModal.raw_token.slice(0, 8) + "••••••••••••••••" + issuedTokenModal.raw_token.slice(-6)}
              </span>
              <div className="flex items-center gap-1 shrink-0">
                <button
                  type="button"
                  onClick={() => setShowRawToken(!showRawToken)}
                  title={showRawToken ? "Hide token" : "Show token"}
                  aria-label={showRawToken ? "Hide token" : "Show token"}
                  className="p-1.5 text-ink-3 hover:text-ink"
                >
                  {showRawToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(issuedTokenModal.raw_token);
                    setCopiedToken(true);
                    setTimeout(() => setCopiedToken(false), 3000);
                  }}
                  title="Copy full token"
                  aria-label="Copy full token"
                  className="p-1.5 text-ink-3 hover:text-ink"
                >
                  {copiedToken ? <Check className="w-4 h-4 text-positive" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div className="text-[11px] text-ink-3 font-mono space-y-1">
              <div>Sensor: {issuedTokenModal.sensor_name}</div>
              <div>Scope: {issuedTokenModal.authorized_scope}</div>
              <div>Header: <code>X-Sensor-Token: {showRawToken ? issuedTokenModal.raw_token : "••••••••••••••••"}</code></div>
            </div>

            <div className="flex justify-end pt-3 border-t border-line">
              <Button
                variant="primary"
                size="sm"
                onClick={() => setIssuedTokenModal(null)}
              >
                I Have Securely Saved This Token
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* DRAWER: INSPECT EVENT DETAILS */}
      {selectedEvent && (
        <InspectorDrawer
          isOpen={true}
          onClose={() => setSelectedEvent(null)}
          title="Telemetry Event Inspector"
          subtitle={`Event ID: ${selectedEvent.event_id}`}
        >
          <div className="space-y-4 font-mono text-xs">
            <div className="space-y-1">
              <div className="text-ink-3">Event Kind</div>
              <div className="font-semibold text-ink">
                {selectedEvent.event_kind}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <div className="text-ink-3">Schema Version</div>
                <div>{selectedEvent.schema_version}</div>
              </div>
              <div>
                <div className="text-ink-3">Evidence Grade</div>
                <div>{selectedEvent.evidence_grade}</div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <div className="text-ink-3">Source Timestamp</div>
                <div>{selectedEvent.source_timestamp}</div>
              </div>
              <div>
                <div className="text-ink-3">Received At (Server)</div>
                <div>{selectedEvent.received_at}</div>
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-ink-3">Clock Skew</div>
              <div>{selectedEvent.clock_skew_seconds.toFixed(3)} seconds</div>
            </div>

            {selectedEvent.initiator_spi && (
              <div className="space-y-1">
                <div className="text-ink-3">Initiator SPI</div>
                <CopyableValue value={selectedEvent.initiator_spi} label={selectedEvent.initiator_spi} />
              </div>
            )}

            {selectedEvent.responder_spi && (
              <div className="space-y-1">
                <div className="text-ink-3">Responder SPI</div>
                <CopyableValue value={selectedEvent.responder_spi} label={selectedEvent.responder_spi} />
              </div>
            )}

            {selectedEvent.cipher_suite && (
              <div className="space-y-1">
                <div className="text-ink-3">Cipher Suite</div>
                <div>{selectedEvent.cipher_suite}</div>
              </div>
            )}

            {selectedEvent.failure_reason && (
              <div className="border border-critical-border bg-critical-bg text-critical p-3">
                <div className="font-semibold mb-1">Failure Reason</div>
                <div>{selectedEvent.failure_reason}</div>
              </div>
            )}

            {selectedEvent.raw_source_status && (
              <div className="space-y-1">
                <div className="text-ink-3">Raw Source Log / Status</div>
                <pre className="border border-line bg-panel-3 p-3 text-[11px] overflow-x-auto whitespace-pre-wrap">
                  {selectedEvent.raw_source_status}
                </pre>
              </div>
            )}

            {/* Quick cross-flow links */}
            <div className="pt-2 border-t border-line space-y-1.5">
              <span className="text-[11px] text-ink-3 uppercase font-semibold block">Cross-Flow Forensics</span>
              <div className="flex gap-2">
                <ButtonLink
                  href="/inventory"
                  variant="secondary"
                  size="sm"
                  className="flex-1"
                >
                  <FileKey2 className="w-3 h-3 text-low" />
                  <span>Config Inventory</span>
                </ButtonLink>
                <ButtonLink
                  href="/analyses"
                  variant="secondary"
                  size="sm"
                  className="flex-1"
                >
                  <Activity className="w-3 h-3 text-accent" />
                  <span>Forensic Analyses</span>
                </ButtonLink>
              </div>
            </div>
          </div>
        </InspectorDrawer>
      )}

      {/* DRAWER: INSPECT GATEWAY DETAILS & WORKFLOW TRANSITIONS */}
      {selectedGatewayDetails && (
        <InspectorDrawer
          isOpen={true}
          onClose={() => setSelectedGatewayDetails(null)}
          title={`Authorized Gateway: ${selectedGatewayDetails.name}`}
          subtitle={`IP: ${selectedGatewayDetails.gateway_ip}`}
          badge={<StatusBadge status={selectedGatewayDetails.status} />}
        >
          <div className="space-y-4 font-mono text-xs">
            {/* Properties */}
            <div className="grid grid-cols-2 gap-2 p-3 border border-line bg-panel-2">
              <div>
                <span className="text-ink-3 text-[11px] block">Primary IP</span>
                <CopyableValue value={selectedGatewayDetails.gateway_ip} label="IP" />
              </div>
              <div>
                <span className="text-ink-3 text-[11px] block">Operator ID</span>
                <span className="font-semibold">{selectedGatewayDetails.operator_id}</span>
              </div>
              <div>
                <span className="text-ink-3 text-[11px] block">Authorized Scope</span>
                <span className="font-semibold text-positive">
                  {selectedGatewayDetails.authorized_scope}
                </span>
              </div>
              <div>
                <span className="text-ink-3 text-[11px] block">Authorization Ref</span>
                <span>{selectedGatewayDetails.authorization_reference}</span>
              </div>
            </div>

            {/* Attached Sensors */}
            <div className="space-y-1.5">
              <span className="text-[11px] text-ink-3 uppercase font-semibold">Attached Telemetry Sensors</span>
              {sensors.filter((s) => s.gateway_id === selectedGatewayDetails.id).length === 0 ? (
                <div className="p-3 border border-line bg-panel-2 text-ink-3 text-[11px]">
                  No dedicated sensors attached directly to this gateway boundary.
                </div>
              ) : (
                <div className="space-y-1">
                  {sensors
                    .filter((s) => s.gateway_id === selectedGatewayDetails.id)
                    .map((s) => {
                      const h = healthList.find((hl) => hl.sensor_id === s.id);
                      return (
                        <div
                          key={s.id}
                          className="p-2 border border-line bg-panel-2 flex items-center justify-between"
                        >
                          <div>
                            <div className="font-semibold">{s.sensor_name}</div>
                            <div className="text-[11px] text-ink-3">
                              {s.sensor_type} • Window: {s.freshness_window_seconds}s
                            </div>
                          </div>
                          <span
                            className={`text-[11px] px-1.5 py-0.5 border font-semibold ${healthBadgeClass(h?.current_health || "UNKNOWN")}`}
                          >
                            {h?.current_health || "UNKNOWN"}
                          </span>
                        </div>
                      );
                    })}
                </div>
              )}
            </div>

            {/* Analyst Workflow Transitions */}
            <div className="space-y-2 pt-2 border-t border-line">
              <span className="text-[11px] text-ink-3 uppercase font-semibold block">
                SOC Analyst Workflow Transitions
              </span>
              <Button
                variant="primary"
                size="sm"
                className="w-full justify-between"
                onClick={() => {
                  setFilterGatewayId(selectedGatewayDetails.id);
                  setActiveTab("timeline");
                  setSelectedGatewayDetails(null);
                }}
              >
                <span className="inline-flex items-center gap-2">
                  <Layers className="w-3.5 h-3.5" />
                  <span>Filter Event Timeline for {selectedGatewayDetails.name}</span>
                </span>
                <ChevronRight className="w-3.5 h-3.5" />
              </Button>

              <Button
                variant="secondary"
                size="sm"
                className="w-full justify-between"
                onClick={() => {
                  setFilterGatewayId(selectedGatewayDetails.id);
                  setActiveTab("sa_states");
                  setSelectedGatewayDetails(null);
                }}
              >
                <span className="inline-flex items-center gap-2">
                  <GitBranch className="w-3.5 h-3.5" />
                  <span>View Projected SAs for {selectedGatewayDetails.name}</span>
                </span>
                <ChevronRight className="w-3.5 h-3.5" />
              </Button>

              <ButtonLink
                href={`/inventory?gateway_identity=${encodeURIComponent(selectedGatewayDetails.name)}`}
                variant="secondary"
                size="sm"
                className="w-full justify-between"
              >
                <span className="inline-flex items-center gap-2">
                  <FileKey2 className="w-3.5 h-3.5 text-low" />
                  <span>Inspect Configuration & Cert Inventory</span>
                </span>
                <ExternalLink className="w-3.5 h-3.5" />
              </ButtonLink>

              <ButtonLink
                href={`/vulnerabilities?host_ip=${encodeURIComponent(selectedGatewayDetails.gateway_ip)}`}
                variant="secondary"
                size="sm"
                className="w-full justify-between"
              >
                <span className="inline-flex items-center gap-2">
                  <ShieldCheck className="w-3.5 h-3.5 text-positive" />
                  <span>View Correlated External Vulnerabilities</span>
                </span>
                <ExternalLink className="w-3.5 h-3.5" />
              </ButtonLink>

              <ButtonLink
                href="/analyses"
                variant="secondary"
                size="sm"
                className="w-full justify-between"
              >
                <span className="inline-flex items-center gap-2">
                  <Activity className="w-3.5 h-3.5 text-accent" />
                  <span>Open Protocol & Forensics Analyses</span>
                </span>
                <ChevronRight className="w-3.5 h-3.5" />
              </ButtonLink>
            </div>
          </div>
        </InspectorDrawer>
      )}
    </div>
  );
}

export default function ContinuousMonitoringPage() {
  return (
    <Suspense
      fallback={
        <EmptyState compact title="Loading Continuous Monitoring workbench and telemetry status…" />
      }
    >
      <MonitoringContent />
    </Suspense>
  );
}
