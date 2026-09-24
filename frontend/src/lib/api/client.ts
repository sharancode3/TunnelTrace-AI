/**
 * Canonical typed API client for TunnelTrace AI.
 * Communicates with FastAPI backend exclusively; zero browser-calculated security logic.
 */

import {
  AnalysisListItemDTO,
  AnalysisOverviewDTO,
  AnalysisRunResponseDTO,
  CaptureResponseDTO,
  ChildSecurityAssociationDTO,
  ComplianceSummaryDTO,
  EvidenceGraphDTO,
  FingerprintabilityDTO,
  InterfaceMetadataDTO,
  ProtocolSummaryDTO,
  ReportListResponseDTO,
  ReportResponseDTO,
  RiskAssessmentDTO,
  SAGraphResponseDTO,
  SecurityFindingDTO,
  SecurityScoreDTO,
  ThreatInstanceDTO,
  TrafficSummaryResponseDTO,
} from "./types";

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000/api/v1";

export class ApiError extends Error {
  constructor(
    public status: number,
    public message: string,
    public detail?: any
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE_URL}${path}`;
  const headers = new Headers(options.headers || {});

  if (!headers.has("Content-Type") && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(url, {
    ...options,
    headers,
  });

  if (!res.ok) {
    let errorDetail: any = null;
    try {
      errorDetail = await res.json();
    } catch {
      errorDetail = await res.text();
    }
    const message =
      typeof errorDetail === "object" && errorDetail?.detail
        ? errorDetail.detail
        : `Request failed with status ${res.status}`;
    throw new ApiError(res.status, message, errorDetail);
  }

  // Handle empty bodies
  if (res.status === 204) {
    return {} as T;
  }

  const contentType = res.headers.get("content-type");
  if (contentType && contentType.includes("application/json")) {
    return res.json();
  }
  return res.text() as unknown as T;
}

export const api = {
  captures: {
    upload: async (file: File): Promise<CaptureResponseDTO> => {
      const formData = new FormData();
      formData.append("file", file);
      return request<CaptureResponseDTO>("/captures/upload", {
        method: "POST",
        body: formData,
      });
    },
    get: async (id: string): Promise<CaptureResponseDTO> => {
      return request<CaptureResponseDTO>(`/captures/${id}`);
    },
    listInterfaces: async (): Promise<InterfaceMetadataDTO[]> => {
      return request<InterfaceMetadataDTO[]>("/live-captures/interfaces");
    },
    startLive: async (data: {
      interface_id: string;
      duration_sec?: number;
      capture_profile?: string;
      bpf_filter?: string;
    }): Promise<any> => {
      return request("/live-captures/start", {
        method: "POST",
        body: JSON.stringify(data),
      });
    },
    stopLive: async (sessionId: string): Promise<any> => {
      return request(`/live-captures/stop/${sessionId}`, {
        method: "POST",
      });
    },
  },

  analyses: {
    list: async (): Promise<AnalysisListItemDTO[]> => {
      return request<AnalysisListItemDTO[]>("/analyses");
    },
    get: async (id: string): Promise<AnalysisRunResponseDTO> => {
      return request<AnalysisRunResponseDTO>(`/analyses/${id}`);
    },
    create: async (captureId: string): Promise<AnalysisRunResponseDTO> => {
      return request<AnalysisRunResponseDTO>("/analyses", {
        method: "POST",
        body: JSON.stringify({ capture_id: captureId }),
      });
    },
    getOverview: async (id: string): Promise<AnalysisOverviewDTO> => {
      return request<AnalysisOverviewDTO>(`/analyses/${id}/overview`);
    },
    getProtocol: async (id: string): Promise<ProtocolSummaryDTO> => {
      return request<ProtocolSummaryDTO>(`/analyses/${id}/protocol`);
    },
    getSas: async (id: string): Promise<ChildSecurityAssociationDTO[]> => {
      return request<ChildSecurityAssociationDTO[]>(
        `/analyses/${id}/security-associations`
      );
    },
    getSaGraph: async (id: string): Promise<SAGraphResponseDTO> => {
      return request<SAGraphResponseDTO>(
        `/analyses/${id}/security-associations/graph`
      );
    },
    getTraffic: async (id: string): Promise<TrafficSummaryResponseDTO> => {
      return request<TrafficSummaryResponseDTO>(`/analyses/${id}/traffic`);
    },
    getFindings: async (id: string): Promise<SecurityFindingDTO[]> => {
      return request<SecurityFindingDTO[]>(`/analyses/${id}/findings`);
    },
    getCompliance: async (id: string): Promise<ComplianceSummaryDTO> => {
      return request<ComplianceSummaryDTO>(`/analyses/${id}/compliance`);
    },
    getSecurityScore: async (id: string): Promise<SecurityScoreDTO> => {
      return request<SecurityScoreDTO>(`/analyses/${id}/security-score`);
    },
    getRisk: async (id: string): Promise<RiskAssessmentDTO> => {
      return request<RiskAssessmentDTO>(`/analyses/${id}/risk`);
    },
    getThreats: async (id: string): Promise<ThreatInstanceDTO[]> => {
      return request<ThreatInstanceDTO[]>(`/analyses/${id}/threat-matrix`);
    },
    getFingerprintability: async (id: string): Promise<FingerprintabilityDTO> => {
      return request<FingerprintabilityDTO>(
        `/analyses/${id}/metadata-fingerprintability`
      );
    },
    getEvidenceGraph: async (id: string): Promise<EvidenceGraphDTO> => {
      return request<EvidenceGraphDTO>(`/analyses/${id}/evidence-graph`);
    },
  },

  reports: {
    generate: async (
      analysisId: string,
      reportType: "EXECUTIVE" | "TECHNICAL"
    ): Promise<ReportResponseDTO> => {
      return request<ReportResponseDTO>(`/analyses/${analysisId}/reports`, {
        method: "POST",
        body: JSON.stringify({ report_type: reportType }),
      });
    },
    list: async (analysisId: string): Promise<ReportListResponseDTO> => {
      return request<ReportListResponseDTO>(`/analyses/${analysisId}/reports`);
    },
    get: async (
      analysisId: string,
      reportId: string
    ): Promise<ReportResponseDTO> => {
      return request<ReportResponseDTO>(
        `/analyses/${analysisId}/reports/${reportId}`
      );
    },
    getHtml: async (
      analysisId: string,
      reportId: string
    ): Promise<string> => {
      return request<string>(
        `/analyses/${analysisId}/reports/${reportId}/html`
      );
    },
    getDownloadUrl: (
      analysisId: string,
      reportId: string,
      format: "pdf" | "html"
    ): string => {
      return `${API_BASE_URL}/analyses/${analysisId}/reports/${reportId}/download?format=${format}`;
    },
  },

  system: {
    getHealth: async (): Promise<{ status: string; checks: Record<string, any> }> => {
      return request("/system/health");
    },
  },
};
