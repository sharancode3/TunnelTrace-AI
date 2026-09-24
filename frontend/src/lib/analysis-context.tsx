"use client";

import React, { createContext, useContext, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api/client";
import { AnalysisOverviewDTO, AnalysisRunResponseDTO } from "./api/types";
import { useAnalysisWebSocket } from "./use-analysis-websocket";

interface AnalysisContextType {
  activeAnalysisId: string | null;
  setActiveAnalysisId: (id: string | null) => void;
  analysis: AnalysisRunResponseDTO | undefined;
  overview: AnalysisOverviewDTO | undefined;
  isLoading: boolean;
  isError: boolean;
  wsConnected: boolean;
  refetch: () => void;
}

const AnalysisContext = createContext<AnalysisContextType>({
  activeAnalysisId: null,
  setActiveAnalysisId: () => {},
  analysis: undefined,
  overview: undefined,
  isLoading: false,
  isError: false,
  wsConnected: false,
  refetch: () => {},
});

export function AnalysisProvider({
  children,
  initialAnalysisId,
}: {
  children: React.ReactNode;
  initialAnalysisId?: string;
}) {
  const [internalAnalysisId, setInternalAnalysisId] = useState<string | null>(null);
  const activeAnalysisId = initialAnalysisId ?? internalAnalysisId;

  const {
    data: analysis,
    isLoading: isAnalysisLoading,
    isError: isAnalysisError,
    refetch: refetchAnalysis,
  } = useQuery({
    queryKey: ["analysis", activeAnalysisId],
    queryFn: () => (activeAnalysisId ? api.analyses.get(activeAnalysisId) : null),
    enabled: !!activeAnalysisId,
  });

  const {
    data: overview,
    isLoading: isOverviewLoading,
    isError: isOverviewError,
    refetch: refetchOverview,
  } = useQuery({
    queryKey: ["analysis-overview", activeAnalysisId],
    queryFn: () =>
      activeAnalysisId ? api.analyses.getOverview(activeAnalysisId) : null,
    enabled: !!activeAnalysisId,
  });

  const { isConnected: wsConnected } = useAnalysisWebSocket(activeAnalysisId);

  const refetch = () => {
    refetchAnalysis();
    refetchOverview();
  };

  return (
    <AnalysisContext.Provider
      value={{
        activeAnalysisId,
        setActiveAnalysisId: setInternalAnalysisId,
        analysis: analysis || undefined,
        overview: overview || undefined,
        isLoading: isAnalysisLoading || isOverviewLoading,
        isError: isAnalysisError || isOverviewError,
        wsConnected,
        refetch,
      }}
    >
      {children}
    </AnalysisContext.Provider>
  );
}

export function useAnalysis() {
  return useContext(AnalysisContext);
}
