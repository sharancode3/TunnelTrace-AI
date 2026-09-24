"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { useQueryClient } from "@tanstack/react-query";

interface WebSocketMessage {
  type: string;
  analysis_id?: string;
  status?: string;
  current_stage?: string;
  timestamp?: string;
  data?: unknown;
}

export function useAnalysisWebSocket(analysisId: string | null) {
  const queryClient = useQueryClient();
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttemptRef = useRef(0);
  const pingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const connectRef = useRef<() => void>(() => {});

  const connect = useCallback(() => {
    if (!analysisId) return;

    if (wsRef.current) {
      wsRef.current.close();
    }

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = process.env.NEXT_PUBLIC_WS_HOST || "127.0.0.1:8000";
    const wsUrl = `${protocol}//${host}/api/v1/ws/analyses/${analysisId}`;

    try {
      const socket = new WebSocket(wsUrl);
      wsRef.current = socket;

      socket.onopen = () => {
        setIsConnected(true);
        setConnectionError(null);
        reconnectAttemptRef.current = 0;

        // Keep-alive ping every 25 seconds
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        pingIntervalRef.current = setInterval(() => {
          if (socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ type: "PING" }));
          }
        }, 25000);
      };

      socket.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data);
          if (parsed.type === "PONG") return;

          setLastMessage(parsed);

          // If analysis state changed, trigger query invalidation for authoritative REST sync
          if (
            parsed.type === "ANALYSIS_STATE" ||
            parsed.type === "STAGE_COMPLETED" ||
            parsed.type === "ANALYSIS_COMPLETED"
          ) {
            queryClient.invalidateQueries({
              queryKey: ["analysis", analysisId],
            });
            queryClient.invalidateQueries({
              queryKey: ["analysis-overview", analysisId],
            });
          }
        } catch {
          // ignore malformed frame
        }
      };

      socket.onerror = () => {
        setConnectionError("WebSocket connection error");
      };

      socket.onclose = () => {
        setIsConnected(false);
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);

        // Exponential backoff reconnect: max 30s
        const backoff = Math.min(
          1000 * Math.pow(1.5, reconnectAttemptRef.current),
          30000
        );
        reconnectAttemptRef.current += 1;

        reconnectTimeoutRef.current = setTimeout(() => {
          connectRef.current();
        }, backoff);
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to initialize WebSocket";
      setConnectionError(msg);
    }
  }, [analysisId, queryClient]);

  useEffect(() => {
    connectRef.current = connect;
    connect();

    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      setIsConnected(false);
    };
  }, [connect]);

  return {
    isConnected,
    lastMessage,
    connectionError,
  };
}
