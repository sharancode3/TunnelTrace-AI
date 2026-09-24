"use client";

import React, { useState, useEffect } from "react";
import { WifiOff } from "lucide-react";

export function OfflineBanner() {
  const [isOffline, setIsOffline] = useState(() => {
    if (typeof window !== "undefined") {
      return !navigator.onLine;
    }
    return false;
  });

  useEffect(() => {
    const handleOnline = () => setIsOffline(false);
    const handleOffline = () => setIsOffline(true);

    window.addEventListener("online", handleOnline);
    window.addEventListener("offline", handleOffline);

    return () => {
      window.removeEventListener("online", handleOnline);
      window.removeEventListener("offline", handleOffline);
    };
  }, []);

  if (!isOffline) return null;

  return (
    <div className="bg-amber-600 text-white px-4 py-2 text-xs font-mono flex items-center justify-between border-b border-amber-700">
      <div className="flex items-center space-x-2">
        <WifiOff className="w-4 h-4 shrink-0" />
        <span className="font-bold uppercase tracking-wider">OFFLINE MODE:</span>
        <span>
          Local application shell loaded. Live capture, real-time ingestion, and remote sync are disabled.
        </span>
      </div>
      <span className="text-[10px] uppercase tracking-widest bg-amber-800 px-2 py-0.5 font-bold">
        AIR-GAP SAFE
      </span>
    </div>
  );
}
