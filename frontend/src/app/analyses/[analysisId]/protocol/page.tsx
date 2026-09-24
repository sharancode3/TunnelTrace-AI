"use client";

import React, { use } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { EvidenceStateBadge } from "@/components/ui/badge";
import { CopyableValue } from "@/components/ui/table";
import { Network, AlertCircle, CheckCircle, ShieldAlert, HelpCircle } from "lucide-react";

export default function ProtocolIntelligencePage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);

  const {
    data: protocol,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["protocol", analysisId],
    queryFn: () => api.analyses.getProtocol(analysisId),
  });

  if (isLoading) {
    return (
      <div className="py-20 text-center font-mono text-xs text-neutral-500 animate-pulse">
        Dissecting protocol frames and extracting IKE/ESP parameters...
      </div>
    );
  }

  if (isError || !protocol) {
    return (
      <div className="p-6 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 text-center space-y-2 font-mono text-xs text-rose-600">
        <AlertCircle className="w-6 h-6 mx-auto" />
        <p>Failed to load protocol intelligence: {(error as any)?.message || "Unknown error"}</p>
      </div>
    );
  }

  const { evidence_states } = protocol;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div className="flex items-center space-x-2">
          <Network className="w-5 h-5 text-[#FF3D00]" />
          <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
            Protocol Intelligence & Cryptographic Handshake Forensics
          </h1>
        </div>
        <p className="text-xs text-neutral-500 mt-1">
          Deterministic dissection of IKEv1/IKEv2 session establishment, Security Associations, transform negotiation, and encapsulation.
        </p>
      </div>

      {/* Primary Status Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card title="IPsec Protocol Status">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className={`text-2xl font-mono font-bold ${protocol.ipsec_detected ? "text-emerald-600" : "text-neutral-400"}`}>
                {protocol.ipsec_detected ? "DETECTED" : "NOT OBSERVED"}
              </span>
            </div>
            <p className="text-[11px] font-mono text-neutral-500">
              Total frames inspected: {protocol.total_packets_inspected}
            </p>
          </div>
        </Card>

        <Card title="IKE Negotiation Packets">
          <div className="space-y-1 font-mono">
            <div className="text-2xl font-bold text-neutral-900 dark:text-white">
              {protocol.ikev1_packet_count + protocol.ikev2_packet_count}
            </div>
            <div className="text-[11px] text-neutral-500 flex space-x-3">
              <span>IKEv1: {protocol.ikev1_packet_count}</span>
              <span>IKEv2: {protocol.ikev2_packet_count}</span>
            </div>
          </div>
        </Card>

        <Card title="Encapsulation (ESP / AH)">
          <div className="space-y-1 font-mono">
            <div className="text-2xl font-bold text-neutral-900 dark:text-white">
              {protocol.esp_packet_count + protocol.ah_packet_count}
            </div>
            <div className="text-[11px] text-neutral-500 flex space-x-3">
              <span>ESP: {protocol.esp_packet_count}</span>
              <span>AH: {protocol.ah_packet_count}</span>
            </div>
          </div>
        </Card>

        <Card title="NAT-T Traversal Status">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className={`text-2xl font-mono font-bold ${protocol.nat_t_detected ? "text-sky-600" : "text-neutral-500"}`}>
                {protocol.nat_t_detected ? "UDP 4500" : "DIRECT / 500"}
              </span>
            </div>
            <p className="text-[11px] font-mono text-neutral-500">
              Non-ESP marker encapsulation check.
            </p>
          </div>
        </Card>
      </div>

      {/* Dissected Handshake Parameters */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Cryptographic Transforms & DH Groups */}
        <div className="space-y-6">
          <Card
            title="Negotiated & Proposed Cryptographic Transforms"
            badge={<EvidenceStateBadge state={evidence_states?.cipher_suites || "INFERRED"} />}
          >
            <div className="space-y-4">
              <div>
                <span className="text-[11px] font-mono uppercase tracking-wider text-neutral-500 block mb-2">
                  Cipher Suites (Encryption Algorithms)
                </span>
                {protocol.observed_cipher_suites && protocol.observed_cipher_suites.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {protocol.observed_cipher_suites.map((cipher, idx) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 text-xs font-mono font-bold bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 text-neutral-900 dark:text-white"
                      >
                        {cipher}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-xs font-mono text-neutral-500">
                    No cipher transforms observed in unencrypted handshake frames (session may have been captured mid-stream).
                  </div>
                )}
              </div>

              <div>
                <span className="text-[11px] font-mono uppercase tracking-wider text-neutral-500 block mb-2">
                  Diffie-Hellman / Key Exchange Groups
                </span>
                {protocol.observed_dh_groups && protocol.observed_dh_groups.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {protocol.observed_dh_groups.map((dh, idx) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 text-xs font-mono font-bold bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 text-neutral-900 dark:text-white"
                      >
                        {dh}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-xs font-mono text-neutral-500">
                    Diffie-Hellman parameters not observed in capture window. State: UNKNOWN.
                  </div>
                )}
              </div>

              <div>
                <span className="text-[11px] font-mono uppercase tracking-wider text-neutral-500 block mb-2">
                  Observed IKE Exchange Types
                </span>
                {protocol.observed_exchange_types && protocol.observed_exchange_types.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {protocol.observed_exchange_types.map((ex, idx) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 text-xs font-mono bg-sky-50 dark:bg-sky-950/20 text-sky-900 dark:text-sky-300 border border-sky-300 dark:border-sky-800"
                      >
                        {ex}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs font-mono text-neutral-500">
                    No discrete IKE exchange headers detected.
                  </div>
                )}
              </div>
            </div>
          </Card>
        </div>

        {/* Right: Security Parameter Index (SPI) Observation Table */}
        <div className="space-y-6">
          <Card title="Observed Session SPI Identifiers">
            <div className="space-y-4">
              <div>
                <span className="text-[11px] font-mono uppercase tracking-wider text-neutral-500 block mb-2">
                  Initiator SPIs ({protocol.observed_initiator_spis?.length || 0})
                </span>
                {protocol.observed_initiator_spis && protocol.observed_initiator_spis.length > 0 ? (
                  <div className="space-y-1.5">
                    {protocol.observed_initiator_spis.map((spi, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-2 bg-neutral-50 dark:bg-neutral-900/60 border border-neutral-200 dark:border-neutral-800"
                      >
                        <CopyableValue value={spi} label="Initiator SPI" />
                        <span className="text-[10px] font-mono text-neutral-400">INITIATOR</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs font-mono text-neutral-500 p-3 border border-neutral-200 dark:border-neutral-800">
                    No initiator SPIs observed.
                  </div>
                )}
              </div>

              <div>
                <span className="text-[11px] font-mono uppercase tracking-wider text-neutral-500 block mb-2">
                  Responder SPIs ({protocol.observed_responder_spis?.length || 0})
                </span>
                {protocol.observed_responder_spis && protocol.observed_responder_spis.length > 0 ? (
                  <div className="space-y-1.5">
                    {protocol.observed_responder_spis.map((spi, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-2 bg-neutral-50 dark:bg-neutral-900/60 border border-neutral-200 dark:border-neutral-800"
                      >
                        <CopyableValue value={spi} label="Responder SPI" />
                        <span className="text-[10px] font-mono text-neutral-400">RESPONDER</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs font-mono text-neutral-500 p-3 border border-neutral-200 dark:border-neutral-800">
                    No responder SPIs observed.
                  </div>
                )}
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
