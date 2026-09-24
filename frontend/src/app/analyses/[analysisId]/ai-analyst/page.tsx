"use client";

import React, { use } from "react";
import { Card } from "@/components/ui/card";
import { Bot, Cpu, Lock, Send, ShieldAlert, Sparkles, Terminal } from "lucide-react";

export default function AIAnalystPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div className="flex items-center space-x-2">
          <Bot className="w-5 h-5 text-[#FF3D00]" />
          <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
            Grounded AI Security Analyst & Conversational Assistant
          </h1>
        </div>
        <p className="text-xs text-neutral-500 mt-1">
          Stage 11 local LLM integration with grounded RAG against standards, evidence graphs, and analysis run state.
        </p>
      </div>

      {/* Stage Boundary Banner */}
      <div className="p-4 bg-neutral-100 dark:bg-neutral-900 border-2 border-neutral-400 dark:border-neutral-700 text-neutral-800 dark:text-neutral-300 text-xs font-mono space-y-2">
        <div className="flex items-center space-x-2 font-bold text-sm text-[#FF3D00]">
          <Cpu className="w-5 h-5" />
          <span>STAGE BOUNDARY: STAGE 11 NOT YET INITIALIZED</span>
        </div>
        <p>
          The user has local models installed and will select either <strong>Qwen 3 4B</strong> or <strong>Gemma 3 4B</strong> for grounded conversational analysis during <strong>Stage 11</strong>.
        </p>
        <p className="text-neutral-500">
          In strict compliance with Stage 9 non-negotiables, no local model calls or synthetic LLM responses are executed here. Reporting, security scores, compliance findings, and threat mappings are 100% deterministic.
        </p>
      </div>

      {/* Preparatory Layout Framework */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Chat / Interaction Area (8 cols) */}
        <div className="lg:col-span-8 space-y-4">
          <Card title="Grounded Conversation Canvas">
            <div className="h-[450px] flex flex-col justify-between">
              {/* Empty / Boundary State */}
              <div className="flex-1 flex flex-col items-center justify-center text-center p-6 space-y-3 font-mono text-xs text-neutral-500">
                <Terminal className="w-8 h-8 text-neutral-400" />
                <div className="space-y-1">
                  <p className="font-bold text-neutral-800 dark:text-neutral-200">
                    AI Analyst Gateway Inactive (Stage 11)
                  </p>
                  <p className="max-w-md">
                    Target model: Qwen 3 4B / Gemma 3 4B (Local-first inference).
                    RAG grounding context: Analysis Run {analysisId.slice(0, 8)}...
                  </p>
                </div>
              </div>

              {/* Disabled Input Bar */}
              <div className="border-t border-neutral-200 dark:border-neutral-800 pt-3">
                <div className="relative">
                  <input
                    type="text"
                    disabled
                    placeholder="Conversational querying disabled until Stage 11..."
                    className="w-full pl-3 pr-10 py-2.5 text-xs font-mono bg-neutral-100 dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-800 text-neutral-400 cursor-not-allowed"
                  />
                  <button
                    disabled
                    className="absolute right-2 top-2 p-1 text-neutral-400 cursor-not-allowed"
                  >
                    <Send className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          </Card>
        </div>

        {/* Source & Model Status Panel (4 cols) */}
        <div className="lg:col-span-4 space-y-4">
          <Card title="Model Runtime Configuration">
            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
                <span className="text-neutral-500">Candidate 1:</span>
                <span className="font-bold">Qwen 3 4B (Local)</span>
              </div>
              <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
                <span className="text-neutral-500">Candidate 2:</span>
                <span className="font-bold">Gemma 3 4B (Local)</span>
              </div>
              <div className="flex justify-between py-1 border-b border-neutral-200 dark:border-neutral-800">
                <span className="text-neutral-500">Inference Status:</span>
                <span className="text-amber-600 font-bold">RESERVED FOR STAGE 11</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-neutral-500">External Cloud AI:</span>
                <span className="font-bold text-rose-600">STRICTLY PROHIBITED</span>
              </div>
            </div>
          </Card>

          <Card title="Grounded Knowledge Context">
            <div className="space-y-2 text-xs font-mono text-neutral-500">
              <p>• IETF RFC 7296 (IKEv2)</p>
              <p>• IETF RFC 8221 (Cryptographic Algorithms)</p>
              <p>• NIST SP 800-77 Rev 1</p>
              <p>• ANSSI IPsec Security Recommendations</p>
              <p>• Verified Session Evidence DAG</p>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
