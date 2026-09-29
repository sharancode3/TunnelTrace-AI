"use client";

import React, { use, useEffect, useState, useRef } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  BookOpen,
  Bot,
  Check,
  Copy,
  Cpu,
  ExternalLink,
  Lock,
  RefreshCw,
  Search,
  Send,
  ShieldCheck,
  Sparkles,
  Terminal,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Section } from "@/components/ui/section";
import { EmptyState } from "@/components/ui/empty-state";
import { Select, Input } from "@/components/ui/input";
import { useAnalysis } from "@/lib/analysis-context";
import { apiClient } from "@/lib/api/client";
import {
  AIChatClaimDTO,
  AIChatCitationDTO,
  AIHealthResponseDTO,
} from "@/lib/api/types";

interface MessageItem {
  id: string;
  role: "user" | "assistant";
  content: string;
  status?: string;
  claims?: AIChatClaimDTO[];
  citations?: AIChatCitationDTO[];
  limitations?: string[];
  provenance?: {
    answer_hash: string;
    fact_lock_hash: string;
    model_name: string;
    verified_at: string;
  } | null;
  metrics?: {
    total_ms: number;
    generation_ms?: number;
  };
}

const EPISTEMIC_CLAIM_STYLES: Record<string, string> = {
  VERIFIED: "bg-positive-bg text-positive border-positive-border",
  INFERRED: "bg-info-bg text-ink-2 border-info-border",
  PROJECTED: "bg-medium-bg text-medium border-medium-border",
  VERIFIED_POST_REMEDIATION: "bg-positive-bg text-positive border-positive-border",
};

export default function AIAnalystPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const { overview } = useAnalysis();

  const failCount = overview?.compliance_counts?.fail ?? 0;
  const score = overview?.security_posture?.score ?? 100;
  const topFinding = overview?.findings_summary?.top_findings?.[0];

  const quickPrompts = React.useMemo(() => {
    const prompts: string[] = [];
    if (failCount > 0 || score < 100) {
      prompts.push("Why did this tunnel fail compliance?");
      if (topFinding) {
        prompts.push(`What evidence supports finding ${topFinding.rule_id || topFinding.finding_id}?`);
      }
    } else {
      prompts.push("Summarize verified cryptographic transforms in this tunnel");
      prompts.push("Explain why this tunnel received a 100/100 score");
    }
    prompts.push("Is Perfect Forward Secrecy (PFS) enabled for Child SAs?");
    prompts.push("What does RFC 8247 require for IKEv2 encryption algorithms?");
    if (overview?.traffic_summary?.total_flows && overview.traffic_summary.total_flows > 0) {
      prompts.push("Explain how encrypted flow timing and metadata were analyzed");
    }
    prompts.push("List the observed Diffie-Hellman groups and key lengths");
    return prompts.slice(0, 5);
  }, [failCount, score, topFinding, overview]);

  // Subsystem state
  const [health, setHealth] = useState<AIHealthResponseDTO | null>(null);
  const [messages, setMessages] = useState<MessageItem[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [inputQuery, setInputQuery] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [generationStep, setGenerationStep] = useState<string>("");
  const [selectedModel, setSelectedModel] = useState<string>("qwen3:4b-instruct-2507-q4_K_M");
  const [evidenceOnlyMode, setEvidenceOnlyMode] = useState(false);
  const [isIngestingKnowledge, setIsIngestingKnowledge] = useState(false);

  // Selected source for highlight in right panel
  const [selectedSourceId, setSelectedSourceId] = useState<string | null>(null);
  const [sourceFilter, setSourceFilter] = useState<"ALL" | "FINDINGS" | "STANDARDS" | "FACTS">("ALL");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Load health & index status on mount
  useEffect(() => {
    async function loadSubsystemStatus() {
      try {
        const h = await apiClient.ai.getHealth();
        setHealth(h);
        if (h.primary_model) {
          setSelectedModel(h.primary_model);
        }
      } catch (err) {
        console.error("Failed to load AI health:", err);
      }
    }
    loadSubsystemStatus();
  }, []);

  // Auto-scroll messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, generationStep]);

  // Handle Query Submission
  const handleSend = async (queryText?: string) => {
    const q = (queryText || inputQuery).trim();
    if (!q || isGenerating) return;

    setInputQuery("");

    // Add user message
    const userMsg: MessageItem = {
      id: `user-${Date.now()}`,
      role: "user",
      content: q,
    };
    setMessages((prev) => [...prev, userMsg]);

    if (evidenceOnlyMode) {
      // Deterministic evidence search fallback
      setIsGenerating(true);
      setGenerationStep("Querying authoritative evidence graph...");
      try {
        const res = await apiClient.ai.searchEvidenceOnly(analysisId, q);

        const fallbackAnswer: MessageItem = {
          id: `assistant-${Date.now()}`,
          role: "assistant",
          content: `Evidence Search Mode: Retrieved ${res.matched_facts.length} structured fact(s) and ${res.matched_standards.length} standard chunk(s) matching your query without generative AI.`,
          status: "ANSWERED",
          claims: [],
          citations: res.matched_standards.map((s) => ({
            source_id: s.source_id,
            source_type: "standard",
            locator: s.section_reference,
            title: `${s.document_code} ${s.section_reference}`,
            excerpt: s.excerpt,
          })),
          limitations: ["Generated in deterministic Evidence-Search mode (LLM bypassed)."],
        };
        setMessages((prev) => [...prev, fallbackAnswer]);
      } catch (err: unknown) {
        setMessages((prev) => [
          ...prev,
          {
            id: `assistant-${Date.now()}`,
            role: "assistant",
            content: `Evidence search failed: ${err instanceof Error ? err.message : String(err)}`,
            status: "FAILED",
          },
        ]);
      } finally {
        setIsGenerating(false);
        setGenerationStep("");
      }
      return;
    }

    // Full Grounded RAG Flow
    setIsGenerating(true);
    setGenerationStep("Retrieving forensic analysis facts...");

    try {
      setTimeout(() => {
        setGenerationStep("Assembling FactLock & normative standards context...");
      }, 600);

      setTimeout(() => {
        setGenerationStep(`Generating grounded response via ${selectedModel.split(":")[0]}...`);
      }, 1500);

      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(
          () =>
            reject(
              new Error(
                "The AI assistant request timed out (20-second bounded limit). This may be due to complex evidence aggregation or local model latency. You can still inspect raw forensic findings directly in the Protocol, SA Explorer, or Evidence tabs."
              )
            ),
          20000
        )
      );

      const resp = await Promise.race([
        apiClient.ai.chat(analysisId, {
          question: q,
          session_id: sessionId || undefined,
          model_override: selectedModel,
        }),
        timeoutPromise,
      ]);

      setGenerationStep("Validating citation integrity & fact grounding...");

      if (!sessionId && resp.session_id) {
        setSessionId(resp.session_id);
      }

      const assistantMsg: MessageItem = {
        id: resp.query_run_id,
        role: "assistant",
        content: resp.answer,
        status: resp.status,
        claims: resp.claims,
        citations: resp.citations,
        limitations: resp.limitations,
        provenance: resp.provenance,
        metrics: resp.metrics,
      };

      setMessages((prev) => [...prev, assistantMsg]);

      // If citations returned, select first citation to show in right panel
      if (resp.citations && resp.citations.length > 0) {
        setSelectedSourceId(resp.citations[0].source_id);
      }
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      setMessages((prev) => [
        ...prev,
        {
          id: `assistant-${Date.now()}`,
          role: "assistant",
          content: `${errorMessage || "Model query timed out or runtime offline."}\n\nDeterministic cryptographic facts, compliance decisions, and threat findings remain 100% authoritative and accessible across the Protocol Forensics, SA Explorer, and Evidence tabs.`,
          status: "MODEL_TIMEOUT",
          limitations: [
            "20-second bounded timeout reached before local model completed token generation.",
            "Deterministic facts in database remain 100% accessible and unimpacted.",
          ],
        },
      ]);
    } finally {
      setIsGenerating(false);
      setGenerationStep("");
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Extract all citations from active messages
  const lastAssistantMsg = [...messages].reverse().find((m) => m.role === "assistant");
  const activeCitations = lastAssistantMsg?.citations || [];

  // Filter sources for right panel
  const filteredCitations = activeCitations.filter((cit) => {
    if (sourceFilter === "ALL") return true;
    if (sourceFilter === "FINDINGS") return cit.source_type === "finding" || cit.source_id.includes("finding");
    if (sourceFilter === "STANDARDS") return cit.source_type === "standard" || cit.source_id.includes("standard");
    if (sourceFilter === "FACTS") return ["fact", "sa", "flow", "score", "claim", "verification"].includes(cit.source_type);
    return true;
  });

  const providerDot =
    health?.status === "healthy"
      ? "bg-positive"
      : health?.status === "degraded"
      ? "bg-medium"
      : "bg-critical";

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold text-ink tracking-tight">
            AI Security Analyst
          </h1>
          <p className="text-[13px] text-ink-2">
            Natural-language explanation of <strong>this investigation</strong>, strictly grounded in
            verified packet evidence and cited standards. Cannot hallucinate unobserved facts or
            override deterministic security scores.
          </p>
        </div>
        <span className="inline-flex items-center gap-1.5 px-2 py-1 text-[11px] font-mono font-semibold uppercase tracking-wide bg-panel-2 border border-line text-ink-2 shrink-0">
          <Bot className="w-3.5 h-3.5 text-accent" />
          <span>Evidence-Grounded Advisor</span>
        </span>
      </div>

      {/* §1 Analyst Context — what evidence the analyst is using */}
      <Section index="§1" title="Analyst Context" description="Runtime, model, and knowledge corpus used to ground responses for this investigation.">
        <div className="border border-line bg-panel p-3.5 flex flex-wrap items-center gap-x-5 gap-y-3">
          {/* Provider Connected */}
          <div
            className="flex items-center gap-2"
            title={`Local Ollama Base URL: ${health?.base_url || "http://localhost:11434"}`}
          >
            <span className={`w-2 h-2 rounded-full ${providerDot}`} />
            <span className="text-[11px] text-ink-3 font-semibold uppercase tracking-wide">
              Provider: <span className="text-ink-2">{health?.runtime || "Ollama"} ({health?.status || "Probing"})</span>
            </span>
          </div>

          {/* Model Selector */}
          <div className="flex items-center gap-2">
            <Cpu className="w-3.5 h-3.5 text-ink-3" />
            <span className="text-[11px] text-ink-3 font-semibold uppercase tracking-wide">Model:</span>
            <div className="w-52">
              <Select
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
                disabled={isGenerating}
                aria-label="Select analyst model"
              >
              <option value="gemma3:4b">Gemma 3 4B (Local)</option>
              <option value="qwen3:4b-instruct-2507-q4_K_M">Qwen 3 4B (Local)</option>
            </Select>
          </div>
          </div>

          {/* Knowledge Chunks Count */}
          <div
            className="flex items-center gap-2"
            title={`${health?.total_documents_indexed || 0} standards documents indexed into vector corpus`}
          >
            <BookOpen className="w-3.5 h-3.5 text-ink-3" />
            <span className="text-[11px] text-ink-3 font-semibold uppercase tracking-wide">
              RAG: <span className="text-ink-2">{health?.total_chunks_indexed ?? 0} Chunks</span>
            </span>
          </div>

          {/* Packet Evidence Linked */}
          <div
            className="flex items-center gap-2"
            title="Fact-locked packet observations and rule violations from current analysis"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-ink-3" />
            <span className="text-[11px] text-ink-3 font-semibold uppercase tracking-wide">
              Evidence: <span className="text-ink-2">{overview?.protocol_summary?.total_observations ?? 0} Facts · {overview?.findings_summary?.total ?? 0} Findings</span>
            </span>
          </div>

          {/* Evidence Only Toggle */}
          <Button
            variant={evidenceOnlyMode ? "primary" : "secondary"}
            size="sm"
            onClick={() => setEvidenceOnlyMode(!evidenceOnlyMode)}
            title="Bypass LLM generation and directly query evidence graphs and standards"
            aria-pressed={evidenceOnlyMode}
          >
            <Search className="w-3.5 h-3.5" />
            <span>Evidence Search {evidenceOnlyMode ? "On" : "Off"}</span>
          </Button>
        </div>
      </Section>

      {/* Unindexed Knowledge Warning Banner with Ingest Trigger */}
      {health && health.total_chunks_indexed === 0 && (
        <div className="p-3 bg-medium-bg border border-medium-border flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-[13px] font-semibold text-medium">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Knowledge base unindexed (0 chunks) — RAG search unavailable</span>
          </div>
          <Button
            variant="primary"
            size="sm"
            disabled={isIngestingKnowledge}
            onClick={async () => {
              setIsIngestingKnowledge(true);
              try {
                await apiClient.ai.ingestKnowledge();
                const h = await apiClient.ai.getHealth();
                setHealth(h);
              } catch (e) {
                console.error("Failed to ingest knowledge:", e);
              } finally {
                setIsIngestingKnowledge(false);
              }
            }}
            aria-live="polite"
          >
            {isIngestingKnowledge ? "Indexing Standards..." : "Index Standards Now"}
          </Button>
        </div>
      )}

      {/* Explicit Explanatory Role & Grounding Philosophy Banner */}
      <div className="border-l-2 border-line-strong bg-panel-2 p-3.5 space-y-1.5">
        <div className="flex items-center gap-2 text-[13px] font-semibold text-ink">
          <Sparkles className="w-4 h-4 text-accent shrink-0" />
          <span>Local Explanatory AI Analyst · Grounded In Evidence</span>
        </div>
        <p className="text-xs leading-relaxed text-ink-3">
          This local assistant (<code className="font-mono font-semibold text-ink">{selectedModel}</code>) operates strictly as an <strong>explanatory analyst</strong> grounded in this investigation&apos;s persisted packet facts and cited IETF/NIST standards.
          It is <strong>separate from the Stage 7 encrypted traffic ML classifier</strong> and <strong>cannot create security findings, alter posture scores, or validate configuration fixes</strong>. All assertions require cited evidence hashes or published standard clauses.
        </p>
      </div>

      {/* Main Workspace Layout (8 cols chat + 4 cols sources) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left Column: Conversation + Composer (8 cols) */}
        <div className="lg:col-span-8 space-y-5">
          {/* §2 Grounded Conversation */}
          <Section
            index="§2"
            title="Grounded Conversation"
            description="Every answer is tied to cited evidence from this investigation."
            actions={
              <div className="flex items-center gap-2">
                {sessionId && (
                  <span className="text-ink-3 text-[11px] font-mono">
                    Session: {sessionId.slice(0, 8)}
                  </span>
                )}
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    setMessages([]);
                    setSessionId(null);
                  }}
                >
                  Clear Thread
                </Button>
              </div>
            }
          >
            <div className="border border-line bg-panel flex flex-col h-[580px]">
              {/* Message Feed Area */}
              <div className="flex-1 overflow-y-auto space-y-4 p-4 font-mono text-xs">
                {messages.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-center p-6 gap-4">
                    <EmptyState
                      icon={<Terminal className="w-5 h-5" />}
                      title="TunnelTrace AI Analyst Ready"
                      description="Ask about cryptographic compliance, IKE negotiations, Security Posture Score deductions, or closed-loop remediation for this investigation."
                    />
                    {/* Quick suggestion prompt chips */}
                    <div className="w-full max-w-lg space-y-2">
                      <p className="text-[11px] text-ink-3 uppercase tracking-wide">
                        Suggested Forensic Inquiries (Run-Specific)
                      </p>
                      <div className="flex flex-wrap justify-center gap-1.5">
                        {quickPrompts.map((prompt, idx) => (
                          <button
                            key={idx}
                            onClick={() => handleSend(prompt)}
                            disabled={isGenerating}
                            className="px-2.5 py-1 text-left bg-panel-2 border border-line text-ink-2 hover:border-accent hover:text-ink transition-colors disabled:opacity-50"
                          >
                            {prompt}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  messages.map((msg) => (
                    <div
                      key={msg.id}
                      className={`space-y-2 ${
                        msg.role === "user" ? "pl-8" : "pr-2"
                      }`}
                    >
                      {/* Message Header */}
                      <div className="flex items-center justify-between gap-2 text-[11px] text-ink-3">
                        <span className="flex items-center gap-1.5 font-semibold">
                          {msg.role === "user" ? (
                            <>
                              <span className="w-2 h-2 bg-info border border-line" />
                              <span className="text-ink-2">Analyst Query</span>
                            </>
                          ) : (
                            <>
                              <span className="w-2 h-2 bg-accent" />
                              <span className="text-ink">
                                Grounded AI Analyst ({selectedModel.split(":")[0]})
                              </span>
                            </>
                          )}
                        </span>
                        {msg.status && (
                          <span
                            className={`px-1.5 py-0.5 text-[11px] font-semibold border ${
                              msg.status === "ANSWERED"
                                ? "bg-positive-bg text-positive border-positive-border"
                                : msg.status === "INSUFFICIENT_EVIDENCE"
                                ? "bg-medium-bg text-medium border-medium-border"
                                : "bg-panel-2 text-ink-2 border-line"
                            }`}
                          >
                            {msg.status}
                          </span>
                        )}
                      </div>

                      {/* Message Body */}
                      <div
                        className={`p-3.5 border text-xs leading-relaxed ${
                          msg.role === "user"
                            ? "bg-panel-2 border-line text-ink"
                            : "bg-panel border-line-strong text-ink space-y-3"
                        }`}
                      >
                        {/* Text */}
                        <div className="whitespace-pre-wrap font-sans text-[13px]">
                          {msg.content}
                        </div>

                        {/* Citation Chips in Answer */}
                        {msg.citations && msg.citations.length > 0 && (
                          <div className="pt-2 border-t border-line flex flex-wrap gap-1.5 items-center">
                            <span className="text-[11px] text-ink-3 uppercase tracking-wide mr-1">
                              Cited Sources:
                            </span>
                            {msg.citations.map((c, i) => (
                              <button
                                key={i}
                                onClick={() => setSelectedSourceId(c.source_id)}
                                aria-pressed={selectedSourceId === c.source_id}
                                className={`px-2 py-0.5 text-[11px] font-mono border transition-colors flex items-center gap-1 ${
                                  selectedSourceId === c.source_id
                                    ? "bg-accent-press text-on-accent border-accent-border font-semibold"
                                    : "bg-panel-2 border-line text-ink-2 hover:border-line-strong"
                                }`}
                              >
                                <span>[{c.source_id.split(":")[0]}: {c.locator || c.title}]</span>
                              </button>
                            ))}
                          </div>
                        )}

                        {/* Itemized Claims with Epistemic State Badges */}
                        {msg.claims && msg.claims.length > 0 && (
                          <div className="pt-2 border-t border-line space-y-1">
                            <p className="text-[11px] text-ink-3 uppercase tracking-wide">
                              Verified Epistemic Claims:
                            </p>
                            <div className="space-y-1">
                              {msg.claims.map((claim, ci) => (
                                <div
                                  key={ci}
                                  className="flex items-start justify-between gap-2 text-[11px] bg-panel-2 p-1.5 border border-line"
                                >
                                  <span className="text-ink-2 pr-2">
                                    • {claim.text}
                                  </span>
                                  <span
                                    className={`px-1.5 py-0.5 text-[11px] font-mono font-semibold uppercase shrink-0 border ${
                                      EPISTEMIC_CLAIM_STYLES[claim.epistemic_state] || "bg-medium-bg text-medium border-medium-border"
                                    }`}
                                  >
                                    {claim.epistemic_state}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Provenance & Action Footer */}
                        {msg.role === "assistant" && (
                          <div className="pt-2 border-t border-line flex items-center justify-between gap-2 text-[11px] text-ink-3 font-mono">
                            <div className="flex items-center gap-3">
                              {msg.provenance && (
                                <>
                                  <span title="SHA-256 hash of answer text">
                                    ANS: {msg.provenance.answer_hash.slice(0, 8)}...
                                  </span>
                                  <span title="SHA-256 hash of FactLock context">
                                    FACTS: {msg.provenance.fact_lock_hash.slice(0, 8)}...
                                  </span>
                                </>
                              )}
                              {msg.metrics?.total_ms && (
                                <span>{msg.metrics.total_ms}ms</span>
                              )}
                            </div>

                            <button
                              onClick={() => handleCopy(msg.content, msg.id)}
                              className="flex items-center gap-1 hover:text-ink transition-colors"
                            >
                              {copiedId === msg.id ? (
                                <>
                                  <Check className="w-3 h-3 text-positive" />
                                  <span className="text-positive">Copied</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  <span>Copy</span>
                                </>
                              )}
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  ))
                )}

                {/* Live Grounding State Indicator */}
                {isGenerating && (
                  <div className="p-3 border border-medium-border bg-medium-bg text-medium space-y-1" role="status" aria-live="polite">
                    <div className="flex items-center gap-2 text-xs font-semibold">
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>{generationStep || "Processing..."}</span>
                    </div>
                    <p className="text-[11px]">
                      Enforcing FactLock, standards cross-referencing, and zero-hallucination integrity gates.
                    </p>
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>
            </div>
          </Section>

          {/* §3 Composer */}
          <Section index="§3" title="Ask the Analyst" description="Responses are bounded to this investigation's evidence graph and indexed standards corpus.">
            <Card>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleSend();
                }}
                className="flex gap-2"
              >
                <Input
                  mono
                  type="text"
                  value={inputQuery}
                  onChange={(e) => setInputQuery(e.target.value)}
                  disabled={isGenerating}
                  placeholder={
                    evidenceOnlyMode
                      ? "Search findings and standards without generative AI..."
                      : "Ask about this investigation — findings, IKE negotiation, scores, RFCs..."
                  }
                  aria-label={evidenceOnlyMode ? "Evidence search query" : "Question for the AI analyst"}
                />
                <Button
                  type="submit"
                  variant="primary"
                  disabled={!inputQuery.trim() || isGenerating}
                >
                  <span>{evidenceOnlyMode ? "Search" : "Ask"}</span>
                  <Send className="w-3.5 h-3.5" />
                </Button>
              </form>
            </Card>
          </Section>
        </div>

        {/* Right Column: Persistent Sources & Evidence Panel (4 cols) */}
        <div className="lg:col-span-4 space-y-5">
          <Section index="§4" title="Evidence & Standards" description="Sources cited by the analyst's latest response.">
            <Card
              padded={false}
              title="Forensic Evidence & Standards"
              actions={
                <div className="flex gap-1 text-[11px] font-mono">
                  {(["ALL", "STANDARDS", "FINDINGS", "FACTS"] as const).map((cat) => (
                    <button
                      key={cat}
                      onClick={() => setSourceFilter(cat)}
                      aria-pressed={sourceFilter === cat}
                      className={`px-1.5 py-0.5 border ${
                        sourceFilter === cat
                          ? "bg-ink text-ground border-transparent font-semibold"
                          : "border-line text-ink-3 hover:bg-panel-2"
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              }
            >
              <div className="space-y-3 text-xs font-mono max-h-[580px] overflow-y-auto p-3">
                {filteredCitations.length === 0 ? (
                  <EmptyState
                    compact
                    icon={<BookOpen className="w-5 h-5" />}
                    title="No sources cited in the current response"
                    description="When the AI Analyst answers, all verified findings, SA transforms, and RFC normative chunks appear here."
                  />
                ) : (
                  filteredCitations.map((cit, idx) => {
                    const isSelected = selectedSourceId === cit.source_id;
                    const isStandard = cit.source_type === "standard" || cit.source_id.startsWith("standard:");
                    const isFinding = cit.source_type === "finding" || cit.source_id.startsWith("finding:");

                    return (
                      <div
                        key={idx}
                        role="button"
                        tabIndex={0}
                        onClick={() => setSelectedSourceId(cit.source_id)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            setSelectedSourceId(cit.source_id);
                          }
                        }}
                        aria-pressed={isSelected}
                        className={`p-3 border cursor-pointer transition-colors ${
                          isSelected
                            ? "bg-accent-soft border-accent-border"
                            : "bg-panel border-line hover:border-line-strong"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 pb-1 border-b border-line">
                          <span className="text-[11px] font-semibold text-ink-3 uppercase tracking-wide">
                            {cit.source_type}
                          </span>
                          <span className="text-[11px] text-ink-3 truncate">
                            {cit.source_id}
                          </span>
                        </div>

                        <div className="pt-2 space-y-1.5">
                          <p className="font-semibold text-ink">
                            {cit.title || cit.locator}
                          </p>
                          {cit.excerpt && (
                            <p className="text-[11px] text-ink-3 leading-normal bg-panel-2 p-2 border border-line">
                              {cit.excerpt}
                            </p>
                          )}

                          {/* Deep link action */}
                          <div className="pt-1 flex justify-end">
                            {isFinding ? (
                              <Link
                                href={`/analyses/${analysisId}/security#findings`}
                                className="text-[11px] text-accent-ink hover:underline flex items-center gap-1"
                              >
                                <span>Open Finding Inspector</span>
                                <ExternalLink className="w-3 h-3" />
                              </Link>
                            ) : isStandard ? (
                              <span className="text-[11px] text-positive font-semibold">
                                Authoritative Local Standard
                              </span>
                            ) : (
                              <Link
                                href={`/analyses/${analysisId}/protocol`}
                                className="text-[11px] text-ink-3 hover:underline flex items-center gap-1"
                              >
                                <span>Inspect SA Protocol</span>
                                <ExternalLink className="w-3 h-3" />
                              </Link>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </Card>
          </Section>

          {/* Subsystem Isolation Notice */}
          <div className="p-3 bg-panel-2 border border-line text-xs text-ink-3 space-y-1">
            <div className="flex items-center gap-1.5 font-semibold text-ink-2">
              <Lock className="w-3.5 h-3.5 text-accent" />
              <span>Read-Only Explanatory Boundary</span>
            </div>
            <p>
              The AI Analyst is strictly explanatory. It cannot alter Security Scores,
              modify Policy-as-Code rules, or execute strongSwan remediations.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
