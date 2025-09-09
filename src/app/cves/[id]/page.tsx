"use client";

import React, { useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import type {
  Cve as DbCve,
  NvdCve,
  CvssMetricV2,
  Node as NodeType,
  CpeMatch as CpeMatchType,
} from "@/store/cveApi";
import { useGetCveByIdQuery } from "@/store/cveApi";


type UiCve = {
  id: string;
  description: string;
  severity?: string | null;
  score?: number | null;
  vectorString?: string | null;
  accessVector?: string | null;
  accessComplexity?: string | null;
  authentication?: string | null;
  confidentialityImpact?: string | null;
  integrityImpact?: string | null;
  availabilityImpact?: string | null;
  exploitabilityScore?: number | null;
  impactScore?: number | null;
  cpeMatches: { criteria: string; matchCriteriaId?: string; vulnerable?: boolean }[];
};

function tryParseRawJson(raw: any): any | null {
  if (raw == null) return null;
  if (typeof raw === "object") return raw;
  if (typeof raw === "string") {
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }
  return null;
}

function unwrapNvdCandidate(rawCandidate: any): NvdCve | undefined {
  if (!rawCandidate) return undefined;
  if (rawCandidate.cve && typeof rawCandidate.cve === "object") return rawCandidate.cve as NvdCve;
  if (rawCandidate.id && rawCandidate.descriptions) return rawCandidate as NvdCve;
  return undefined;
}

function firstEnglishDescription(descriptions?: { lang: string; value: string }[] | null, fallback?: string) {
  if (!descriptions) return fallback ?? "-";
  if (typeof descriptions === "string") return descriptions;
  if (!Array.isArray(descriptions)) return fallback ?? "-";
  const en = descriptions.find((d) => d.lang === "en");
  if (en) return en.value ?? fallback ?? "-";
  return descriptions[0]?.value ?? fallback ?? "-";
}

function extractCvssV2(nvd?: NvdCve) {
  if (!nvd) return { metric: null as CvssMetricV2 | null, data: null as any | null };
  const metrics: any = (nvd as any).metrics ?? {};

  const arr = metrics.cvssMetricV2;
  if (Array.isArray(arr) && arr.length) {
    const m = arr[0] as CvssMetricV2;
    const data = (m as any).cvssData ?? (m as any).cvss_data ?? null;
    return { metric: m, data };
  }
  for (const k of Object.keys(metrics)) {
    try {
      const val = metrics[k];
      if (Array.isArray(val) && val.length && String(k).toLowerCase().includes("cvss")) {
        const m = val[0] as CvssMetricV2;
        const data = (m as any).cvssData ?? (m as any).cvss_data ?? null;
        return { metric: m, data };
      }
    } catch {}
  }

  return { metric: null as CvssMetricV2 | null, data: null as any | null };
}

function collectCpeMatches(nvd?: NvdCve) {
  const out: { criteria: string; matchCriteriaId?: string; vulnerable?: boolean }[] = [];
  if (!nvd || !Array.isArray(nvd.configurations)) return out;

  nvd.configurations.forEach((cfg) => {
    const nodes = cfg.nodes ?? [];
    nodes.forEach((node) => {
      const nodeAny = node as any;
      const matches: any[] = nodeAny.cpeMatch ?? nodeAny.cpe_match ?? nodeAny.cpeMatches ?? [];
      (matches || []).forEach((m: any) => {
        const criteria = m.criteria ?? m.cpe23Uri ?? m.cpe ?? String(m ?? "-");
        const matchCriteriaId = m.matchCriteriaId ?? m.match_criteria_id ?? m.matchId ?? undefined;
        const vulnerable = typeof m.vulnerable === "boolean" ? m.vulnerable : !!m.vulnerable;
        out.push({ criteria, matchCriteriaId, vulnerable });
      });
    });
  });

  return out;
}

function mapDbToUi(db?: DbCve | null, paramId?: string): UiCve {
  const rawCandidate = tryParseRawJson((db as any)?.rawJson ?? undefined) ?? tryParseRawJson((db as any)?.raw_json ?? undefined);
  const nvd = unwrapNvdCandidate(rawCandidate);

  const id = (nvd?.id ?? (db?.cveId as string) ?? paramId ?? "unknown").toString();
  const description = firstEnglishDescription(nvd?.descriptions ?? undefined, db?.description ?? "-") ?? "-";

  const { metric, data } = extractCvssV2(nvd);
  const severity = metric?.baseSeverity ?? (metric ? (metric as any).base_severity : undefined) ?? (data?.baseSeverity ?? (data?.base_severity ?? null));
  const score = (data?.baseScore ?? (data?.base_score ?? (metric ? ((metric as any).cvssData?.baseScore ?? (metric as any).baseScore) : undefined))) ?? null;
  const vectorString = (data?.vectorString ?? data?.vector_string) ?? null;

  const accessVector = (data?.accessVector ?? data?.access_vector) ?? null;
  const accessComplexity = (data?.accessComplexity ?? data?.access_complexity) ?? null;
  const authentication = data?.authentication ?? (data ? (data as any).authentication : null) ?? null;
  const confidentialityImpact = (data?.confidentialityImpact ?? data?.confidentiality_impact) ?? null;
  const integrityImpact = (data?.integrityImpact ?? data?.integrity_impact) ?? null;
  const availabilityImpact = (data?.availabilityImpact ?? data?.availability_impact) ?? null;

  const exploitabilityScore = metric?.exploitabilityScore ?? (metric ? (metric as any).exploitability_score : undefined) ?? null;
  const impactScore = metric?.impactScore ?? (metric ? (metric as any).impact_score : undefined) ?? null;

  const cpeMatches = collectCpeMatches(nvd);

  return {
    id,
    description,
    severity,
    score,
    vectorString,
    accessVector,
    accessComplexity,
    authentication,
    confidentialityImpact,
    integrityImpact,
    availabilityImpact,
    exploitabilityScore,
    impactScore,
    cpeMatches,
  };
}

export default function Page() {
  const params = useParams();
  const router = useRouter();
  const idParam = (params?.id as string) ?? undefined;

  const { data, isLoading, isError } = useGetCveByIdQuery(idParam ?? "", { skip: !idParam });
  const ui = useMemo(() => mapDbToUi(data ?? undefined, idParam), [data, idParam]);
  const [showRaw, setShowRaw] = useState(false);

  if (!idParam) return <div className="p-6 text-center">No CVE ID provided</div>;
  if (isLoading) return <div className="p-6 text-center">Loading…</div>;
  if (isError || !data) {
    return (
      <div className="p-6 text-center">
        <p className="mb-3">Not found or error loading CVE.</p>
        <button onClick={() => router.back()} className="px-3 py-1 border rounded text-xs">Back</button>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-5xl mx-auto bg-white p-8 rounded-lg shadow-sm">
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-gray-900">{ui.id}</h1>
        </div>

        <div className="mb-6">
          <h2 className="font-semibold text-gray-800">Description:</h2>
          <p className="mt-2 text-gray-700">{ui.description}</p>
        </div>

        <div className="mb-6">
          <h2 className="font-semibold text-gray-800">CVSS V2 Metrics:</h2>

          <div className="mt-3 flex items-center gap-6">
            <div className="text-sm">
              <span className="text-gray-700 font-medium">Severity:</span>{" "}
              <span className="text-gray-900">{ui.severity ?? "-"}</span>
            </div>
            <div className="text-sm">
              <span className="text-gray-700 font-medium">Score:</span>{" "}
              <span className="text-red-600 font-bold">{ui.score ?? "-"}</span>
            </div>
            <div className="text-sm">
              <span className="text-gray-700 font-medium">Vector String:</span>{" "}
              <span className="text-gray-900">{ui.vectorString ?? "-"}</span>
            </div>
          </div>

          <div className="mt-4 overflow-x-auto">
            <table className="w-full border border-gray-300 text-sm">
              <thead className="bg-gray-100">
                <tr>
                  <th className="border px-2 py-2 text-left">Access Vector</th>
                  <th className="border px-2 py-2 text-left">Access Complexity</th>
                  <th className="border px-2 py-2 text-left">Authentication</th>
                  <th className="border px-2 py-2 text-left">Confidentiality Impact</th>
                  <th className="border px-2 py-2 text-left">Integrity Impact</th>
                  <th className="border px-2 py-2 text-left">Availability Impact</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="border px-2 py-2">{ui.accessVector ?? "-"}</td>
                  <td className="border px-2 py-2">{ui.accessComplexity ?? "-"}</td>
                  <td className="border px-2 py-2">{ui.authentication ?? "-"}</td>
                  <td className="border px-2 py-2">{ui.confidentialityImpact ?? "-"}</td>
                  <td className="border px-2 py-2">{ui.integrityImpact ?? "-"}</td>
                  <td className="border px-2 py-2">{ui.availabilityImpact ?? "-"}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div className="mb-6">
          <h3 className="font-semibold text-gray-800">Scores :</h3>
          <div className="mt-2 text-sm text-gray-700">
            <div><strong>Exploitability Score:</strong> {ui.exploitabilityScore ?? "-"}</div>
            <div><strong>Impact Score:</strong> {ui.impactScore ?? "-"}</div>
          </div>
        </div>

        <div className="mb-6">
          <h3 className="font-semibold text-gray-800">CPE:</h3>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full border border-gray-300 text-sm">
              <thead className="bg-gray-100">
                <tr>
                  <th className="border px-2 py-2 text-left">Criteria</th>
                  <th className="border px-2 py-2 text-left">Match Criteria ID</th>
                  <th className="border px-2 py-2 text-left">Vulnerable</th>
                </tr>
              </thead>
              <tbody>
                {ui.cpeMatches.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="border px-2 py-2 text-center text-gray-500">-</td>
                  </tr>
                ) : (
                  ui.cpeMatches.map((m, i) => (
                    <tr key={i}>
                      <td className="border px-2 py-2 break-words">{m.criteria}</td>
                      <td className="border px-2 py-2">{m.matchCriteriaId ?? "-"}</td>
                      <td className="border px-2 py-2">{m.vulnerable ? "Yes" : "No"}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="mt-6">
          <button
            onClick={() => setShowRaw((s) => !s)}
            className="px-3 py-1 border rounded text-sm bg-gray-100 hover:bg-gray-200"
          >
            {showRaw ? "Hide Raw JSON" : "Show Raw JSON"}
          </button>
          {showRaw && (
            <pre className="mt-3 bg-black text-green-300 text-xs p-3 rounded max-h-96 overflow-auto">
              {JSON.stringify((data as any)?.rawJson ?? data ?? {}, null, 2)}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
