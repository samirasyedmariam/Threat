"use client";
import React, { useState } from "react";

interface CveDetailsProps {
  data: any;
}

export default function CveDetails({ data }: CveDetailsProps) {
  const [showJson, setShowJson] = useState(false);

  const cve = data.cve || {};
  const cvssV2 = data.metrics?.cvssMetricV2?.[0];
  const weaknesses = data.weaknesses || [];
  const configs = data.configurations || [];
  const refs = data.references || [];

  return (
    <div className="max-w-5xl mx-auto p-6 text-sm">

      <div className="flex justify-between items-center mb-4">
        <h1 className="text-2xl font-bold">{cve.id}</h1>
        <span
          className={`px-3 py-1 rounded-full text-xs font-medium ${
            cve.vulnStatus === "Deferred"
              ? "bg-yellow-100 text-yellow-800"
              : "bg-green-100 text-green-800"
          }`}
        >
          {cve.vulnStatus}
        </span>
      </div>

      <p className="mb-4 text-gray-600">
        <strong>Published:</strong>{" "}
        {new Date(cve.published).toLocaleDateString()} &nbsp; | &nbsp;
        <strong>Last Modified:</strong>{" "}
        {new Date(cve.lastModified).toLocaleDateString()}
      </p>


      <div className="mb-6">
        <h2 className="text-lg font-semibold mb-2">Description</h2>
        {cve.descriptions?.map((desc: any, i: number) => (
          <p key={i} className="mb-2">
            <span className="italic text-gray-500">[{desc.lang}]</span>{" "}
            {desc.value}
          </p>
        ))}
      </div>


      {cvssV2 && (
        <div className="mb-6">
          <h2 className="text-lg font-semibold mb-2">CVSS v2 Metrics</h2>
          <p>
            <strong>Severity:</strong> {cvssV2.baseSeverity} &nbsp; | &nbsp;
            <strong>Score:</strong> {cvssV2.cvssData.baseScore} &nbsp; | &nbsp;
            <strong>Vector:</strong> {cvssV2.cvssData.vectorString}
          </p>

          <table className="w-full mt-3 border text-xs">
            <thead className="bg-gray-100">
              <tr>
                <th className="border px-2 py-1">Access Vector</th>
                <th className="border px-2 py-1">Access Complexity</th>
                <th className="border px-2 py-1">Authentication</th>
                <th className="border px-2 py-1">Confidentiality</th>
                <th className="border px-2 py-1">Integrity</th>
                <th className="border px-2 py-1">Availability</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="border px-2 py-1">
                  {cvssV2.cvssData.accessVector}
                </td>
                <td className="border px-2 py-1">
                  {cvssV2.cvssData.accessComplexity}
                </td>
                <td className="border px-2 py-1">
                  {cvssV2.cvssData.authentication}
                </td>
                <td className="border px-2 py-1">
                  {cvssV2.cvssData.confidentialityImpact}
                </td>
                <td className="border px-2 py-1">
                  {cvssV2.cvssData.integrityImpact}
                </td>
                <td className="border px-2 py-1">
                  {cvssV2.cvssData.availabilityImpact}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      )}


      {weaknesses.length > 0 && (
        <div className="mb-6">
          <h2 className="text-lg font-semibold mb-2">Weakness</h2>
          <ul className="list-disc pl-6">
            {weaknesses.map((w: any, i: number) => (
              <li key={i}>
                {w.description?.[0]?.value} ({w.source})
              </li>
            ))}
          </ul>
        </div>
      )}

      {configs.length > 0 && (
        <div className="mb-6">
          <h2 className="text-lg font-semibold mb-2">CPE</h2>
          {configs.map((conf: any, i: number) => (
            <div key={i} className="mb-4">
              {conf.nodes.map((node: any, j: number) => (
                <table
                  key={j}
                  className="w-full border text-xs mb-2 shadow-sm"
                >
                  <thead className="bg-gray-100">
                    <tr>
                      <th className="border px-2 py-1">Criteria</th>
                      <th className="border px-2 py-1">Match ID</th>
                      <th className="border px-2 py-1">Vulnerable</th>
                    </tr>
                  </thead>
                  <tbody>
                    {node.cpeMatch.map((c: any, k: number) => (
                      <tr key={k}>
                        <td className="border px-2 py-1">{c.criteria}</td>
                        <td className="border px-2 py-1">
                          {c.matchCriteriaId}
                        </td>
                        <td className="border px-2 py-1">
                          {c.vulnerable ? "Yes" : "No"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ))}
            </div>
          ))}
        </div>
      )}

      {refs.length > 0 && (
        <div className="mb-6">
          <h2 className="text-lg font-semibold mb-2">References</h2>
          <ul className="list-disc pl-6">
            {refs.map((r: any, i: number) => (
              <li key={i}>
                <a
                  href={r.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:underline"
                >
                  {r.url}
                </a>{" "}
                <span className="text-gray-500">({r.source})</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div>
        <button
          onClick={() => setShowJson(!showJson)}
          className="px-4 py-2 bg-gray-200 rounded text-xs hover:bg-gray-300"
        >
          {showJson ? "Hide Raw JSON" : "Show Raw JSON"}
        </button>
        {showJson && (
          <pre className="mt-3 bg-gray-900 text-green-400 text-xs p-3 rounded overflow-x-auto">
            {JSON.stringify(data, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}
