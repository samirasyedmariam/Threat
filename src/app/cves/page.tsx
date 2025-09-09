// src/app/cves/components/CveTable.tsx
"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import { Funnel } from "lucide-react";
import Link from "next/link";
import { useGetCvesQuery } from "@/store/cveApi";

type FilterState = {
  column: string | null;
  value: string;
};

type ToastItem = {
  id: number;
  text: string;
};

export default function CveTable() {
  const [page, setPage] = useState<number>(1); // 1-based UI
  const [limit, setLimit] = useState<number>(10);

  // search/filter state
  const [globalSearch, setGlobalSearch] = useState<string>("");
  const [filterDraft, setFilterDraft] = useState<FilterState>({
    column: null,
    value: "",
  });
  const [filterVisibleCol, setFilterVisibleCol] = useState<string | null>(null);

  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const inputRef = useRef<HTMLInputElement | null>(null);

  // click outside to hide column filter input
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (inputRef.current && !inputRef.current.contains(e.target as Node)) {
        setFilterVisibleCol(null);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Prepare query params passed to RTK Query (live values)
  const queryParams = useMemo(() => {
    return {
      page,
      limit,
      q: globalSearch.trim() || undefined,
      filterColumn: filterDraft.column || undefined,
      filterValue: filterDraft.value.trim() || undefined,
    };
  }, [page, limit, globalSearch, filterDraft]);

  const { data, isLoading, isFetching, isError } = useGetCvesQuery(queryParams, {
    refetchOnFocus: false,
    refetchOnReconnect: false,
  });

  // Toast helper
  function pushToast(text: string) {
    const id = Date.now() + Math.floor(Math.random() * 999);
    setToasts((t) => [...t, { id, text }]);
    setTimeout(() => {
      setToasts((t) => t.filter((x) => x.id !== id));
    }, 3500);
  }

  // Show toast on error
  useEffect(() => {
    if (isError) {
      pushToast("No relevant data (server error).");
    }
  }, [isError]);

  // Show toast on empty results
  useEffect(() => {
    const cves = data?.cves ?? [];
    if (
      !isLoading &&
      !isFetching &&
      Array.isArray(cves) &&
      cves.length === 0 &&
      (data?.total ?? 0) === 0
    ) {
      pushToast("No relevant data.");
    }
  }, [data, isLoading, isFetching]);

  if (isLoading) return <p className="text-center p-4">Loading…</p>;

  const cves = data?.cves ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <>
      <div className="p-4">
        <div className="flex flex-wrap justify-between items-center gap-3 mb-3">
          <h2 className="text-lg font-semibold">
            CVE LIST <span className="text-gray-500">(Total: {total})</span>
          </h2>

          {/* Global search */}
          <div className="flex items-center gap-2">
            <input
              type="text"
              className="border rounded px-3 py-1 text-sm w-64"
              placeholder="Search globally..."
              value={globalSearch}
              onChange={(e) => {
                setGlobalSearch(e.target.value);
                setPage(1);
              }}
            />
          </div>

          <div className="flex items-center text-sm">
            <span className="mr-2">Results per page</span>
            <select
              value={limit}
              onChange={(e) => {
                setLimit(Number(e.target.value));
                setPage(1);
              }}
              className="border rounded px-2 py-1 text-sm"
            >
              {[10, 25, 50, 100].map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </div>
        </div>

        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="bg-gray-100 text-left text-xs font-semibold">
              {["cveId", "description", "createdAt", "updatedAt", "cvssV3"].map(
                (col) => (
                  <th key={col} className="relative px-3 py-2 border">
                    <div className="flex justify-between items-center">
                      <span className="capitalize">
                        {col === "cvssV3" ? "Score (v3)" : col}
                      </span>
                      <Funnel
                        className="w-4 h-4 cursor-pointer text-gray-500"
                        onClick={() => {
                          if (filterVisibleCol === col) {
                            setFilterVisibleCol(null);
                            setFilterDraft({ column: null, value: "" });
                          } else {
                            setFilterVisibleCol(col);
                            setFilterDraft({
                              column: col,
                              value:
                                filterDraft.column === col
                                  ? filterDraft.value
                                  : "",
                            });
                          }
                        }}
                      />
                    </div>

                    {filterVisibleCol === col && (
                      <div className="mt-1">
                        <input
                          ref={inputRef}
                          type="text"
                          className="w-full border px-2 py-1 text-xs rounded"
                          placeholder={`Filter ${col} (server-side)`}
                          value={
                            filterDraft.column === col ? filterDraft.value : ""
                          }
                          onChange={(e) => {
                            setFilterDraft({ column: col, value: e.target.value });
                            setPage(1);
                          }}
                        />
                      </div>
                    )}
                  </th>
                )
              )}
            </tr>
          </thead>

          <tbody>
            {cves.length === 0 ? (
              <tr>
                <td colSpan={6} className="p-4 text-center text-gray-500">
                  No records
                </td>
              </tr>
            ) : (
              cves.map((cve) => {
                const id = cve.cveId ?? cve.id;
                return (
                  <tr key={String(id)} className="border-b hover:bg-gray-50">
                    <td className="px-3 py-2 text-blue-600 underline">
                      <Link href={`/cves/${encodeURIComponent(String(id))}`}>
                        {id}
                      </Link>
                    </td>
                    <td
                      className="px-3 py-2 max-w-xs truncate"
                      title={cve.description}
                    >
                      {cve.description}
                    </td>
                    <td className="px-3 py-2">{cve.createdAt ?? "-"}</td>
                    <td className="px-3 py-2">{cve.updatedAt ?? "-"}</td>
                    <td className="px-3 py-2">{cve.cvssV3 ?? "-"}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>

        {/* Pagination */}
        <div className="flex justify-between items-center mt-4 text-sm">
          <span>
            {total === 0
              ? "0 records"
              : `${Math.min((page - 1) * limit + 1, total)} – ${Math.min(
                  page * limit,
                  total
                )} of ${total} records`}
          </span>

          <div className="flex items-center space-x-1">
            <button
              disabled={page === 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="px-2 py-1 border rounded disabled:opacity-50"
            >
              ◀
            </button>

            {(() => {
              const maxButtons = 5;
              const pages: number[] = [];
              const totalPagesLocal = Math.max(1, totalPages);

              let start = Math.max(1, page - Math.floor(maxButtons / 2));
              let end = start + maxButtons - 1;
              if (end > totalPagesLocal) {
                end = totalPagesLocal;
                start = Math.max(1, end - maxButtons + 1);
              }

              for (let i = start; i <= end; i++) pages.push(i);

              const elems: React.ReactNode[] = [];
              if (start > 1) {
                elems.push(
                  <button
                    key={1}
                    onClick={() => setPage(1)}
                    className="px-3 py-1 border rounded bg-white hover:bg-gray-100"
                  >
                    1
                  </button>
                );
                if (start > 2)
                  elems.push(
                    <span key="left-ellipsis" className="px-2 text-gray-500">
                      …
                    </span>
                  );
              }

              pages.forEach((num) =>
                elems.push(
                  <button
                    key={num}
                    onClick={() => setPage(num)}
                    className={`px-3 py-1 border rounded ${
                      num === page
                        ? "bg-blue-600 text-white"
                        : "bg-white hover:bg-gray-100"
                    }`}
                  >
                    {num}
                  </button>
                )
              );

              if (end < totalPagesLocal) {
                if (end < totalPagesLocal - 1)
                  elems.push(
                    <span key="right-ellipsis" className="px-2 text-gray-500">
                      …
                    </span>
                  );
                elems.push(
                  <button
                    key={totalPagesLocal}
                    onClick={() => setPage(totalPagesLocal)}
                    className="px-3 py-1 border rounded bg-white hover:bg-gray-100"
                  >
                    {totalPagesLocal}
                  </button>
                );
              }

              return elems;
            })()}

            <button
              disabled={page === totalPages || totalPages === 0}
              onClick={() =>
                setPage((p) => Math.min(totalPages || p, p + 1))
              }
              className="px-2 py-1 border rounded disabled:opacity-50"
            >
              ▶
            </button>
          </div>
        </div>
      </div>

      {/* Toasts container */}
      <div
        aria-live="polite"
        className="fixed z-50 bottom-6 right-6 flex flex-col gap-2"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            className="min-w-[220px] max-w-sm bg-gray-900 text-white text-sm px-4 py-2 rounded shadow-md opacity-95"
          >
            {t.text}
          </div>
        ))}
      </div>
    </>
  );
}
