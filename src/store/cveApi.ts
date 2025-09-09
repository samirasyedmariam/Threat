import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8080/api";


export interface Cve {
  id?: number | string;
  cveId?: string;
  description?: string;
  publishedDate?: string | null;
  lastModifiedDate?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
  cvssV2?: number | null;
  cvssV3?: number | null;
  rawJson?: CveRoot | any; 
}


export interface CveRoot {
  cve: NvdCve;
}

export interface NvdCve {
  id: string;
  sourceIdentifier: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  cveTags?: string[];
  descriptions?: Description[];
  metrics?: Metrics;
  weaknesses?: Weakness[];
  configurations?: Configuration[];
  references?: Reference[];
}

export interface Description {
  lang: string;
  value: string;
}

export interface Metrics {
  cvssMetricV2?: CvssMetricV2[];
  cvssMetricV30?: CvssMetricV3[];
  cvssMetricV31?: CvssMetricV3[];
}

export interface CvssMetricV2 {
  source: string;
  type: string;
  cvssData: CvssDataV2;
  baseSeverity: string;
  exploitabilityScore: number;
  impactScore: number;
  acInsufInfo: boolean;
  obtainAllPrivilege: boolean;
  obtainUserPrivilege: boolean;
  obtainOtherPrivilege: boolean;
  userInteractionRequired: boolean;
}

export interface CvssDataV2 {
  version: string;
  vectorString: string;
  baseScore: number;
  accessVector: string;
  accessComplexity: string;
  authentication: string;
  confidentialityImpact: string;
  integrityImpact: string;
  availabilityImpact: string;
}

export interface CvssMetricV3 {
  source: string;
  type: string;
  cvssData: CvssDataV3;
  exploitabilityScore: number;
  impactScore: number;
}

export interface CvssDataV3 {
  version: string;
  vectorString: string;
  baseScore: number;
  baseSeverity: string;
  attackVector: string;
  attackComplexity: string;
  privilegesRequired: string;
  userInteraction: string;
  scope: string;
  confidentialityImpact: string;
  integrityImpact: string;
  availabilityImpact: string;
}

export interface Weakness {
  source: string;
  type: string;
  description: Description[];
}

export interface Configuration {
  operator: string;
  negate: boolean;
  nodes: Node[];
}

export interface Node {
  operator: string;
  negate: boolean;
  cpeMatch: CpeMatch[];
}

export interface CpeMatch {
  vulnerable: boolean;
  criteria: string;
  matchCriteriaId: string;
  versionEndExcluding?: string;
  versionEndIncluding?: string;
}

export interface Reference {
  url: string;
  source?: string;
  tags?: string[];
}

export const cveApi = createApi({
  reducerPath: "cveApi",
  baseQuery: fetchBaseQuery({
    baseUrl: API_BASE,
    credentials: "include", 
  }),
  endpoints: (builder) => ({
   
   getCves: builder.query<
      { cves: Cve[]; total: number; page?: number; size?: number },
      {
        page: number;
        limit: number;
        year?: number | null;
        minScore?: number | null;
        lastModifiedDays?: number | null;
        sort?: string | null;
        direction?: "asc" | "desc" | null;
        cveId?: string | null;
        q?: string | null;
        filterColumn?: string | null;
        filterValue?: string | null;
      }
    >({
      query: ({
        page,
        limit,
        year,
        minScore,
        lastModifiedDays,
        sort = "publishedDate",
        direction = "desc",
        cveId,
        q,
        filterColumn,
        filterValue,
      }) => {
        const params = new URLSearchParams();

        // Convert frontend 1-based page -> backend 0-based page
        const backendPage = Math.max(0, (page || 1) - 1);
        params.set("page", String(backendPage));
        params.set("size", String(limit || 10));

        if (typeof year !== "undefined" && year !== null) params.set("year", String(year));
        if (typeof minScore !== "undefined" && minScore !== null) params.set("minScore", String(minScore));
        if (typeof lastModifiedDays !== "undefined" && lastModifiedDays !== null) params.set("lastModifiedDays", String(lastModifiedDays));
        if (cveId) params.set("cveId", cveId);
        if (q) params.set("q", q);
        if (filterColumn) params.set("filterColumn", filterColumn);
        if (filterValue) params.set("filterValue", filterValue);

        if (sort) params.set("sort", sort);
        if (direction) params.set("direction", direction);

        return `/cves?${params.toString()}`;
      },
      transformResponse: (response: any) => {
        // Try to handle various server shapes:
        // - Spring Page: { content: [...], totalElements, number, size }
        // - custom: { content: [...], total: N, number, size }
        // - minimal: array
        let results: any[] = [];
        let total = 0;
        let page: number | undefined = undefined;
        let size: number | undefined = undefined;

        if (!response) {
          return { cves: [], total: 0 };
        }

        if (Array.isArray(response)) {
          results = response;
          total = results.length;
        } else if (Array.isArray(response?.content)) {
          results = response.content;
          total = typeof response.totalElements === "number" ? response.totalElements : (typeof response.total === "number" ? response.total : results.length);
          page = typeof response.number === "number" ? response.number : undefined;
          size = typeof response.size === "number" ? response.size : undefined;
        } else if (Array.isArray(response?.cves)) {
          results = response.cves;
          total = typeof response.total === "number" ? response.total : results.length;
          page = typeof response.page === "number" ? response.page : undefined;
          size = typeof response.size === "number" ? response.size : undefined;
        } else {
          // fallback: try to interpret response as single object/record -> wrap into array
          results = [response];
          total = 1;
        }

        return { cves: results as Cve[], total, page, size };
      },
    }),

    /**
     * getCveById - fetch single CVE record
     */
    getCveById: builder.query<Cve, string>({
      query: (id) => `/cves/${encodeURIComponent(id)}`,
      transformResponse: (response: any) => {
        // backend might wrap the entity in an object; just return the payload
        if (!response) return {} as Cve;
        return response as Cve;
      },
    }),

    /**
     * getYears - optionally fetch distinct publish years from the DB
     * Backend endpoint: GET /api/cves/years -> [2025,2024,...] or { years: [...] }
     */
    getYears: builder.query<number[], void>({
      query: () => `/cves/years`,
      transformResponse: (response: any) => {
        if (Array.isArray(response)) return response as number[];
        if (Array.isArray(response?.years)) return response.years as number[];
        return [];
      },
      // small cache time because years don't change often
      keepUnusedDataFor: 60 * 5,
    }),
  }),
});

export const { useGetCvesQuery, useGetCveByIdQuery } = cveApi;
