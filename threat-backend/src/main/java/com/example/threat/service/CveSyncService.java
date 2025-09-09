package com.example.threat.service;

import com.example.threat.model.CveEntity;
import com.example.threat.util.CveParseUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.OffsetDateTime;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;

@Service
public class CveSyncService {
    private final CveService cveService;
    private final RestTemplate rest = new RestTemplate();
    private final ObjectMapper mapper = new ObjectMapper();

    @Value("${nvd.base-url}")
    private String nvdBase;

    @Value("${nvd.api-key:}")
    private String apiKey;

    @Value("${nvd.page-size:2000}")
    private int pageSize;

    public CveSyncService(CveService cveService) {
        this.cveService = cveService;
    }

    @Scheduled(cron = "${nvd.sync-cron}")
    public void scheduledSync() {
        asyncSync();
    }

    @Async
    public void asyncSync() {
        try {
            syncAll();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void syncAll() {
        int startIndex = 0;
        boolean more = true;

        while (more) {
            try {
                String url = nvdBase + "?startIndex=" + startIndex + "&resultsPerPage=" + pageSize;
                HttpHeaders headers = new HttpHeaders();
                headers.set("User-Agent", "threat-sync/1.0");
                if (apiKey != null && !apiKey.isBlank()) headers.set("apiKey", apiKey);
                HttpEntity<Void> entity = new HttpEntity<>(headers);
                ResponseEntity<String> resp = fetchPageWithRetries(url, entity);

                if (!resp.getStatusCode().is2xxSuccessful() || resp.getBody() == null) {
                    more = false;
                    break;
                }

                JsonNode root = mapper.readTree(resp.getBody());

                JsonNode vulns = root.path("vulnerabilities");
                if (vulns.isMissingNode() || !vulns.isArray()) {
                    vulns = root.path("result").path("CVE_Items");
                }

                if (!vulns.isArray() || vulns.size() == 0) {
                    more = false;
                    break;
                }

                int processed = 0;
                for (JsonNode item : vulns) {
                    JsonNode cveNode = item.path("cve");
                    if (cveNode.isMissingNode()) cveNode = item;

                    // Extract ID robustly
                    String id = CveParseUtil.extractCveId(item).orElse(null);
                    if (id == null || id.isBlank()) continue;

                    String description = CveParseUtil.extractDescription(item);
                    String publishedStr = cveNode.path("published").asText(null);
                    if (publishedStr == null || publishedStr.isBlank()) {
                        publishedStr = item.path("published").asText(null);
                        if (publishedStr == null || publishedStr.isBlank()) {
                            publishedStr = cveNode.path("Published").asText(null);
                        }
                    }

                    String lastModStr = cveNode.path("lastModified").asText(null);
                    if (lastModStr == null || lastModStr.isBlank()) {
                        lastModStr = item.path("lastModified").asText(null);
                    }

                    CveEntity e = new CveEntity();
                    e.setCveId(id);
                    e.setDescription(description);
                    CveParseUtil.parseOffsetDateTime(publishedStr).ifPresent(e::setPublishedDate);
                    CveParseUtil.parseOffsetDateTime(lastModStr).ifPresent(e::setLastModifiedDate);

                    // cvss
                    CveParseUtil.extractCvssV3(item).ifPresent(e::setCvssV3);
                    CveParseUtil.extractCvssV2(item).ifPresent(e::setCvssV2);

                    e.setRawJson(item.toString());

                    cveService.saveOrUpdate(e);
                    processed++;
                }

                startIndex += pageSize;
                try { TimeUnit.MILLISECONDS.sleep(250); } catch (InterruptedException ignored) {}

                if (processed < pageSize) more = false;
            } catch (Exception ex) {
                ex.printStackTrace();
                more = false;
            }
        }
    }

    private ResponseEntity<String> fetchPageWithRetries(String url, HttpEntity<Void> entity) {
        int attempts = 0;
        long backoff = 1000L;
        while (attempts < 5) {
            attempts++;
            try {
                ResponseEntity<String> resp = rest.exchange(url, HttpMethod.GET, entity, String.class);
                if (resp.getStatusCode().is2xxSuccessful() || resp.getStatusCode().value() == 404) return resp;
                if (resp.getStatusCode().value() == 429 || resp.getStatusCode().is5xxServerError()) {
                    // retryable
                } else {
                    return resp;
                }
            } catch (Exception ex) {
            }
            try { Thread.sleep(backoff); } catch (InterruptedException ignored) {}
            backoff *= 2;
        }
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(null);
    }
}
