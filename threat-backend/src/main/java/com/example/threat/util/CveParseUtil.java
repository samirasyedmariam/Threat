package com.example.threat.util;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Optional;

public final class CveParseUtil {
    private CveParseUtil() {}

    public static Optional<String> extractCveId(JsonNode item) {
        if (item == null || item.isMissingNode()) return Optional.empty();
        JsonNode cveNode = safeNode(item, "cve");
        if (cveNode != null && !cveNode.isMissingNode()) {
            String id = safeText(cveNode, "id");
            if (isNotBlank(id)) return Optional.of(id);
            id = safeText(safeNode(cveNode, "CVE_data_meta"), "ID");
            if (isNotBlank(id)) return Optional.of(id);
        }
        String id = safeText(item, "id");
        if (isNotBlank(id)) return Optional.of(id);
        id = safeText(safeNode(item, "CVE_data_meta"), "ID");
        if (isNotBlank(id)) return Optional.of(id);
        return Optional.empty();
    }

    public static String extractDescription(JsonNode item) {
        JsonNode cveNode = safeNode(item, "cve");
        JsonNode descs = safeNode(cveNode, "descriptions");
        if (descs != null && descs.isArray() && descs.size() > 0) {
            return safeText(descs.get(0), "value");
        }
        JsonNode descData = safeNode(cveNode, "description");
        if (descData != null) {
            JsonNode arr = safeNode(descData, "description_data");
            if (arr != null && arr.isArray() && arr.size() > 0) {
                return safeText(arr.get(0), "value");
            }
        }
        return safeText(cveNode, "description");
    }

    public static Optional<OffsetDateTime> parseOffsetDateTime(String raw) {
        if (raw == null || raw.isBlank()) return Optional.empty();
        try {
            return Optional.of(OffsetDateTime.parse(raw));
        } catch (DateTimeParseException e) {
            try {
                // Try trimming or fallback formats if necessary (expand here)
                return Optional.of(OffsetDateTime.parse(raw));
            } catch (Exception ex) {
                return Optional.empty();
            }
        }
    }

    public static Optional<Double> extractCvssV3(JsonNode item) {
        if (item == null || item.isMissingNode()) return Optional.empty();
        JsonNode metrics = safeNode(item, "metrics");
        if (metrics != null && !metrics.isMissingNode()) {
            JsonNode v3arr = safeNode(metrics, "cvssMetricV3");
            if (v3arr != null && v3arr.isArray() && v3arr.size() > 0) {
                JsonNode scoreNode = safeNode(v3arr.get(0), "cvssData");
                if (scoreNode != null) scoreNode = safeNode(scoreNode, "baseScore");
                if (scoreNode != null && scoreNode.isNumber()) return Optional.of(scoreNode.asDouble());
                if (scoreNode != null && scoreNode.isTextual()) return tryParseDouble(scoreNode.asText());
            }
        }
        // legacy: impact.baseMetricV3...
        JsonNode impact = safeNode(item, "impact");
        if (impact != null) {
            JsonNode v3 = safeNode(safeNode(impact, "baseMetricV3"), "cvssV3");
            if (v3 != null) {
                JsonNode baseScore = safeNode(v3, "baseScore");
                if (baseScore != null && baseScore.isNumber()) return Optional.of(baseScore.asDouble());
            }
        }
        return Optional.empty();
    }

    public static Optional<Double> extractCvssV2(JsonNode item) {
        if (item == null || item.isMissingNode()) return Optional.empty();
        JsonNode metrics = safeNode(item, "metrics");
        if (metrics != null && !metrics.isMissingNode()) {
            JsonNode v2arr = safeNode(metrics, "cvssMetricV2");
            if (v2arr != null && v2arr.isArray() && v2arr.size() > 0) {
                JsonNode scoreNode = safeNode(v2arr.get(0), "cvssData");
                if (scoreNode != null) scoreNode = safeNode(scoreNode, "baseScore");
                if (scoreNode != null && scoreNode.isNumber()) return Optional.of(scoreNode.asDouble());
                if (scoreNode != null && scoreNode.isTextual()) return tryParseDouble(scoreNode.asText());
            }
        }
        JsonNode impact = safeNode(item, "impact");
        if (impact != null) {
            JsonNode v2 = safeNode(safeNode(impact, "baseMetricV2"), "cvssV2");
            if (v2 != null) {
                JsonNode baseScore = safeNode(v2, "baseScore");
                if (baseScore != null && baseScore.isNumber()) return Optional.of(baseScore.asDouble());
            }
        }
        return Optional.empty();
    }

    // helpers
    private static JsonNode safeNode(JsonNode node, String name) {
        if (node == null || node.isMissingNode()) return null;
        JsonNode child = node.path(name);
        return child.isMissingNode() ? null : child;
    }

    private static String safeText(JsonNode node, String field) {
        if (node == null || node.isMissingNode()) return "";
        JsonNode f = node.path(field);
        if (f.isMissingNode() || f.isNull()) return "";
        return f.asText("");
    }

    private static boolean isNotBlank(String s) {
        return s != null && !s.trim().isEmpty();
    }

    private static Optional<Double> tryParseDouble(String t) {
        if (t == null || t.isBlank()) return Optional.empty();
        try { return Optional.of(Double.valueOf(t)); } catch (NumberFormatException e) { return Optional.empty(); }
    }
}
