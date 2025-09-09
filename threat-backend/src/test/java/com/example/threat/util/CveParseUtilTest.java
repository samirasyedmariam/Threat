package com.example.threat.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class CveParseUtilTest {
    private final ObjectMapper mapper = new ObjectMapper();


    @Test
    void extractIdFromDifferentShapes() {
        ObjectNode root = mapper.createObjectNode();
        ObjectNode cve = mapper.createObjectNode();
        cve.put("id", "CVE-2025-0001");
        root.set("cve", cve);
        Optional<String> id = CveParseUtil.extractCveId(root);
        assertTrue(id.isPresent());
        assertEquals("CVE-2025-0001", id.get());
    }

    @Test
    void parseDatesSafely() {
        String iso = "2024-05-01T12:00:00Z";
        Optional result = CveParseUtil.parseOffsetDateTime(iso);
        assertTrue(result.isPresent());
    }

    @Test
    void cvssExtractionHandlesMissing() throws Exception {
        ObjectNode root = mapper.createObjectNode();
        assertTrue(CveParseUtil.extractCvssV3(root).isEmpty());
        assertTrue(CveParseUtil.extractCvssV2(root).isEmpty());
    }
}
