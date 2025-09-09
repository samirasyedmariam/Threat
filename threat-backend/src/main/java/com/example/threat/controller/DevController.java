package com.example.threat.controller;

import com.example.threat.service.CveSyncService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Value;

@RestController
@RequestMapping("/api/dev")
public class DevController {
    private final CveSyncService syncService;

    @Value("${dev.sync-token:}")
    private String expectedToken;

    public DevController(CveSyncService syncService) {
        this.syncService = syncService;
    }

    @PostMapping("/sync")
    public ResponseEntity<String> syncNow(@RequestHeader(value = "X-ADMIN-TOKEN", required = false) String token) {
        if (expectedToken != null && !expectedToken.isBlank()) {
            if (token == null || !token.equals(expectedToken)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Forbidden");
            }
        }
        syncService.asyncSync();
        return ResponseEntity.accepted().body("Sync started");
    }
}
