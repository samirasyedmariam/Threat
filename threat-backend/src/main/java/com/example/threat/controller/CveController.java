package com.example.threat.controller;

import com.example.threat.model.CveEntity;
import com.example.threat.service.CveService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/cves")
public class CveController {
    private final CveService service;

    public CveController(CveService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<Page<CveEntity>> list(
            @RequestParam Optional<String> cveId,
            @RequestParam Optional<Integer> year,
            @RequestParam Optional<Double> minScore,
            @RequestParam Optional<Long> lastModifiedDays,
            @RequestParam Optional<String> q,
            @RequestParam Optional<String> filterColumn,
            @RequestParam Optional<String> filterValue,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "publishedDate") String sort,
            @RequestParam(defaultValue = "desc") String direction
    ) {
        Page<CveEntity> p = service.searchOptional(cveId, year, minScore, lastModifiedDays, q, filterColumn, filterValue, page, size, sort, direction);
        return ResponseEntity.ok(p);
    }

    @GetMapping("/{cveId}")
    public ResponseEntity<CveEntity> getById(@PathVariable String cveId) {
        return service.findByCveId(cveId)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
