package com.example.threat.service;

import com.example.threat.model.CveEntity;
import com.example.threat.repository.CveRepository;
import com.example.threat.util.CveSpecifications;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CveService {
    private final CveRepository repo;
    private final ObjectMapper mapper = new ObjectMapper();

    public CveService(CveRepository repo) {
        this.repo = repo;
    }

    public Page<CveEntity> searchOptional(
            Optional<String> cveId,
            Optional<Integer> year,
            Optional<Double> minScore,
            Optional<Long> lastModifiedDays,
            Optional<String> q,
            Optional<String> filterColumn,
            Optional<String> filterValue,
            int page, int size, String sort, String direction) {

        Pageable pageable = PageRequest.of(
                Math.max(0, page),
                Math.max(1, size),
                "desc".equalsIgnoreCase(direction) ? Sort.Direction.DESC : Sort.Direction.ASC,
                sort == null ? "publishedDate" : sort
        );

        Specification<CveEntity> spec = Specification.where(null);
        if (cveId.isPresent()) spec = spec.and(CveSpecifications.hasCveId(cveId.get()));
        if (year.isPresent()) spec = spec.and(CveSpecifications.publishedYear(year.get()));
        if (minScore.isPresent()) spec = spec.and(CveSpecifications.minScore(minScore.get()));
        if (lastModifiedDays.isPresent()) spec = spec.and(CveSpecifications.lastModifiedWithinDays(lastModifiedDays.get()));

        if (q.isPresent() && !q.get().isBlank()) {
            spec = spec.and(CveSpecifications.globalSearch(q.get().trim()));
        }
        if (filterColumn.isPresent() && filterValue.isPresent() && !filterColumn.get().isBlank()) {
            spec = spec.and(CveSpecifications.filterColumnEquals(filterColumn.get().trim(), filterValue.get().trim()));
        }

        return repo.findAll(spec, pageable);
    }

    public Optional<CveEntity> findByCveId(String id) {
        return repo.findByCveId(id);
    }

    public CveEntity saveOrUpdate(CveEntity e) {
        Optional<CveEntity> existing = repo.findByCveId(e.getCveId());
        if (existing.isPresent()) {
            CveEntity ex = existing.get();
            ex.setDescription(e.getDescription());
            ex.setPublishedDate(e.getPublishedDate());
            ex.setLastModifiedDate(e.getLastModifiedDate());
            ex.setCvssV2(e.getCvssV2());
            ex.setCvssV3(e.getCvssV3());
            ex.setRawJson(e.getRawJson());
            return repo.save(ex);
        } else {
            return repo.save(e);
        }
    }
}
