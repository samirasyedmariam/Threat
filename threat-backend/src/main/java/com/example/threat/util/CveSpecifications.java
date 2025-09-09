package com.example.threat.util;

import com.example.threat.model.CveEntity;
import org.springframework.data.jpa.domain.Specification;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Predicate;

import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Locale;

public final class CveSpecifications {

    private CveSpecifications() {}

    public static Specification<CveEntity> hasCveId(String cveId) {
        return (root, query, cb) -> cb.equal(root.get("cveId"), cveId);
    }

    public static Specification<CveEntity> descriptionContains(String fragment) {
        return (root, query, cb) -> cb.like(cb.lower(root.get("description")), "%" + fragment.toLowerCase(Locale.ROOT) + "%");
    }

    public static Specification<CveEntity> publishedYear(int year) {
        return (root, query, cb) -> {
            // Build start and end of year to compare publishedDate range
            OffsetDateTime start = OffsetDateTime.now().withYear(year).withMonth(1).withDayOfMonth(1).truncatedTo(ChronoUnit.DAYS);
            OffsetDateTime end = start.plus(1, ChronoUnit.YEARS);
            return cb.between(root.get("publishedDate"), start, end);
        };
    }

    public static Specification<CveEntity> minScore(double minScore) {
        return (root, query, cb) -> cb.or(
                cb.greaterThanOrEqualTo(root.get("cvssV3"), minScore),
                cb.greaterThanOrEqualTo(root.get("cvssV2"), minScore)
        );
    }

    public static Specification<CveEntity> lastModifiedWithinDays(long days) {
        return (root, query, cb) -> {
            OffsetDateTime cutoff = OffsetDateTime.now().minus(days, ChronoUnit.DAYS);
            return cb.greaterThanOrEqualTo(root.get("lastModifiedDate"), cutoff);
        };
    }

    /**
     * Global search across common text fields (cveId, description, rawJson).
     * Uses LOWER(...) LIKE %term%.
     */
    public static Specification<CveEntity> globalSearch(String term) {
        String lowered = "%" + term.toLowerCase(Locale.ROOT) + "%";
        return (root, query, cb) -> {
            Predicate p1 = cb.like(cb.lower(root.get("cveId")), lowered);
            Predicate p2 = cb.like(cb.lower(root.get("description")), lowered);
            Predicate p3 = cb.like(cb.lower(root.get("rawJson")), lowered);
            return cb.or(p1, p2, p3);
        };
    }

    /**
     * Column filter: only allow a safe set of columns to be filtered.
     * Avoids SQL injection by white-listing property names and building typesafe predicates.
     */
    public static Specification<CveEntity> filterColumnEquals(String column, String value) {
        String col = column.trim();
        String val = value.trim();

        switch (col) {
            case "cveId":
                return (root, query, cb) -> cb.like(cb.lower(root.get("cveId")), "%" + val.toLowerCase(Locale.ROOT) + "%");
            case "description":
                return descriptionContains(val);
            case "rawJson":
                return (root, query, cb) -> cb.like(cb.lower(root.get("rawJson")), "%" + val.toLowerCase(Locale.ROOT) + "%");
            case "cvssV3":
                try {
                    double parsed = Double.parseDouble(val);
                    return (root, query, cb) -> cb.equal(root.get("cvssV3"), parsed);
                } catch (NumberFormatException e) {
                    return (root, query, cb) -> cb.disjunction();
                }
            case "cvssV2":
                try {
                    double parsed = Double.parseDouble(val);
                    return (root, query, cb) -> cb.equal(root.get("cvssV2"), parsed);
                } catch (NumberFormatException e) {
                    return (root, query, cb) -> cb.disjunction();
                }
            case "createdAt":
                return (root, query, cb) -> cb.like(cb.lower(root.get("createdAt")), "%" + val.toLowerCase(Locale.ROOT) + "%");
            case "updatedAt":
                return (root, query, cb) -> cb.like(cb.lower(root.get("updatedAt")), "%" + val.toLowerCase(Locale.ROOT) + "%");
            default:
                return (root, query, cb) -> cb.disjunction();
        }
    }
}
