package com.example.threat.model;

import jakarta.persistence.*;
import java.time.OffsetDateTime;

@Entity
@Table(
    name = "cves",
    uniqueConstraints = @UniqueConstraint(columnNames = {"cve_id"})
)
public class CveEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cve_id", nullable = false, unique = true, length = 100)
    private String cveId;

    @Column(columnDefinition = "text")
    private String description;

    @Column(name = "published_date")
    private OffsetDateTime publishedDate;

    @Column(name = "last_modified_date")
    private OffsetDateTime lastModifiedDate;

    @Column(name = "cvss_v2")
    private Double cvssV2;

    @Column(name = "cvss_v3")
    private Double cvssV3;

    @Column(name = "raw_json", columnDefinition = "text")
    private String rawJson;

    @Column(name = "created_at", updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at")
    private OffsetDateTime updatedAt;

    public CveEntity() {}

    @PrePersist
    public void prePersist() {
        OffsetDateTime now = OffsetDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = OffsetDateTime.now();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getCveId() { return cveId; }
    public void setCveId(String cveId) { this.cveId = cveId; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public OffsetDateTime getPublishedDate() { return publishedDate; }
    public void setPublishedDate(OffsetDateTime publishedDate) { this.publishedDate = publishedDate; }

    public OffsetDateTime getLastModifiedDate() { return lastModifiedDate; }
    public void setLastModifiedDate(OffsetDateTime lastModifiedDate) { this.lastModifiedDate = lastModifiedDate; }

    public Double getCvssV2() { return cvssV2; }
    public void setCvssV2(Double cvssV2) { this.cvssV2 = cvssV2; }

    public Double getCvssV3() { return cvssV3; }
    public void setCvssV3(Double cvssV3) { this.cvssV3 = cvssV3; }

    public String getRawJson() { return rawJson; }
    public void setRawJson(String rawJson) { this.rawJson = rawJson; }

    public OffsetDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(OffsetDateTime createdAt) { this.createdAt = createdAt; }

    public OffsetDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(OffsetDateTime updatedAt) { this.updatedAt = updatedAt; }
}
