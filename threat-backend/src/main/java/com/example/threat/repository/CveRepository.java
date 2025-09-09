package com.example.threat.repository;

import com.example.threat.model.CveEntity;
import org.springframework.data.jpa.repository.*;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CveRepository extends JpaRepository<CveEntity, Long>, JpaSpecificationExecutor<CveEntity> {
    Optional<CveEntity> findByCveId(String cveId);
}
