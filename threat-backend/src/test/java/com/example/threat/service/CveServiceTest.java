package com.example.threat.service;

import com.example.threat.model.CveEntity;
import com.example.threat.repository.CveRepository;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class CveServiceTest {

    @Test
    void saveOrUpdate_insertsWhenMissing() {
        CveRepository repo = Mockito.mock(CveRepository.class);
        Mockito.when(repo.findByCveId("CVE-1")).thenReturn(Optional.empty());
        CveEntity saved = new CveEntity();
        saved.setId(1L);
        saved.setCveId("CVE-1");
        Mockito.when(repo.save(Mockito.any())).thenReturn(saved);

        CveService svc = new CveService(repo);
        CveEntity in = new CveEntity();
        in.setCveId("CVE-1");
        CveEntity out = svc.saveOrUpdate(in);
        assertEquals("CVE-1", out.getCveId());
    }

    @Test
    void saveOrUpdate_updatesWhenExists() {
        CveRepository repo = Mockito.mock(CveRepository.class);
        CveEntity existing = new CveEntity();
        existing.setId(2L);
        existing.setCveId("CVE-2");
        existing.setDescription("old");
        Mockito.when(repo.findByCveId("CVE-2")).thenReturn(Optional.of(existing));
        Mockito.when(repo.save(Mockito.any())).thenAnswer(i -> i.getArgument(0));

        CveService svc = new CveService(repo);
        CveEntity in = new CveEntity();
        in.setCveId("CVE-2");
        in.setDescription("new");
        CveEntity out = svc.saveOrUpdate(in);
        assertEquals("new", out.getDescription());
    }
}
