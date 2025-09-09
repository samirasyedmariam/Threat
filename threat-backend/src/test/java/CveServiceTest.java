package com.example.threat;

import com.example.threat.model.CveEntity;
import com.example.threat.repository.CveRepository;
import com.example.threat.service.CveService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@SpringBootTest
public class CveServiceTest {

    @Autowired
    private CveService cveService;

    @MockBean
    private CveRepository cveRepository;

    @Test
    void saveOrUpdateNewEntity() {
        CveEntity e = new CveEntity();
        e.setCveId("CVE-TEST-UNIT-1");
        e.setDescription("Unit test CVE");
        when(cveRepository.findByCveId("CVE-TEST-UNIT-1")).thenReturn(Optional.empty());
        when(cveRepository.save(any(CveEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        CveEntity out = cveService.saveOrUpdate(e);

        assertEquals("CVE-TEST-UNIT-1", out.getCveId());
        assertEquals("Unit test CVE", out.getDescription());
    }
}
