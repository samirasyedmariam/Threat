package com.example.threat;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;

import com.example.threat.service.CveSyncService;
import org.springframework.beans.factory.annotation.Value;

@SpringBootApplication
public class ThreatApplication {

    public static void main(String[] args) {
        SpringApplication.run(ThreatApplication.class, args);
    }

    @Bean
    CommandLineRunner runOnStartup(CveSyncService syncService,
                                  @Value("${nvd.sync-on-startup:false}") boolean syncOnStartup) {
        return args -> {
            if (syncOnStartup) {
                System.out.println("🚀 Starting async CVE sync on startup...");
                syncService.asyncSync();
            } else {
                System.out.println("CVE sync on startup disabled (nvd.sync-on-startup=false)");
            }
        };
    }
}
