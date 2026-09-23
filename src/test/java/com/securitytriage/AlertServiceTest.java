package com.securitytriage;

import com.securitytriage.model.SecurityAlert;
import com.securitytriage.model.Severity;
import com.securitytriage.service.AlertService;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AlertServiceTest {

    private final AlertService alertService = new AlertService();

    @Test
    void highestRiskAlertAppearsFirst() {
        List<SecurityAlert> alerts = new ArrayList<>();

        SecurityAlert lowRisk = createAlert(
                "A1",
                "FAILED_LOGIN",
                Severity.LOW,
                "203.0.113.10",
                "user1",
                0,
                false,
                false
        );

        SecurityAlert highRisk = createAlert(
                "A2",
                "DATA_EXFILTRATION",
                Severity.CRITICAL,
                "203.0.113.20",
                "admin",
                10,
                true,
                true
        );

        alerts.add(lowRisk);
        alerts.add(highRisk);

        List<SecurityAlert> result =
                alertService.getPrioritizedAlerts(alerts);

        assertEquals("A2", result.get(0).getId());
    }

    @Test
    void severityFilteringWorks() {
        List<SecurityAlert> alerts = new ArrayList<>();

        alerts.add(createAlert(
                "A1",
                "FAILED_LOGIN",
                Severity.LOW,
                "203.0.113.10",
                "user1",
                0,
                false,
                false
        ));

        alerts.add(createAlert(
                "A2",
                "SUSPICIOUS_IP",
                Severity.HIGH,
                "203.0.113.20",
                "user2",
                0,
                false,
                false
        ));

        List<SecurityAlert> result =
                alertService.filterBySeverity(alerts, Severity.HIGH);

        assertEquals(1, result.size());
        assertEquals("A2", result.get(0).getId());
    }

    @Test
    void minimumRiskScoreFilteringWorks() {
        List<SecurityAlert> alerts = new ArrayList<>();

        alerts.add(createAlert(
                "A1",
                "FAILED_LOGIN",
                Severity.LOW,
                "203.0.113.10",
                "user1",
                0,
                false,
                false
        ));

        alerts.add(createAlert(
                "A2",
                "PRIVILEGE_ESCALATION",
                Severity.HIGH,
                "203.0.113.20",
                "admin",
                0,
                true,
                false
        ));

        List<SecurityAlert> result =
                alertService.filterByMinimumRiskScore(alerts, 70);

        assertEquals(1, result.size());
        assertEquals("A2", result.get(0).getId());
    }

    private SecurityAlert createAlert(
            String id,
            String type,
            Severity severity,
            String sourceIp,
            String username,
            int failedAttempts,
            boolean privilegedAccount,
            boolean knownMaliciousIp) {

        return new SecurityAlert(
                id,
                type,
                severity,
                sourceIp,
                username,
                failedAttempts,
                privilegedAccount,
                knownMaliciousIp,
                "Test alert",
                LocalDateTime.now()
        );
    }
}