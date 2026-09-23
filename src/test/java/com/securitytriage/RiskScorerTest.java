package com.securitytriage;

import com.securitytriage.model.SecurityAlert;
import com.securitytriage.model.Severity;
import com.securitytriage.service.RiskScorer;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RiskScorerTest {

    private final RiskScorer riskScorer = new RiskScorer();

    @Test
    void lowSeverityReturnsBaseScore() {
        SecurityAlert alert = createAlert(
                Severity.LOW,
                0,
                false,
                false
        );

        int score = riskScorer.calculateRiskScore(alert);

        assertEquals(10, score);
    }

    @Test
    void highSeverityReturnsBaseScore() {
        SecurityAlert alert = createAlert(
                Severity.HIGH,
                0,
                false,
                false
        );

        int score = riskScorer.calculateRiskScore(alert);

        assertEquals(60, score);
    }

    @Test
    void fiveFailedAttemptsAddsTenPoints() {
        SecurityAlert alert = createAlert(
                Severity.MEDIUM,
                5,
                false,
                false
        );

        int score = riskScorer.calculateRiskScore(alert);

        assertEquals(40, score);
    }

    @Test
    void tenFailedAttemptsAddsTwentyPointsInsteadOfTen() {
        SecurityAlert alert = createAlert(
                Severity.MEDIUM,
                10,
                false,
                false
        );

        int score = riskScorer.calculateRiskScore(alert);

        assertEquals(50, score);
    }

    @Test
    void privilegedAccountAddsFifteenPoints() {
        SecurityAlert alert = createAlert(
                Severity.MEDIUM,
                0,
                true,
                false
        );

        int score = riskScorer.calculateRiskScore(alert);

        assertEquals(45, score);
    }

    @Test
    void knownMaliciousIpAddsTwentyPoints() {
        SecurityAlert alert = createAlert(
                Severity.MEDIUM,
                0,
                false,
                true
        );

        int score = riskScorer.calculateRiskScore(alert);

        assertEquals(50, score);
    }

    @Test
    void scoreNeverExceedsOneHundred() {
        SecurityAlert alert = createAlert(
                Severity.CRITICAL,
                10,
                true,
                true
        );

        int score = riskScorer.calculateRiskScore(alert);

        assertEquals(100, score);
    }

    private SecurityAlert createAlert(
            Severity severity,
            int failedAttempts,
            boolean privilegedAccount,
            boolean knownMaliciousIp) {

        return new SecurityAlert(
                "TEST-001",
                "FAILED_LOGIN",
                severity,
                "203.0.113.10",
                "testuser",
                failedAttempts,
                privilegedAccount,
                knownMaliciousIp,
                "Test alert",
                LocalDateTime.now()
        );
    }
}