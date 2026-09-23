package com.securitytriage.service;

import com.securitytriage.model.SecurityAlert;
import com.securitytriage.model.Severity;

import java.util.ArrayList;
import java.util.List;

public class RiskScorer {

    public int calculateRiskScore(SecurityAlert alert) {
        int score = getBaseScore(alert.getSeverity());

        if (alert.getFailedAttempts() >= 10) {
            score += 20;
        } else if (alert.getFailedAttempts() >= 5) {
            score += 10;
        }

        if (alert.isPrivilegedAccount()) {
            score += 15;
        }

        if (alert.isKnownMaliciousIp()) {
            score += 20;
        }

        if (score > 100) {
            score = 100;
        }

        return score;
    }

    public List<String> explainScore(SecurityAlert alert) {
        List<String> reasons = new ArrayList<>();

        int score = getBaseScore(alert.getSeverity());

        reasons.add("Base " + alert.getSeverity() + " severity: " + score);

        if (alert.getFailedAttempts() >= 10) {
            score += 20;
            reasons.add("10+ failed login attempts: +20");
        } else if (alert.getFailedAttempts() >= 5) {
            score += 10;
            reasons.add("5+ failed login attempts: +10");
        }

        if (alert.isPrivilegedAccount()) {
            score += 15;
            reasons.add("Privileged account: +15");
        }

        if (alert.isKnownMaliciousIp()) {
            score += 20;
            reasons.add("Known malicious IP: +20");
        }

        if (score > 100) {
            score = 100;
            reasons.add("Score capped at 100");
        }

        reasons.add("Final score: " + score);

        return reasons;
    }

    private int getBaseScore(Severity severity) {
        switch (severity) {
            case LOW:
                return 10;
            case MEDIUM:
                return 30;
            case HIGH:
                return 60;
            case CRITICAL:
                return 80;
            default:
                throw new IllegalArgumentException("Unknown severity: " + severity);
        }
    }
}
