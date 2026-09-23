package com.securitytriage.service;

import com.securitytriage.model.SecurityAlert;
import com.securitytriage.model.Severity;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class AlertService {

    private final RiskScorer riskScorer;
    private final AlertDeduplicator deduplicator;

    public AlertService() {
        this.riskScorer = new RiskScorer();
        this.deduplicator = new AlertDeduplicator();
    }

    public List<SecurityAlert> getPrioritizedAlerts(List<SecurityAlert> alerts) {
        List<SecurityAlert> uniqueAlerts = deduplicator.removeDuplicates(alerts);

        uniqueAlerts.sort(
                Comparator.comparingInt(riskScorer::calculateRiskScore)
                        .reversed()
        );

        return uniqueAlerts;
    }

    public List<SecurityAlert> filterBySeverity(
            List<SecurityAlert> alerts,
            Severity severity) {

        List<SecurityAlert> filteredAlerts = new ArrayList<>();

        for (SecurityAlert alert : alerts) {
            if (alert.getSeverity() == severity) {
                filteredAlerts.add(alert);
            }
        }

        return filteredAlerts;
    }

    public List<SecurityAlert> filterByMinimumRiskScore(
            List<SecurityAlert> alerts,
            int minimumScore) {

        List<SecurityAlert> filteredAlerts = new ArrayList<>();

        for (SecurityAlert alert : alerts) {
            int score = riskScorer.calculateRiskScore(alert);

            if (score >= minimumScore) {
                filteredAlerts.add(alert);
            }
        }

        return filteredAlerts;
    }
}

