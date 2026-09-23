package com.securitytriage;

import com.securitytriage.io.AlertJsonReader;
import com.securitytriage.model.SecurityAlert;
import com.securitytriage.service.AlertService;
import com.securitytriage.service.RiskScorer;

import java.io.IOException;
import java.util.List;

public class Main {

    public static void main(String[] args) {

        AlertJsonReader reader = new AlertJsonReader();
        AlertService alertService = new AlertService();
        RiskScorer riskScorer = new RiskScorer();

        try {
            List<SecurityAlert> alerts = reader.readAlerts("alerts.json");

            List<SecurityAlert> prioritizedAlerts =
                    alertService.getPrioritizedAlerts(alerts);

            int duplicatesRemoved =
                    alerts.size() - prioritizedAlerts.size();

            int minimumRiskScore = 70;

            List<SecurityAlert> highPriorityAlerts =
                    alertService.filterByMinimumRiskScore(
                            prioritizedAlerts,
                            minimumRiskScore
                    );

            System.out.println("========================================");
            System.out.println("SECURITY ALERT TRIAGE ENGINE");
            System.out.println("========================================");
            System.out.println();

            System.out.println(
                    "Alerts loaded: " + reader.getTotalRecordsRead()
            );

            System.out.println(
                    "Invalid alerts skipped: " + reader.getInvalidAlertCount()
            );

            System.out.println(
                    "Duplicates removed: " + duplicatesRemoved
            );

            System.out.println(
                    "Alerts remaining: " + prioritizedAlerts.size()
            );

            System.out.println();
            System.out.println(
                    "TOP PRIORITY ALERTS (minimum risk score: "
                            + minimumRiskScore + ")"
            );
            System.out.println();

            for (SecurityAlert alert : highPriorityAlerts) {

                int riskScore =
                        riskScorer.calculateRiskScore(alert);

                System.out.println(
                        "[Risk: " + riskScore + "] "
                                + alert.getSeverity()
                                + " - "
                                + alert.getType()
                );

                System.out.println(
                        "User: " + alert.getUsername()
                );

                System.out.println(
                        "Source IP: " + alert.getSourceIp()
                );

                System.out.println("Reasons:");

                List<String> reasons =
                        riskScorer.explainScore(alert);

                for (String reason : reasons) {
                    System.out.println("- " + reason);
                }

                System.out.println("----------------------------------------");
            }

        } catch (IOException e) {
            System.out.println(
                    "Could not read alert data: " + e.getMessage()
            );
        }
    }
}