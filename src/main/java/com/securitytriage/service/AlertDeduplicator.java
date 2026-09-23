package com.securitytriage.service;

import com.securitytriage.model.SecurityAlert;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AlertDeduplicator {

    public List<SecurityAlert> removeDuplicates(List<SecurityAlert> alerts) {
        Set<String> seenKeys = new HashSet<>();
        List<SecurityAlert> uniqueAlerts = new ArrayList<>();

        for (SecurityAlert alert : alerts) {
            String key = createDuplicateKey(alert);

            if (!seenKeys.contains(key)) {
                seenKeys.add(key);
                uniqueAlerts.add(alert);
            }
        }

        return uniqueAlerts;
    }

    private String createDuplicateKey(SecurityAlert alert) {
        return alert.getType()
                + "|"
                + alert.getSourceIp()
                + "|"
                + alert.getUsername();
    }
}