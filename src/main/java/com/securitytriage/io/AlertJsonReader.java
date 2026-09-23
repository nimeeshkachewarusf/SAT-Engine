package com.securitytriage.io;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.securitytriage.model.SecurityAlert;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class AlertJsonReader {

    private final ObjectMapper objectMapper;
    private int invalidAlertCount;
    private int totalRecordsRead;

    public AlertJsonReader() {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
    }

    public List<SecurityAlert> readAlerts(String resourceName) throws IOException {
        List<SecurityAlert> alerts = new ArrayList<>();

        invalidAlertCount = 0;
        totalRecordsRead = 0;

        InputStream inputStream =
                getClass().getClassLoader().getResourceAsStream(resourceName);

        if (inputStream == null) {
            throw new IOException("Resource not found: " + resourceName);
        }

        JsonNode rootNode = objectMapper.readTree(inputStream);

        if (!rootNode.isArray()) {
            throw new IOException("Expected JSON file to contain an array of alerts.");
        }

        for (JsonNode alertNode : rootNode) {
            totalRecordsRead++;

            if (!hasRequiredFields(alertNode)) {
                invalidAlertCount++;
                System.out.println(
                        "Skipping invalid alert record #" + totalRecordsRead
                );
                continue;
            }

            try {
                SecurityAlert alert =
                        objectMapper.treeToValue(alertNode, SecurityAlert.class);

                alerts.add(alert);

            } catch (JsonProcessingException e) {
                invalidAlertCount++;

                System.out.println(
                        "Skipping invalid alert record #"
                                + totalRecordsRead
                                + ": "
                                + e.getOriginalMessage()
                );
            }
        }

        return alerts;
    }

    private boolean hasRequiredFields(JsonNode node) {
        return node.hasNonNull("id")
                && node.hasNonNull("type")
                && node.hasNonNull("severity")
                && node.hasNonNull("sourceIp")
                && node.hasNonNull("username")
                && node.hasNonNull("failedAttempts")
                && node.hasNonNull("privilegedAccount")
                && node.hasNonNull("knownMaliciousIp")
                && node.hasNonNull("description")
                && node.hasNonNull("timestamp");
    }

    public int getInvalidAlertCount() {
        return invalidAlertCount;
    }

    public int getTotalRecordsRead() {
        return totalRecordsRead;
    }
}