package com.securitytriage.model;

import java.time.LocalDateTime;

public class SecurityAlert {

    private String id;
    private String type;
    private Severity severity;
    private String sourceIp;
    private String username;
    private int failedAttempts;
    private boolean privilegedAccount;
    private boolean knownMaliciousIp;
    private String description;
    private LocalDateTime timestamp;

    public SecurityAlert() {
    }

    public SecurityAlert(
            String id,
            String type,
            Severity severity,
            String sourceIp,
            String username,
            int failedAttempts,
            boolean privilegedAccount,
            boolean knownMaliciousIp,
            String description,
            LocalDateTime timestamp) {

        this.id = id;
        this.type = type;
        this.severity = severity;
        this.sourceIp = sourceIp;
        this.username = username;
        this.failedAttempts = failedAttempts;
        this.privilegedAccount = privilegedAccount;
        this.knownMaliciousIp = knownMaliciousIp;
        this.description = description;
        this.timestamp = timestamp;
    }

    public String getId() {
        return id;
    }

    public String getType() {
        return type;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getUsername() {
        return username;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public boolean isPrivilegedAccount() {
        return privilegedAccount;
    }

    public boolean isKnownMaliciousIp() {
        return knownMaliciousIp;
    }

    public String getDescription() {
        return description;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    public void setPrivilegedAccount(boolean privilegedAccount) {
        this.privilegedAccount = privilegedAccount;
    }

    public void setKnownMaliciousIp(boolean knownMaliciousIp) {
        this.knownMaliciousIp = knownMaliciousIp;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}
