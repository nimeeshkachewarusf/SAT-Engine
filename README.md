Security Alert Triage Engine

A small Java command-line application that processes simulated cybersecurity alerts, removes duplicates, calculates deterministic risk scores, filters alerts, and produces a prioritized incident queue.

This is an educational project built to practice Java and software engineering fundamentals. It does not detect real attacks and is not intended for production security use.

Overview

The Security Alert Triage Engine reads simulated alert records from a JSON file and converts them into Java objects. It then:

skips invalid or incomplete records where practical,
removes duplicate alerts,
calculates an explainable risk score,
sorts alerts from highest risk to lowest risk,
filters alerts using a minimum risk-score threshold,
prints the prioritized alerts with the reasons behind each score.

The current sample dataset contains 100 simulated records across six alert categories.

Features
JSON alert ingestion with Jackson
Deterministic, explainable risk scoring
Alert deduplication using a HashSet
Risk-based prioritization with Comparator
Severity and minimum-risk filtering
Graceful handling of invalid alert records
Java LocalDateTime support
Automated testing with JUnit 5
Maven-based build and dependency management
Technologies
Java 17
Maven
Jackson
JUnit 5
Git / GitHub
Project Structure
security-alert-triage/
├── pom.xml
├── README.md
└── src/
    ├── main/
    │   ├── java/
    │   │   └── com/
    │   │       └── securitytriage/
    │   │           ├── Main.java
    │   │           ├── io/
    │   │           │   └── AlertJsonReader.java
    │   │           ├── model/
    │   │           │   ├── SecurityAlert.java
    │   │           │   └── Severity.java
    │   │           └── service/
    │   │               ├── AlertDeduplicator.java
    │   │               ├── AlertService.java
    │   │               └── RiskScorer.java
    │   └── resources/
    │       └── alerts.json
    └── test/
        └── java/
            └── com/
                └── securitytriage/
                    ├── AlertDeduplicatorTest.java
                    ├── AlertServiceTest.java
                    └── RiskScorerTest.java
Architecture
SecurityAlert

Represents one simulated security alert. It stores fields such as alert type, severity, source IP, username, failed login attempts, account privilege status, malicious-IP status, description, and timestamp.

Severity

An enum containing the supported severity levels:

LOW
MEDIUM
HIGH
CRITICAL

Using an enum prevents arbitrary or misspelled severity values inside the application.

RiskScorer

Calculates a deterministic risk score for a SecurityAlert and can also return a human-readable explanation of how the score was calculated.

AlertDeduplicator

Removes duplicate alerts using a HashSet. Two alerts are considered duplicates when they have the same:

alert type,
source IP,
username.
AlertService

Coordinates higher-level alert operations, including:

deduplication,
risk-based sorting,
severity filtering,
minimum-risk filtering.
AlertJsonReader

Reads alerts.json using Jackson, converts valid JSON records into SecurityAlert objects, and skips invalid records where practical.

Main

Acts as the command-line entry point. It connects the JSON reader, alert-processing service, and risk scorer, then prints the prioritized alert queue.

Risk Scoring

Risk scores are deterministic and capped at 100.

Rule	Score
LOW severity	10
MEDIUM severity	30
HIGH severity	60
CRITICAL severity	80
5–9 failed attempts	+10
10+ failed attempts	+20
Privileged account	+15
Known malicious IP	+20
Maximum score	100

Example:

Base HIGH severity: 60
10+ failed login attempts: +20
Privileged account: +15
Final score: 95
Deduplication

The application creates a duplicate key from:

type + sourceIp + username

A HashSet stores keys that have already been seen. Because hash-based membership checks are typically O(1) on average, this is a simple and efficient fit for duplicate detection.

Sample Data

The included alerts.json file contains 100 simulated alert records across six categories:

FAILED_LOGIN
MALWARE_DETECTION
PRIVILEGE_ESCALATION
SUSPICIOUS_IP
UNUSUAL_LOGIN
DATA_EXFILTRATION

The dataset includes normal alerts, high-risk alerts, duplicate records, varied severity levels, privileged and non-privileged accounts, known malicious-IP flags, and intentionally invalid or incomplete records for error-handling practice.

Testing

The project currently contains 13 JUnit tests covering:

LOW and HIGH base risk scores
failed-attempt thresholds
privileged-account scoring
known-malicious-IP scoring
the 100-point score cap
duplicate removal
non-duplicate users
non-duplicate alert types
highest-risk-first sorting
severity filtering
minimum-risk filtering

Run all tests with:

mvn test

For a clean rebuild:

mvn clean test
Building

Build and test the project with:

mvn clean package

Maven writes compiled output to the generated target/ directory.

Running

In VS Code:

Open the project root folder.
Open src/main/java/com/securitytriage/Main.java.
Click Run above the main method.

The application reads src/main/resources/alerts.json, skips invalid records, removes duplicates, sorts the remaining alerts, applies the configured minimum risk threshold, and prints the results to the terminal.

Example summary output:

========================================
SECURITY ALERT TRIAGE ENGINE
========================================

Alerts loaded: 100
Invalid alerts skipped: 3
Duplicates removed: 3
Alerts remaining: 94
Example Prioritized Alert
[Risk: 100] CRITICAL - DATA_EXFILTRATION
User: admin
Source IP: 203.0.113.28

Reasons:
- Base CRITICAL severity: 80
- 10+ failed login attempts: +20
- Privileged account: +15
- Known malicious IP: +20
- Score capped at 100
- Final score: 100
What I Learned

This project gave me practice with:

Java classes and objects
encapsulation with private fields and getters/setters
constructors
enums
Java Collections
List, ArrayList, Set, and HashSet
Comparator
exception handling with try/catch
file and resource input
JSON parsing with Jackson
LocalDateTime
Maven
JUnit 5
separation of concerns
testing and debugging
Possible Improvements

With more time, the project could be extended by:

improving realism in the simulated alert dataset,
adding more input-validation tests,
making the priority threshold configurable,
adding deterministic tie-breaking for alerts with equal risk scores,
exporting prioritized alerts to a file.

The project intentionally avoids frameworks, databases, microservices, and unnecessary abstraction so the core Java design remains small and explainable.
=======
# SAT-Engine
Files for Security Alert Triage
>>>>>>> 370cfd48dce6d17b37e9902e7cf48343e3862ee8
