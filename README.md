## Automated SIEM Detection Coverage Lookup to MITRE ATT&CK

## Overview

This project provides a fully automated framework to **inventory SIEM detection rules**, **map them to the MITRE ATT&CK framework**, and **validate their real detection coverage** based on the telemetry actually available in the environment.

It is designed for:

* SOC Teams
* Detection Engineers
* Purple Teams
* Security Operations Leadership

The goal is to close the gap between **theoretical detection coverage** and **real, enforceable coverage**.

---

## Problem Statement

In most SIEM environments:

* Many detection rules are not mapped to MITRE ATT&CK
* Existing MITRE mappings are often manual, inconsistent, or outdated
* Rules exist but cannot function due to missing log sources or fields

This creates a false sense of security and makes it difficult to:

* Measure detection maturity
* Identify real coverage gaps
* Prioritize telemetry onboarding

---

## Solution

The project is built around two automated workflows:

### Trigger A – Detection Inventory & MITRE Mapping

* Extracts all enabled detection rules from the SIEM
* Identifies rules with missing MITRE ATT&CK mappings
* Uses an AI model to automatically map unmapped rules to MITRE techniques
* Extracts rule requirements:

  * Required fields
  * Required log sources
  * Query type and metadata
* Stores the full detection inventory in Google Sheets

### Trigger B – Telemetry Coverage Validation

* Retrieves all available data views and field mappings from the SIEM
* Builds a complete telemetry and field inventory
* Compares each rule’s requirements against available telemetry
* Determines rule coverage status:

  * COVERED
  * PARTIALLY COVERED
  * NOT COVERED
* Updates coverage status and missing dependencies automatically

---

## High-Level Architecture

* SIEM (Elastic Security / Kibana)
* n8n Automation Workflows
* AI Model for MITRE ATT&CK Mapping
* Google Sheets as Detection Inventory
* ECS-aware matching and normalization logic

---

## Key Features

* Automated MITRE ATT&CK mapping
* AI-assisted detection analysis
* ECS-aware field matching
* Log source normalization
* Real detection coverage validation
* SOC-ready reporting and visibility

---

## Technologies Used

* n8n
* Elastic Security APIs
* MITRE ATT&CK Framework
* Google Sheets API
* JavaScript
* AI model for detection-to-MITRE analysis

---

## Use Cases

* Detection coverage gap analysis
* SOC maturity assessment
* Purple team validation
* Telemetry onboarding prioritization
* Audit and compliance evidence
* Detection engineering optimization

---

## Output

Each detection rule is enriched with:

* MITRE tactic and technique
* Required fields
* Required log sources
* Coverage status
* Missing fields
* Missing log sources

---

## How to Run

1. Import the n8n workflows
2. Configure SIEM authentication
3. Configure Google Sheets access
4. Run Trigger A manually to build the detection inventory
5. Trigger B runs on a schedule to continuously validate coverage

---

## Disclaimer

This project is intended for detection engineering, visibility, and coverage analysis.
Review and validate results before using in production environments.

---


لو حابب نسخة:

* أقصر
* مناسبة للـ CV أو LinkedIn
* أو موجهة أكتر للـ Hiring Managers

قولي وأنا أظبطها فورًا.
