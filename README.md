# Secure Coding Review — CodeAlpha Task2 

## Overview
A complete security audit of a Java Banking Transaction Application.
Identified 8 vulnerabilities and provided fully fixed, secure code.

## Files
- VulnerableBankingApp.java — Original code with security flaws
- SecureBankingApp.java — Fixed, secure version of the application
- Secure_Coding_Review_Report_CodeAlpha.html — Full detailed report

## Vulnerabilities Found
| # | Vulnerability | Severity |
|---|--------------|----------|
| V1 | SQL Injection | Critical |
| V2 | Hardcoded Credentials | Critical |
| V3 | Weak Hashing MD5 | Critical |
| V4 | No Input Validation | High |
| V5 | Sensitive Data in Logs | High |
| V6 | Insecure Session Token | High |
| V7 | Path Traversal | Medium |
| V8 | Missing Authorization (IDOR) | Critical |

## Tools Used
- Manual Code Review
- OWASP Top 10 Framework
- SpotBugs (Static Analysis)

## Language
Java

## Author
Ayesha Minhaj— CodeAlpha Cybersecurity Internship
