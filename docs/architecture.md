\# NOVA AI - System Architecture



\## Overview



NOVA AI is an intelligent email threat detection system that combines Machine Learning and rule-based security analysis to classify emails as \*\*HAM\*\*, \*\*SUSPICIOUS\*\*, or \*\*SPAM\*\*.



\---



\# System Workflow



```

&#x20;                    EMAIL INPUT

&#x20;                         │

&#x20;                         ▼

&#x20;               Email Preprocessing

&#x20;                         │

&#x20;                         ▼

&#x20;         ┌────────────────────────────────┐

&#x20;         │     Naive Bayes Classifier     │

&#x20;         │   (Machine Learning Engine)    │

&#x20;         └────────────────────────────────┘

&#x20;                         │

&#x20;                         ▼

&#x20;            Security Rule Analysis

&#x20;                         │

&#x20;                         ▼

&#x20;             Phishing URL Detection

&#x20;                         │

&#x20;                         ▼

&#x20;            Sender Reputation Analysis

&#x20;                         │

&#x20;                         ▼

&#x20;                Risk Score Engine

&#x20;                         │

&#x20;                         ▼

&#x20;           Explainable AI Decision Engine

&#x20;                         │

&#x20;                         ▼

&#x20;             Final Email Classification

&#x20;                         │

&#x20;                         ▼

&#x20;    Report Generation + History + Statistics

```



\---



\# Project Modules



\## Email Scanner

Reads sender, subject, and email body from the user.



\---



\## Naive Bayes Classifier



\- Tokenizes email

\- Calculates spam probability

\- Predicts HAM or SPAM



\---



\## Security Analysis



Detects:



\- Spam keywords

\- Urgency indicators

\- Money-related phrases

\- Security requests

\- Excessive punctuation



\---



\## Phishing Detector



Checks for:



\- URLs

\- Fake domains

\- Suspicious links

\- URL shorteners



\---



\## Sender Analyzer



Evaluates:



\- Trusted domains

\- Suspicious domains

\- Sender reputation



\---



\## Risk Engine



Combines:



\- ML Probability

\- Security Score

\- Phishing Score

\- Sender Score



Produces the final risk percentage.



\---



\## Explanation Engine



Explains why the email was classified.



\---



\## Report Generator



Generates:



\- Latest Scan Report

\- Scan History

\- Statistics



\---



\# Technologies Used



\- C++17

\- Object-Oriented Programming

\- STL

\- File Handling

\- Regular Expressions

\- Naive Bayes Machine Learning



\---



\# Output



The system provides:



\- Spam Probability

\- Security Score

\- Phishing Score

\- Sender Score

\- Final Risk Score

\- Detailed Report

\- Scan History

\- Statistics

