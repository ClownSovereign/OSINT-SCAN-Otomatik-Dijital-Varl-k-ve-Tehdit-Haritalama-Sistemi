# OSINT-SCAN-Automated-Digital-Asset-and-Threat-Mapping-System
A Program Written to Participate in the TÜBİTAK (Scientific and Technological Research Council of Turkey) Competition, a Science and Technology Competition Organized by the Republic of Turkey at All Educational Levels
# 🛡️ OSINT-SCAN: Automated Digital Asset & Threat Mapping System

**OSINT-SCAN** is an integrated cybersecurity research project designed to analyze digital footprints, collect publicly available information (PAI), and provide a unified risk score. This tool helps individuals and organizations understand what attackers can see about them from the outside.

> [!IMPORTANT]
> This project is being developed for the **TÜBİTAK 2204-A High School Students Research Projects Competition**.

## 🚀 Purpose & Problem Statement

*   **The Problem:** Users often leave behind vast amounts of data (emails, technical logs, social media clues) without realizing it. Attackers aggregate this data to launch sophisticated, targeted attacks.
*   **The Solution:** An automated platform that scans public data sources (Shodan, Whois, social media, leaked databases), correlates the findings, and generates a "Digital Security Report card" with actionable risk scores.

## 🏗️ System Architecture & Tech Stack

The project utilizes a hybrid architecture to balance high-performance scanning with deep data analysis:

| Technology | Role | Why? |
| :--- | :--- | :--- |
| **Python** | Core Logic & Analysis | Rich ecosystem for OSINT libraries (Scapy, BeautifulSoup) and AI integration. |
| **Golang** | High-Speed Scanning | Used for network-heavy tasks. Go-routines allow scanning thousands of ports/APIs concurrently. |
| **SQLite** | Data Persistence | Enables relational querying to find connections between disparate data points (e.g., Email ↔ Leak). |
| **Streamlit** | Dashboard UI | Provides a professional, web-based interface for data visualization without heavy frontend overhead. |

## 🧠 Risk Scoring Algorithm ($ARF$)

The scientific core of the project is the **Weighted Risk Factor ($ARF$)** formula. It transforms raw data into a measurable security metric:

$$ARF = (W \times 0.1) + (S \times 0.3) + (P \times 0.2) + (L \times 0.4)$$

*   **W (Whois):** Exposure level of domain registration details.
*   **S (Leakage):** Presence of credentials in historical data breaches.
*   **P (Ports):** Discovery of critical open services (e.g., SSH, RDP, FTP).
*   **L (Links):** The strength of connections found between social media and professional profiles.

## 🛠️ Methodology

1.  **Data Acquisition (Scraping & APIs):** 
    *   Passive reconnaissance using specialized Python scripts and Go-based scanners.
    *   API integration with services like Shodan for infrastructure analysis.
2.  **Data Correlation:** 
    *   Aggregating raw results into an SQLite database.
    *   Identifying "cross-contamination" where one data point (like an email) leads to another (like a leaked password).
3.  **Threat Modeling & Reporting:** 
    *   Applying the scoring algorithm to generate a risk level (Low, Medium, High, Critical).
    *   Visualizing findings via a Streamlit-based interactive dashboard.

## ⚖️ Legal Disclaimer & Ethics
This tool is strictly for **personal security auditing** and **educational purposes**. Unauthorized scanning of third-party assets is unethical and may be illegal. The developer is not responsible for any misuse of this software.

---
*Developed by Efe — 10th Grade Software Developer & Cybersecurity Enthusiast.*
