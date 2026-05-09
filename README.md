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

### 🧠 Advanced Threat Scoring Algorithm ($TP$)

The project uses a multi-factor weighting system to calculate the **Total Threat Power ($TP$)**. This formula accounts for both the presence of vulnerabilities and their frequency, with defined saturation limits for each category to ensure a balanced risk assessment:

$$TP = W(10) + S(30 \times n, \text{max } 90) + P(20 \times n, \text{max } 60) + L(8 \times n, \text{max } 40) + D(5 \times n, \text{max } 20)$$

**Variable Definitions:**

*   **$W$ (Whois Data):** Base risk if domain registration data is publicly exposed (+10).
*   **$S$ (Data Leaks):** Number of unique data breaches ($n$) identified. Each leak adds 30 points, capped at a maximum of 90.
*   **$P$ (Critical Ports):** Number of open critical ports ($n$) detected (e.g., SSH, RDP, FTP). Each adds 20 points, capped at 60.
*   **$L$ (Linked Accounts):** Verified connections between different social/professional digital profiles ($n$). Each adds 8 points, capped at 40.
*   **$D$ (Google Dorks):** Sensitive files or indexed directories found via advanced Dorking techniques ($n$). Each adds 5 points, capped at 20.

**Why this scoring model?**
The implementation of "saturation caps" (max limits) prevents a single vulnerability type from disproportionately inflating the threat level. This ensures a more holistic and scientific approach to digital risk analysis, which is a core requirement for the **TÜBİTAK** research methodology.

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
