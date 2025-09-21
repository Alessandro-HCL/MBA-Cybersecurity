# Cybersecurity Simulation and Predictive Detection Framework

## 📑 Table of Contents
- [📌 Project Overview](#-project-overview)
- [⚙️ Architecture](#️-architecture)
- [🖥️ Implementation Environment](#️-implementation-environment)
- [📊 Results](#-results)
- [🚀 Roadmap (Next Steps)](#-roadmap-next-steps)
- [📂 Repository Structure](#-repository-structure)
- [🔗 Project Modules & Key Files](#-project-modules--key-files)
- [📸 Screenshots](#-screenshots)
- [📝 Academic Validation](#-academic-validation)
- [📜 License](#-license)
- [📧 Contact](#-contact)

---

## 🔗 Project Modules & Key Files

[/M&A](./M&A) → M&A analysis module (menu, inventory, reports)

[Red Team script — attack simulation](./M&A/Red_team_ataque_OKAY.py) → Controlled attack simulations (hping3 / Kali)

[Blue Team script — traffic capture & detection](./M&A/Blue_team_detecção_OKAY.py) → Passive monitoring & Scapy analysis

[Data collection script (tshark automation)](./M&A/Coleta_dados-OKAY.py) → Automated pcap collection and metadata export

[/Streamlit testes](./Streamlit%20testes) → Streamlit prototype interfaces and demos

[/docs](./docs) → Technical reports, PDFs, and MBA defense presentation

---

## 📸 Screenshots

Below are some key screenshots of the framework in action (stored in `./docs/screenshots/`):

- ![Streamlit UI prototype](./docs/screenshots/streamlit_ui.png)  
  *Prototype interface for running attack simulations and viewing results.*

- ![Wireshark capture](./docs/screenshots/wireshark_capture.png)  
  *Example of packet capture showing spoofed IP and abnormal headers.*

- ![Anomaly detection report](./docs/screenshots/anomaly_report.png)  
  *Sample output of Isolation Forest detection highlighting malicious flows.*
