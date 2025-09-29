# Python WAF: A Simple Web Application Firewall
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A simple, educational Web Application Firewall (WAF) written in Python. This script acts as a reverse proxy to inspect incoming web traffic for common threats like SQL Injection (SQLi) and Cross-Site Scripting (XSS). It's designed to be a learning tool to understand the core concepts behind how a WAF operates.

> **⚠️ Disclaimer:** This is an educational project and is **NOT** suitable for a production environment. Production-grade WAFs are far more sophisticated and undergo rigorous security testing.

---

## Features

-   **Basic Threat Detection:** Uses regular expressions to detect and block common SQLi and XSS attack patterns.
-   **Reverse Proxy Architecture:** Sits between the user and your web server, forwarding only legitimate traffic.
-   **Interactive Setup:** A command-line interface guides you through the configuration of IPs and protocols.
-   **HTTP & HTTPS Support:** Can operate in both non-SSL (HTTP) and SSL/TLS (HTTPS) modes, performing SSL termination to inspect encrypted traffic.
-   **Customizable Block Page:** Serves a user-friendly HTML page when an attack is detected and blocked.
-   **Intelligent Response Rewriting:** Correctly handles backend redirects and session cookies, ensuring web applications function properly behind the proxy.

---

## Requirements

-   Python 3.x
-   `requests` library (`pip install requests`)

---

## Setup and Usage

Follow these steps to get the WAF up and running.

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd <repository-directory>
```

### 2. Install Dependencies

```bash
pip install requests, ssl
```

### 3. (Optional) Generate SSL Certificate for HTTPS Mode

If you plan to use the WAF in HTTPS mode, you need to generate a self-signed certificate and a private key. The `openssl` command will create `cert.pem` and `key.pem`.

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```
*(You can press Enter to accept the defaults when prompted for certificate information.)*

### 4. Run the WAF

Launch the script from your terminal:

```bash
python3 WAF.py
```

The script will then prompt you to configure it interactively:

```
--- WAF Configuration ---
Select Protocol:
1. Non-SSL (HTTP)
2. SSL/TLS (HTTPS)
Enter choice (1 or 2): 2

Enter Your Web Server IP : 192.168.10.50
Enter Your WAF Server IP : 192.168.10.101
Enter path to SSL certificate file (e.g., cert.pem): cert.pem
Enter path to SSL private key file (e.g., key.pem): key.pem

--- Starting WAF ---
✅ WAF running in SSL/TLS (HTTPS) mode on port 443
Forwarding to: [http://192.168.10.50:80](http://192.168.10.50:80)
Press Ctrl+C to stop.
```

Once running, direct your web traffic to the WAF's IP address.

---

## Testing Environment Setup (VMware)

To properly test the WAF, you should use an isolated virtual environment. This setup uses three separate virtual machines.

### 1. VMware Network Configuration

-   Create a **"Host-Only"** or **"Private"** virtual network in VMware. This isolates the VMs from your main network.
-   Disable DHCP on this virtual network to use static IPs.

### 2. Virtual Machines

Create three VMs and connect them to your Host-Only network.

-   **Web Server VM (Target):**
    -   **OS:** OWASP Broken Web Apps (BWA) is a perfect choice.
    -   **Static IP:** `192.168.10.50`
-   **WAF VM (Firewall):**
    -   **OS:** Kali Linux or any Debian-based distro.
    -   **Static IP:** `192.168.10.101`
-   **Attacker VM (Client):**
    -   **OS:** Ubuntu Desktop or Kali Linux.
    -   **Static IP:** `192.168.10.102`

### 3. Deployment and Testing

1.  **On the WAF VM (`192.168.10.101`):**
    -   Clone the repository and install dependencies.
    -   Run `python3 WAF.py`.
    -   When prompted, enter the Web Server IP (`192.168.10.50`) and the WAF IP (`192.168.10.101`).

2.  **On the Attacker VM (`192.168.10.102`):**
    -   Open a web browser and navigate to the WAF's IP (e.g., `http://192.168.10.101:8080`). You should see the OWASP BWA homepage.
    -   Use `curl` or your browser to test attacks. All traffic must be sent to the WAF's IP.

    **Example Attack Tests:**
    Open the WAF IP address, and it will open OWASP BWA in the web
    or
    ```bash
    # Test for SQL Injection (should be blocked)
    curl "[http://192.168.10.101/dvwa/vulnerabilities/sqli/?id=1'%20OR%20'1'='1&Submit=Submit#"

    # Test for XSS (should be blocked)
    curl "http://192.168.10.101/dvwa/vulnerabilities/xss_r/?name=<script>alert('xss')</script>"
    ```

---

## How It Works

The WAF operates as a reverse proxy, creating a protective barrier for your web server.

1.  **Request Interception:** All user traffic is sent to the WAF first.
2.  **SSL Termination (HTTPS Mode):** If running in HTTPS mode, the WAF decrypts the traffic using its SSL certificate so it can be inspected.
3.  **Threat Inspection:** The WAF scans the request's URL, headers, and body for malicious patterns defined by regular expressions.
4.  **Blocking or Forwarding:**
    -   If a threat is found, the WAF blocks the request and redirects the user to a custom error page.
    -   If the request is clean, the WAF forwards it to the actual web server.
5.  **Response Rewriting:** The WAF intercepts the response from the web server. It rewrites URLs, redirects, and session cookies to ensure that all future communication continues to go through the proxy, making the process seamless to the end-user.
6.  **Relaying Response:** The modified response is sent back to the user's browser.

---

## File Structure

-   `WAF.py`: The main Python script containing all the WAF logic.
-   `error.html`: The customizable HTML page that is shown to users when their request is blocked.
-   `key.pem`: The private key for the SSL certificate (generated by you).
-   `cert.pem`: The public SSL certificate (generated by you).

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## 📝 Author

Created with ❤️ by **AMIRX**
