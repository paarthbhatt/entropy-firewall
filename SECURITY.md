# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability within Entropy, please follow these steps:

1.  **Do NOT open a public issue.** This allows us to assess the risk and fix the issue before it is exploited.
2.  Email our security team at `security@example.com` (replace with actual email) or open a **Security Advisory** on GitHub if enabled.
3.  Include a detailed description of the vulnerability, steps to reproduce, and any potential impact.

## Security Features

Entropy is designed to be secure by default:

*   **API Keys**: Never logged or exposed in error messages.
*   **PII/Secrets**: Automatically redacted from logs and outputs.
*   **Dependencies**: Regularly scanned for vulnerabilities.
*   **Container**: Runs as non-root user.

## Recognition

We believe in safe disclosure and will credit researchers who responsibly report vulnerabilities.
