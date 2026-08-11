# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities. Report
them privately instead:

- Open a private advisory at
  https://github.com/xiabai2008/PacketForge/security/advisories/new, or
- Email the maintainers via the repository's GitHub profile.

You should receive an acknowledgement within 5 business days, and a first
response within 10 business days. We will keep you informed about the
remediation timeline.

## Disclosure policy

- The report is kept confidential until a fix is released.
- Once fixed, a security advisory is published along with the release notes.

## Security design (built-in)

PacketForge is a dual-use tool intended for authorized penetration testing.
The following controls are enforced at the core level and must not be
weakened by contributions:

- Input validation: IP/CIDR/FQDN, port ranges, BPF/display filters, and
  sandboxed file paths (`core/security.py`)
- Command injection protection: all subprocess calls use `shell=False`
- Rate limiting: Nmap scans are throttled by default (10 calls / hour)
- Tamper-evident audit trail: every operation is chained via SHA-256
  (`core/audit.py`), exportable as a compliance report

## Responsible use

This project must only be used against systems you own or are explicitly
authorized to test. The project assumes no liability for misuse; users are
responsible for complying with all applicable laws and regulations.
