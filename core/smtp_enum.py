"""
core/smtp_enum.py — ReconNinja v7.0.0
SMTP User Enumeration via VRFY, EXPN, and RCPT TO commands.

Maps valid email addresses by probing SMTP servers for username
existence. Each valid address found becomes a phishing/BEC target.

No external tools — pure Python smtplib + socket stdlib.
"""

from __future__ import annotations

import smtplib
import socket
from dataclasses import dataclass, field
from pathlib import Path

from utils.helpers import ensure_dir
from utils.logger import safe_print

COMMON_USERS = [
    "admin", "administrator", "root", "info", "contact", "support",
    "security", "abuse", "postmaster", "webmaster", "hostmaster",
    "noreply", "no-reply", "sales", "hr", "finance", "cto", "ceo",
    "devops", "it", "help", "helpdesk", "mail", "careers", "jobs",
]


@dataclass
class SMTPEnumResult:
    host:          str
    port:          int
    valid_users:   list[str] = field(default_factory=list)
    banner:        str       = ""
    methods_tried: list[str] = field(default_factory=list)
    error:         str       = ""

    def to_dict(self) -> dict:
        return {
            "host":          self.host,
            "port":          self.port,
            "valid_users":   self.valid_users,
            "banner":        self.banner,
            "methods_tried": self.methods_tried,
        }


def smtp_user_enum(
    host: str,
    domain: str,
    out_folder: Path,
    port: int = 25,
    users: list[str] | None = None,
    timeout: int = 10,
) -> SMTPEnumResult:
    """
    Enumerate valid SMTP users via VRFY/EXPN/RCPT TO.

    Args:
        host:      SMTP server hostname or IP
        domain:    target domain (used for RCPT TO)
        out_folder: output directory
        port:      SMTP port (default 25)
        users:     custom user list (falls back to COMMON_USERS)
        timeout:   per-command timeout

    Returns:
        SMTPEnumResult with list of valid user addresses
    """
    ensure_dir(out_folder)
    result = SMTPEnumResult(host=host, port=port)
    test_users = users or COMMON_USERS
    safe_print(f"[info]▶ SMTP User Enum — {host}:{port} ({len(test_users)} users)[/]")

    try:
        smtp = smtplib.SMTP(timeout=timeout)
        code, banner = smtp.connect(host, port)
        result.banner = banner.decode(errors="ignore") if isinstance(banner, bytes) else str(banner)

        # Try VRFY
        vrfy_works = False
        try:
            code, msg = smtp.verify(test_users[0])
            if code in (250, 252):
                vrfy_works = True
        except smtplib.SMTPException:
            pass

        if vrfy_works:
            result.methods_tried.append("VRFY")
            for user in test_users:
                try:
                    code, _ = smtp.verify(user)
                    if code in (250, 252):
                        result.valid_users.append(f"{user}@{domain}")
                except smtplib.SMTPException:
                    pass
        else:
            # Fall back to RCPT TO
            result.methods_tried.append("RCPT TO")
            try:
                smtp.ehlo(domain)
                smtp.mail("test@test.com")
                for user in test_users:
                    addr = f"{user}@{domain}"
                    try:
                        code, _ = smtp.rcpt(addr)
                        if code in (250, 251):
                            result.valid_users.append(addr)
                    except smtplib.SMTPRecipientsRefused:
                        pass
                    except Exception:
                        pass
            except Exception:
                pass

        smtp.quit()

    except (ConnectionRefusedError, socket.timeout) as e:
        result.error = f"Connection failed: {e}"
    except Exception as e:
        result.error = str(e)

    if result.valid_users:
        safe_print(f"  [danger]⚠  SMTP: {len(result.valid_users)} valid user(s) found[/]")
        for u in result.valid_users:
            safe_print(f"    [warning]→ {u}[/]")
    else:
        safe_print("  [dim]SMTP: no valid users found (or enum blocked)[/]")

    # Save
    out_file = out_folder / "smtp_enum.txt"
    lines = [
        f"# SMTP User Enumeration — {host}:{port}",
        f"Banner: {result.banner}",
        f"Methods: {', '.join(result.methods_tried)}",
        "",
        "Valid users:",
    ] + result.valid_users
    out_file.write_text("\n".join(lines))
    return result
