"""Outbound email. Dev delivers to Mailpit, so nothing leaves the machine."""

import asyncio
import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

from app.config import Settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Mail:
    to: str
    subject: str
    body: str


class Mailer(Protocol):
    async def send(self, mail: Mail) -> None: ...


class SmtpMailer:
    def __init__(self, settings: Settings) -> None:
        self._host = settings.smtp_host
        self._port = settings.smtp_port
        self._from = settings.mail_from

    def _send_sync(self, mail: Mail) -> None:
        msg = EmailMessage()
        msg["From"] = self._from
        msg["To"] = mail.to
        msg["Subject"] = mail.subject
        msg.set_content(mail.body)
        with smtplib.SMTP(self._host, self._port, timeout=5) as smtp:
            smtp.send_message(msg)

    async def send(self, mail: Mail) -> None:
        try:
            await asyncio.to_thread(self._send_sync, mail)
        except OSError as exc:
            # Mail failure must not undo the business action; it is logged for the operator.
            logger.warning("mail delivery failed (%s): %s", type(exc).__name__, mail.subject)


class MemoryMailer:
    """Test double that records messages."""

    def __init__(self) -> None:
        self.sent: list[Mail] = []

    async def send(self, mail: Mail) -> None:
        self.sent.append(mail)
