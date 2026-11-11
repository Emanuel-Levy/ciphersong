"""
Serviço de Envio de E-mails Transacionais para Códigos OTP (`senior-architect` + `security-specialist`).

Suporta:
1. Resend API REST (`RESEND_API_KEY`)
2. SMTP Padrão com TLS/SSL (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`)
3. Provedor de Desenvolvimento e Testes (Mock/Console Logger com histórico em memória)
"""

from __future__ import annotations

import email.mime.multipart
import email.mime.text
import logging
import os
import smtplib
import ssl
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


class TransactionalEmailService:
    """Despachante de e-mails com suporte a múltiplos provedores transacionais e fallback de desenvolvimento."""

    def __init__(self) -> None:
        self.resend_api_key = os.getenv("RESEND_API_KEY")
        self.smtp_host = os.getenv("SMTP_HOST")
        self.smtp_port = int(os.getenv("SMTP_PORT") or 587)
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_password = os.getenv("SMTP_PASSWORD") or os.getenv("SMTP_PASS")
        self.from_email = os.getenv("SMTP_FROM") or os.getenv("RESEND_FROM") or "CipherSong <auth@ciphersong.app>"

        # Histórico em memória dos últimos e-mails enviados (útil para testes automatizados)
        self.sent_history: list[dict[str, Any]] = []

    def build_otp_html(self, codigo: str, expires_in_minutes: int = 10) -> str:
        """Gera o HTML responsivo e com visual moderno do e-mail de código OTP."""
        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Código de Acesso CipherSong</title>
</head>
<body style="margin: 0; padding: 0; background-color: #09090B; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #F4F4F5;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #09090B; padding: 32px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width: 460px; background-color: #18181B; border: 1px solid #27272A; border-radius: 16px; padding: 32px 24px; text-align: center;">
          <tr>
            <td>
              <div style="display: inline-block; width: 48px; height: 48px; background-color: #083344; border: 2px solid #06B6D4; border-radius: 14px; line-height: 48px; font-size: 24px; color: #06B6D4;">
                🎵
              </div>
              <h1 style="margin: 16px 0 4px 0; font-size: 22px; font-weight: 700; color: #FFFFFF;">CipherSong</h1>
              <p style="margin: 0 0 24px 0; font-size: 13px; color: #A1A1AA;">Gestão de Repertório & Equipes Musicais</p>
              
              <div style="background-color: #09090B; border: 1px solid #27272A; border-radius: 12px; padding: 20px 16px; margin-bottom: 24px;">
                <p style="margin: 0 0 10px 0; font-size: 13px; color: #A1A1AA;">Seu código de acesso único é:</p>
                <div style="font-size: 38px; font-weight: 800; letter-spacing: 8px; color: #06B6D4; font-family: 'Courier New', Courier, monospace;">
                  {codigo}
                </div>
                <p style="margin: 12px 0 0 0; font-size: 12px; color: #71717A;">
                  ⏱️ Válido por <strong>{expires_in_minutes} minutos</strong>
                </p>
              </div>

              <p style="margin: 0 0 16px 0; font-size: 12px; color: #A1A1AA; line-height: 1.5;">
                Digite este código no aplicativo CipherSong para entrar na sua conta.
              </p>
              
              <div style="border-top: 1px solid #27272A; padding-top: 16px; margin-top: 16px;">
                <p style="margin: 0; font-size: 11px; color: #71717A; line-height: 1.4;">
                  🛡️ <strong>Segurança:</strong> Nunca compartilhe este código. Nenhuma pessoa da nossa equipe pedirá este código a você. Se não foi você quem solicitou, desconsidere este e-mail.
                </p>
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    def send_otp_email(
        self,
        to_email: str,
        codigo: str,
        expires_in_minutes: int = 10,
    ) -> dict[str, Any]:
        """
        Envia o e-mail com o código de 6 dígitos para o destinatário usando o provedor configurado.
        Retorna informações sobre o envio.
        """
        subject = f"Seu código de acesso CipherSong: {codigo}"
        plain_text = (
            f"CipherSong - Código de Acesso\n\n"
            f"Seu código de verificação é: {codigo}\n\n"
            f"Este código é de uso único e expira em {expires_in_minutes} minutos.\n"
            f"Se não foi você quem solicitou, desconsidere este e-mail."
        )
        html_body = self.build_otp_html(codigo, expires_in_minutes)

        # 1. Envio via Resend API
        if self.resend_api_key:
            try:
                headers = {
                    "Authorization": f"Bearer {self.resend_api_key}",
                    "Content-Type": "application/json",
                }
                payload = {
                    "from": self.from_email,
                    "to": [to_email],
                    "subject": subject,
                    "html": html_body,
                    "text": plain_text,
                }
                with httpx.Client(timeout=10.0) as client:
                    resp = client.post("https://api.resend.com/emails", json=payload, headers=headers)
                    if resp.status_code in (200, 201):
                        info = {"status": "sent", "provider": "resend", "data": resp.json()}
                        self.sent_history.append({"to": to_email, "code": codigo, "info": info})
                        return info
            except Exception as exc:
                print(f"[Resend Error Fallback]: {exc}")

        # 2. Envio via SMTP Padrão (Gmail, AWS SES, Postmark, Mailgun, etc.)
        if self.smtp_host and self.smtp_user and self.smtp_password:
            try:
                msg = email.mime.multipart.MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = self.from_email
                msg["To"] = to_email
                msg.attach(email.mime.text.MIMEText(plain_text, "plain", "utf-8"))
                msg.attach(email.mime.text.MIMEText(html_body, "html", "utf-8"))

                context = ssl.create_default_context()
                if self.smtp_port == 465:
                    with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, context=context, timeout=12) as server:
                        server.login(self.smtp_user, self.smtp_password)
                        server.send_message(msg)
                else:
                    with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=12) as server:
                        server.starttls(context=context)
                        server.login(self.smtp_user, self.smtp_password)
                        server.send_message(msg)

                info = {"status": "sent", "provider": "smtp", "host": self.smtp_host}
                self.sent_history.append({"to": to_email, "code": codigo, "info": info})
                return info
            except Exception as exc:
                print(f"[SMTP Error Fallback]: {exc}")

        # 3. Provedor de Desenvolvimento / Testes (Console Logger com Mock Delivery)
        print("\n" + "=" * 60)
        print(f" [DEV / MOCK EMAIL TRANSACTIONAL]")
        print(f" Para: {to_email}")
        print(f" Assunto: {subject}")
        print(f" Código OTP: >>> {codigo} <<< (Válido por {expires_in_minutes} min)")
        print("=" * 60 + "\n")

        info = {
            "status": "delivered_dev",
            "provider": "development_mock",
            "message": "E-mail simulado com sucesso em ambiente de desenvolvimento/testes.",
            "code_preview": codigo,
        }
        self.sent_history.append({"to": to_email, "code": codigo, "info": info})
        return info


# Instância Singleton do despachante de e-mails
default_email_service = TransactionalEmailService()
