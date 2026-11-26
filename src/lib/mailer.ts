import nodemailer from 'nodemailer';
import { insertPreviewEmail } from '../db/authRepo.ts';

export interface OutboundSecurityEmail {
  recipientEmail: string;
  subject: string;
  category: 'verification' | 'password_reset';
  actionCode: string;
  actionToken: string;
  bodyPreview: string;
}

export function isSmtpConfigured(): boolean {
  return Boolean(
    process.env.SMTP_HOST &&
      process.env.SMTP_PORT &&
      process.env.SMTP_USER &&
      process.env.SMTP_PASS
  );
}

export async function dispatchSecurityEmail(mail: OutboundSecurityEmail): Promise<{
  deliveredVia: 'smtp' | 'preview';
}> {
  if (isSmtpConfigured()) {
    const port = Number(process.env.SMTP_PORT) || 587;
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port,
      secure: port === 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: mail.recipientEmail,
      subject: mail.subject,
      text: `${mail.bodyPreview}\n\nCódigo: ${mail.actionCode}`,
    });

    return { deliveredVia: 'smtp' };
  }

  await insertPreviewEmail(mail);
  return { deliveredVia: 'preview' };
}
