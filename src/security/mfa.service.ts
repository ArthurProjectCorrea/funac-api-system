/* eslint-disable */
import { Injectable } from '@nestjs/common';
import * as QRCode from 'qrcode';

const speakeasy = require('speakeasy');

@Injectable()
export class MfaService {
  /**
   * Generate MFA secret for user
   */
  generateSecret(userEmail: string): {
    secret: string;
    otpauthUrl: string;
  } {
    const secret = speakeasy.generateSecret({
      name: userEmail,
      issuer: 'FUNAC System',
      length: 32,
    });

    return {
      secret: secret.base32 || '',
      otpauthUrl: secret.otpauth_url || '',
    };
  }

  /**
   * Generate QR code for MFA setup
   */
  async generateQRCode(otpauthUrl: string): Promise<string> {
    return QRCode.toDataURL(otpauthUrl);
  }

  /**
   * Verify TOTP token
   */
  verifyToken(secret: string, token: string, window: number = 2): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window, // Allow ±2 time steps (±60 seconds)
    });
  }

  /**
   * Generate backup codes for MFA recovery
   */
  generateBackupCodes(count: number = 8): string[] {
    const codes: string[] = [];
    for (let i = 0; i < count; i++) {
      const code = Math.random().toString(36).substring(2, 10).toUpperCase();
      codes.push(code);
    }
    return codes;
  }

  /**
   * Verify backup code
   */
  verifyBackupCode(userCodes: string[], providedCode: string): boolean {
    return userCodes.includes(providedCode.toUpperCase());
  }

  /**
   * Remove used backup code
   */
  removeBackupCode(userCodes: string[], usedCode: string): string[] {
    return userCodes.filter((code) => code !== usedCode.toUpperCase());
  }
}
