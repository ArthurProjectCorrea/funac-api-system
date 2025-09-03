import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import * as zxcvbn from 'zxcvbn';
import * as crypto from 'crypto';

export interface PasswordValidationResult {
  isValid: boolean;
  score: number;
  feedback: {
    warning: string;
    suggestions: string[];
  };
  errors: string[];
}

@Injectable()
export class PasswordService {
  private readonly minLength: number;
  private readonly maxLength: number;
  private readonly minScore: number;
  private readonly pepper: string;

  constructor(private configService: ConfigService) {
    this.minLength = this.configService.get<number>('PASSWORD_MIN_LENGTH', 12);
    this.maxLength = this.configService.get<number>('PASSWORD_MAX_LENGTH', 128);
    this.minScore = this.configService.get<number>('PASSWORD_MIN_SCORE', 3);
    this.pepper = this.configService.get<string>('PASSWORD_PEPPER', '');
  }
  /**
   * Hash a password using Argon2id with pepper
   */
  async hashPassword(password: string): Promise<string> {
    // Adiciona pepper antes do hash
    const pepperedPassword = password + this.pepper;

    return argon2.hash(pepperedPassword, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16, // 64 MB
      timeCost: 3,
      parallelism: 1,
    });
  }

  /**
   * Verify a password against its hash
   */
  async verifyPassword(hash: string, password: string): Promise<boolean> {
    // Adiciona pepper antes da verificação
    const pepperedPassword = password + this.pepper;

    try {
      return await argon2.verify(hash, pepperedPassword);
    } catch {
      return false;
    }
  }

  /**
   * Valida a força e política da senha com zxcvbn
   */
  validatePassword(password: string): PasswordValidationResult {
    const errors: string[] = [];

    // Verificações básicas
    if (password.length < this.minLength) {
      errors.push(`A senha deve ter pelo menos ${this.minLength} caracteres`);
    }

    if (password.length > this.maxLength) {
      errors.push(`A senha deve ter no máximo ${this.maxLength} caracteres`);
    }

    // Verificar caracteres especiais mínimos
    if (!/[A-Z]/.test(password)) {
      errors.push('A senha deve conter pelo menos uma letra maiúscula');
    }

    if (!/[a-z]/.test(password)) {
      errors.push('A senha deve conter pelo menos uma letra minúscula');
    }

    if (!/[0-9]/.test(password)) {
      errors.push('A senha deve conter pelo menos um número');
    }

    if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
      errors.push('A senha deve conter pelo menos um caractere especial');
    }

    // Análise de força com zxcvbn
    const strength = zxcvbn(password);

    if (strength.score < this.minScore) {
      errors.push(
        `A senha é muito fraca (pontuação: ${strength.score}/${this.minScore})`,
      );
    }

    // Verificar padrões comuns perigosos
    if (this.hasCommonPatterns(password)) {
      errors.push('A senha contém padrões comuns inseguros');
    }

    return {
      isValid: errors.length === 0,
      score: strength.score,
      feedback: {
        warning: strength.feedback.warning || '',
        suggestions: strength.feedback.suggestions || [],
      },
      errors,
    };
  }

  /**
   * Verifica se a senha foi comprometida (simulação)
   */
  isPasswordCompromised(password: string): boolean {
    const commonPasswords = [
      '123456',
      'password',
      '123456789',
      '12345678',
      '12345',
      '1234567',
      '1234567890',
      'qwerty',
      'abc123',
      'Million2',
      'password123',
      'admin123',
      'letmein',
      'welcome',
      'monkey',
      'admin',
      '123456789',
      'qwerty123',
    ];

    const lowerPassword = password.toLowerCase();
    return commonPasswords.some((common) =>
      lowerPassword.includes(common.toLowerCase()),
    );
  }

  /**
   * Verifica padrões comuns inseguros
   */
  private hasCommonPatterns(password: string): boolean {
    // Sequências simples
    const sequences = ['123', 'abc', 'qwe', 'asd', 'zxc'];
    const lowerPassword = password.toLowerCase();

    return sequences.some((seq) => lowerPassword.includes(seq));
  }

  /**
   * Generate a secure random password
   */
  generateSecurePassword(length: number = 16): string {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '@$!%*?&';
    const allChars = lowercase + uppercase + numbers + symbols;

    let password = '';

    // Ensure at least one character from each category
    password += this.getRandomChar(lowercase);
    password += this.getRandomChar(uppercase);
    password += this.getRandomChar(numbers);
    password += this.getRandomChar(symbols);

    // Fill the rest randomly
    for (let i = 4; i < length; i++) {
      password += this.getRandomChar(allChars);
    }

    // Shuffle the password
    return this.shuffleString(password);
  }

  /**
   * Gera senha temporária segura
   */
  generateTemporaryPassword(): string {
    return this.generateSecurePassword(16);
  }

  /**
   * Pega caractere aleatório de um conjunto
   */
  private getRandomChar(charset: string): string {
    const randomIndex = crypto.randomInt(0, charset.length);
    return charset[randomIndex];
  }

  /**
   * Embaralha string
   */
  private shuffleString(str: string): string {
    const array = str.split('');
    for (let i = array.length - 1; i > 0; i--) {
      const j = crypto.randomInt(0, i + 1);
      [array[i], array[j]] = [array[j], array[i]];
    }
    return array.join('');
  }
}
