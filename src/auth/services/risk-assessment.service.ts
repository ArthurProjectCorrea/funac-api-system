import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as geoip from 'geoip-lite';

export interface LoginAttempt {
  userId?: string;
  email: string;
  ipAddress: string;
  userAgent: string;
  timestamp: Date;
  success: boolean;
}

export interface RiskAssessment {
  riskScore: number; // 0-100
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factors: string[];
  requireMfa: boolean;
  requireStepUp: boolean;
  shouldBlock: boolean;
}

@Injectable()
export class RiskAssessmentService {
  private readonly enableGeolocation: boolean;
  private readonly suspiciousThreshold: number;
  private readonly blockThreshold: number;

  constructor(private configService: ConfigService) {
    this.enableGeolocation = this.configService.get<boolean>(
      'ENABLE_IP_GEOLOCATION',
      true,
    );
    this.suspiciousThreshold = this.configService.get<number>(
      'SUSPICIOUS_LOGIN_THRESHOLD',
      3,
    );
    this.blockThreshold = this.configService.get<number>(
      'BLOCK_LOGIN_THRESHOLD',
      5,
    );
  }

  /**
   * Avalia o risco de uma tentativa de login
   */
  assessLoginRisk(
    attempt: LoginAttempt,
    userHistory: LoginAttempt[] = [],
  ): RiskAssessment {
    let riskScore = 0;
    const factors: string[] = [];

    // 1. Verificar geolocalização anômala
    if (this.enableGeolocation) {
      const geoRisk = this.assessGeolocationRisk(attempt, userHistory);
      riskScore += geoRisk.score;
      factors.push(...geoRisk.factors);
    }

    // 2. Verificar dispositivo novo/anômalo
    const deviceRisk = this.assessDeviceRisk(attempt, userHistory);
    riskScore += deviceRisk.score;
    factors.push(...deviceRisk.factors);

    // 3. Verificar padrão temporal
    const temporalRisk = this.assessTemporalRisk(attempt, userHistory);
    riskScore += temporalRisk.score;
    factors.push(...temporalRisk.factors);

    // 4. Verificar tentativas falhas recentes
    const failureRisk = this.assessFailurePatternRisk(attempt, userHistory);
    riskScore += failureRisk.score;
    factors.push(...failureRisk.factors);

    // 5. Verificar características do IP
    const ipRisk = this.assessIpRisk(attempt.ipAddress);
    riskScore += ipRisk.score;
    factors.push(...ipRisk.factors);

    // Determinar nível de risco e ações
    const riskLevel = this.determineRiskLevel(riskScore);
    const requireMfa = riskScore >= 30;
    const requireStepUp = riskScore >= 50;
    const shouldBlock = riskScore >= 80;

    return {
      riskScore: Math.min(riskScore, 100),
      riskLevel,
      factors,
      requireMfa,
      requireStepUp,
      shouldBlock,
    };
  }

  /**
   * Avalia risco baseado em geolocalização
   */
  private assessGeolocationRisk(
    attempt: LoginAttempt,
    history: LoginAttempt[],
  ): { score: number; factors: string[] } {
    let score = 0;
    const factors: string[] = [];

    if (!this.enableGeolocation || history.length === 0) {
      return { score, factors };
    }

    const currentGeo = geoip.lookup(attempt.ipAddress);
    if (!currentGeo) {
      factors.push('Geolocalização não disponível');
      return { score: 5, factors };
    }

    // Verificar países dos últimos logins bem-sucedidos
    const recentSuccessfulLogins = history
      .filter(
        (h) =>
          h.success &&
          h.timestamp > new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
      )
      .slice(-10);

    if (recentSuccessfulLogins.length > 0) {
      const knownCountries = new Set(
        recentSuccessfulLogins
          .map((h) => geoip.lookup(h.ipAddress)?.country)
          .filter(Boolean),
      );

      if (!knownCountries.has(currentGeo.country)) {
        score += 25;
        factors.push(`Novo país: ${currentGeo.country}`);

        // Verificar "impossible travel"
        const lastLogin =
          recentSuccessfulLogins[recentSuccessfulLogins.length - 1];
        if (lastLogin) {
          const lastGeo = geoip.lookup(lastLogin.ipAddress);
          if (
            lastGeo &&
            this.isImpossibleTravel(
              lastGeo,
              currentGeo,
              lastLogin.timestamp,
              attempt.timestamp,
            )
          ) {
            score += 40;
            factors.push('Viagem impossível detectada');
          }
        }
      }

      // Verificar cidades novas
      const knownCities = new Set(
        recentSuccessfulLogins
          .map((h) => geoip.lookup(h.ipAddress)?.city)
          .filter(Boolean),
      );

      if (!knownCities.has(currentGeo.city)) {
        score += 10;
        factors.push(`Nova cidade: ${currentGeo.city}`);
      }
    }

    return { score, factors };
  }

  /**
   * Avalia risco baseado no dispositivo
   */
  private assessDeviceRisk(
    attempt: LoginAttempt,
    history: LoginAttempt[],
  ): { score: number; factors: string[] } {
    let score = 0;
    const factors: string[] = [];

    if (history.length === 0) {
      score += 15;
      factors.push('Primeiro login do usuário');
      return { score, factors };
    }

    const recentLogins = history.filter(
      (h) => h.timestamp > new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
    );

    if (recentLogins.length > 0) {
      const knownUserAgents = new Set(recentLogins.map((h) => h.userAgent));

      if (!knownUserAgents.has(attempt.userAgent)) {
        score += 20;
        factors.push('Novo dispositivo/navegador');
      }

      const knownIps = new Set(recentLogins.map((h) => h.ipAddress));
      if (!knownIps.has(attempt.ipAddress)) {
        score += 15;
        factors.push('Novo endereço IP');
      }
    }

    return { score, factors };
  }

  /**
   * Avalia risco baseado em padrões temporais
   */
  private assessTemporalRisk(
    attempt: LoginAttempt,
    history: LoginAttempt[],
  ): { score: number; factors: string[] } {
    let score = 0;
    const factors: string[] = [];

    const hour = attempt.timestamp.getHours();

    // Horário incomum (madrugada)
    if (hour >= 2 && hour <= 5) {
      score += 10;
      factors.push('Horário incomum de acesso');
    }

    // Verificar padrão histórico do usuário
    if (history.length >= 5) {
      const userHours = history
        .filter((h) => h.success)
        .map((h) => h.timestamp.getHours());

      const commonHours = new Set(userHours);
      if (!commonHours.has(hour)) {
        score += 15;
        factors.push('Horário atípico para este usuário');
      }
    }

    return { score, factors };
  }

  /**
   * Avalia risco baseado em padrão de falhas
   */
  private assessFailurePatternRisk(
    attempt: LoginAttempt,
    history: LoginAttempt[],
  ): { score: number; factors: string[] } {
    let score = 0;
    const factors: string[] = [];

    const recentAttempts = history.filter(
      (h) => h.timestamp > new Date(Date.now() - 60 * 60 * 1000), // última hora
    );

    const recentFailures = recentAttempts.filter((h) => !h.success);
    const failuresFromSameIp = recentFailures.filter(
      (h) => h.ipAddress === attempt.ipAddress,
    );

    if (failuresFromSameIp.length >= this.blockThreshold) {
      score += 60;
      factors.push(`${failuresFromSameIp.length} falhas recentes do mesmo IP`);
    } else if (failuresFromSameIp.length >= this.suspiciousThreshold) {
      score += 30;
      factors.push(`${failuresFromSameIp.length} falhas recentes`);
    }

    // Verificar spray de tentativas (múltiplos emails do mesmo IP)
    const emailsFromIp = new Set(
      recentAttempts
        .filter((h) => h.ipAddress === attempt.ipAddress)
        .map((h) => h.email),
    );

    if (emailsFromIp.size >= 5) {
      score += 40;
      factors.push('Múltiplas contas tentadas do mesmo IP');
    }

    return { score, factors };
  }

  /**
   * Avalia risco baseado nas características do IP
   */
  private assessIpRisk(ipAddress: string): {
    score: number;
    factors: string[];
  } {
    let score = 0;
    const factors: string[] = [];

    // Verificar se é IP privado/local
    if (this.isPrivateIP(ipAddress)) {
      score -= 10; // IPs privados são menos suspeitos
      factors.push('IP privado/interno');
      return { score, factors };
    }

    // Verificar características conhecidas de IPs suspeitos
    // (Em produção, integrar com serviços de reputation como VirusTotal, AbuseIPDB)

    // Verificar padrões de IP suspeitos (exemplo básico)
    if (this.isSuspiciousIPPattern(ipAddress)) {
      score += 25;
      factors.push('Padrão de IP suspeito');
    }

    return { score, factors };
  }

  /**
   * Determina nível de risco baseado na pontuação
   */
  private determineRiskLevel(score: number): RiskAssessment['riskLevel'] {
    if (score >= 80) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 30) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Verifica se a viagem é fisicamente impossível
   */
  private isImpossibleTravel(
    from: geoip.Lookup,
    to: geoip.Lookup,
    fromTime: Date,
    toTime: Date,
  ): boolean {
    // Calcular distância aproximada entre coordenadas
    const distance = this.calculateDistance(
      from.ll[0],
      from.ll[1],
      to.ll[0],
      to.ll[1],
    );

    const timeDiff = (toTime.getTime() - fromTime.getTime()) / (1000 * 60 * 60); // horas
    const maxSpeed = 900; // km/h (velocidade de avião comercial)

    return distance > maxSpeed * timeDiff;
  }

  /**
   * Calcula distância entre duas coordenadas (fórmula de Haversine)
   */
  private calculateDistance(
    lat1: number,
    lon1: number,
    lat2: number,
    lon2: number,
  ): number {
    const R = 6371; // Raio da Terra em km
    const dLat = this.deg2rad(lat2 - lat1);
    const dLon = this.deg2rad(lon2 - lon1);
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(this.deg2rad(lat1)) *
        Math.cos(this.deg2rad(lat2)) *
        Math.sin(dLon / 2) *
        Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }

  private deg2rad(deg: number): number {
    return deg * (Math.PI / 180);
  }

  /**
   * Verifica se é IP privado
   */
  private isPrivateIP(ip: string): boolean {
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./,
      /^::1$/,
      /^fc00:/,
    ];

    return privateRanges.some((range) => range.test(ip));
  }

  /**
   * Verifica padrões suspeitos de IP (exemplo básico)
   */
  private isSuspiciousIPPattern(ip: string): boolean {
    // Exemplos de padrões suspeitos
    const suspiciousPatterns = [
      /^tor-/, // Tor exit nodes
      /^proxy-/, // Proxies conhecidos
      /\.onion$/, // Tor hidden services
    ];

    return suspiciousPatterns.some((pattern) => pattern.test(ip));
  }
}
