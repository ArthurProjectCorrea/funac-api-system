import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../database/prisma.service';
import * as crypto from 'crypto';
import { UAParser } from 'ua-parser-js';
import * as geoip from 'geoip-lite';

export interface DeviceInfo {
  fingerprint: string;
  browser: string;
  os: string;
  deviceType: string;
  ipAddress: string;
  location?: {
    country: string;
    region: string;
    city: string;
  };
  isTrusted: boolean;
  firstSeen: Date;
  lastSeen: Date;
}

export interface NewDeviceDetection {
  isNewDevice: boolean;
  isNewLocation: boolean;
  riskScore: number;
  shouldNotify: boolean;
  deviceInfo: DeviceInfo;
}

@Injectable()
export class DeviceManagementService {
  private readonly logger = new Logger(DeviceManagementService.name);
  private readonly trustThresholdDays: number;

  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
  ) {
    this.trustThresholdDays = this.configService.get<number>(
      'DEVICE_TRUST_THRESHOLD_DAYS',
      7,
    );
  }

  /**
   * Gera fingerprint único do dispositivo
   */
  generateDeviceFingerprint(userAgent: string): string {
    const parser = new UAParser(userAgent);
    const result = parser.getResult();

    // Combinar informações para criar fingerprint
    const deviceString = [
      result.browser.name || 'unknown',
      result.browser.version || 'unknown',
      result.os.name || 'unknown',
      result.os.version || 'unknown',
      result.device.type || 'desktop',
      result.device.vendor || 'unknown',
      result.device.model || 'unknown',
    ].join('|');

    return crypto
      .createHash('sha256')
      .update(deviceString)
      .digest('hex')
      .substring(0, 32);
  }

  /**
   * Analisa User-Agent e extrai informações do dispositivo
   */
  parseDeviceInfo(
    userAgent: string,
    ipAddress: string,
  ): Omit<DeviceInfo, 'isTrusted' | 'firstSeen' | 'lastSeen'> {
    const parser = new UAParser(userAgent);
    const result = parser.getResult();
    const geo = geoip.lookup(ipAddress);

    return {
      fingerprint: this.generateDeviceFingerprint(userAgent),
      browser:
        `${result.browser.name || 'Unknown'} ${result.browser.version || ''}`.trim(),
      os: `${result.os.name || 'Unknown'} ${result.os.version || ''}`.trim(),
      deviceType: result.device.type || 'desktop',
      ipAddress,
      location: geo
        ? {
            country: geo.country,
            region: geo.region,
            city: geo.city,
          }
        : undefined,
    };
  }

  /**
   * Detecta se é um novo dispositivo e avalia risco
   */
  async detectNewDevice(
    userId: string,
    userAgent: string,
    ipAddress: string,
  ): Promise<NewDeviceDetection> {
    const deviceInfo = this.parseDeviceInfo(userAgent, ipAddress);

    // Buscar sessões existentes do usuário
    const existingSessions = await this.prisma.session.findMany({
      where: {
        userId,
        isActive: true,
      },
      select: {
        deviceFingerprint: true,
        ipAddress: true,
        userAgent: true,
        createdAt: true,
        lastUsedAt: true,
      },
    });

    // Verificar se é dispositivo conhecido
    const isNewDevice = !existingSessions.some(
      (session) => session.deviceFingerprint === deviceInfo.fingerprint,
    );

    // Verificar se é nova localização
    const isNewLocation = !existingSessions.some((session) => {
      if (!session.ipAddress) return false;
      const sessionGeo = geoip.lookup(session.ipAddress);
      return (
        sessionGeo &&
        deviceInfo.location &&
        sessionGeo.country === deviceInfo.location.country
      );
    });

    // Calcular score de risco
    let riskScore = 0;

    if (isNewDevice) riskScore += 50;
    if (isNewLocation) riskScore += 30;

    // Verificar se IP é de proxy/VPN/Tor (implementação básica)
    if (this.isHighRiskIP()) {
      riskScore += 40;
    }

    // Verificar se é horário atípico (implementação básica)
    const hour = new Date().getHours();
    if (hour < 6 || hour > 22) {
      riskScore += 10;
    }

    const shouldNotify =
      riskScore >=
      this.configService.get<number>('NEW_DEVICE_NOTIFICATION_THRESHOLD', 50);

    // Determinar se dispositivo é confiável
    const sessionsForDevice = existingSessions.filter(
      (s) =>
        s.deviceFingerprint === deviceInfo.fingerprint &&
        s.createdAt instanceof Date,
    );

    const oldestSession =
      sessionsForDevice.length > 0
        ? sessionsForDevice.reduce((oldest, session) =>
            !oldest || session.createdAt < oldest.createdAt ? session : oldest,
          )
        : null;

    const isTrusted = oldestSession
      ? Date.now() - oldestSession.createdAt.getTime() >
        this.trustThresholdDays * 24 * 60 * 60 * 1000
      : false;

    return {
      isNewDevice,
      isNewLocation,
      riskScore: Math.min(riskScore, 100),
      shouldNotify,
      deviceInfo: {
        ...deviceInfo,
        isTrusted,
        firstSeen: oldestSession?.createdAt || new Date(),
        lastSeen: new Date(),
      },
    };
  }

  /**
   * Lista dispositivos do usuário
   */
  async getUserDevices(userId: string): Promise<DeviceInfo[]> {
    const sessions = await this.prisma.session.findMany({
      where: {
        userId,
        isActive: true,
      },
      orderBy: {
        lastUsedAt: 'desc',
      },
      select: {
        deviceFingerprint: true,
        ipAddress: true,
        userAgent: true,
        createdAt: true,
        lastUsedAt: true,
      },
    });

    // Agrupar por device fingerprint
    const deviceMap = new Map<string, DeviceInfo>();

    for (const session of sessions) {
      if (!session.deviceFingerprint || !session.userAgent) continue;

      const existing = deviceMap.get(session.deviceFingerprint);
      const deviceInfo = this.parseDeviceInfo(
        session.userAgent,
        session.ipAddress || '',
      );

      if (!existing) {
        const isTrusted =
          Date.now() - session.createdAt.getTime() >
          this.trustThresholdDays * 24 * 60 * 60 * 1000;

        deviceMap.set(session.deviceFingerprint, {
          ...deviceInfo,
          isTrusted,
          firstSeen: session.createdAt,
          lastSeen: session.lastUsedAt || session.createdAt,
        });
      } else {
        // Atualizar última utilização
        if (session.lastUsedAt && session.lastUsedAt > existing.lastSeen) {
          existing.lastSeen = session.lastUsedAt;
        }
      }
    }

    return Array.from(deviceMap.values());
  }

  /**
   * Marca dispositivo como confiável
   */
  trustDevice(userId: string, deviceFingerprint: string): void {
    // Não há tabela específica para dispositivos confiáveis
    // A confiança é calculada baseada no tempo de uso
    // Esta função pode ser expandida para incluir uma tabela de dispositivos explicitamente confiáveis

    this.logger.log(
      `Dispositivo ${deviceFingerprint} marcado como confiável para usuário ${userId}`,
    );

    // Implementação futura: criar tabela trusted_devices
    // await this.prisma.trustedDevice.create({
    //   data: { userId, deviceFingerprint, trustedAt: new Date() }
    // });
  }

  /**
   * Remove confiança de um dispositivo
   */
  async untrustDevice(
    userId: string,
    deviceFingerprint: string,
  ): Promise<void> {
    // Revogar todas as sessões deste dispositivo
    const revokedCount = await this.prisma.session.updateMany({
      where: {
        userId,
        deviceFingerprint,
        isActive: true,
      },
      data: {
        isActive: false,
        revokedAt: new Date(),
      },
    });

    this.logger.log(
      `Dispositivo ${deviceFingerprint} removido da confiança. ${revokedCount.count} sessões revogadas.`,
    );
  }

  /**
   * Obtém estatísticas de dispositivos do usuário
   */
  async getDeviceStats(userId: string): Promise<{
    totalDevices: number;
    trustedDevices: number;
    activeSessions: number;
    newDevicesLast30Days: number;
  }> {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const sessions = await this.prisma.session.findMany({
      where: { userId },
      select: {
        deviceFingerprint: true,
        createdAt: true,
        isActive: true,
      },
    });

    const uniqueDevices = new Set(
      sessions
        .filter((s) => s.deviceFingerprint)
        .map((s) => s.deviceFingerprint),
    );

    const trustedDevices = sessions.filter(
      (session) =>
        session.deviceFingerprint &&
        Date.now() - session.createdAt.getTime() >
          this.trustThresholdDays * 24 * 60 * 60 * 1000,
    );

    const uniqueTrustedDevices = new Set(
      trustedDevices.map((s) => s.deviceFingerprint),
    );

    const newDevicesLast30Days = sessions.filter(
      (session) => session.createdAt >= thirtyDaysAgo,
    );

    const uniqueNewDevices = new Set(
      newDevicesLast30Days
        .filter((s) => s.deviceFingerprint)
        .map((s) => s.deviceFingerprint),
    );

    return {
      totalDevices: uniqueDevices.size,
      trustedDevices: uniqueTrustedDevices.size,
      activeSessions: sessions.filter((s) => s.isActive).length,
      newDevicesLast30Days: uniqueNewDevices.size,
    };
  }

  /**
   * Verificação básica de IP de alto risco
   */
  private isHighRiskIP(): boolean {
    // Implementação básica - pode ser expandida com serviços de threat intelligence
    // Para implementação completa, usar serviços como:
    // - AbuseIPDB
    // - VirusTotal
    // - MaxMind

    return false; // Placeholder
  }
}
