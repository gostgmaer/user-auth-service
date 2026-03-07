// src/services/deviceDetector.js
const crypto    = require('crypto');
const geoip     = require('geoip-lite');
const UAParser  = require('ua-parser-js');

class DeviceDetector {
  static detectDevice(req) {
    const userAgent = req.headers['user-agent'] || '';
    const ip        = this.getClientIP(req);
    const parser    = new UAParser(userAgent);
    const result    = parser.getResult();

    return {
      userAgent,
      ipAddress: ip,
      deviceId:  this.generateDeviceId(req),
      fingerprint: this.generateFingerprint(req),
      browser:   result.browser,
      os:        result.os,
      device:    result.device,
      location:  this.getLocationFromIP(ip),
      security:  this.analyzeSecurityIndicators(req),
      detectedAt: new Date(),
    };
  }

  static generateDeviceId(req) {
    const factors = [
      req.headers['user-agent'],
      req.headers['accept'],
      req.headers['accept-language'],
      req.headers['accept-encoding'],
      this.getClientIP(req),
    ].filter(Boolean);
    return crypto
      .createHash('sha256')
      .update(factors.join('|'))
      .digest('hex')
      .substring(0, 16);
  }

  static generateFingerprint(req) {
    const factors = [
      req.headers['user-agent'],
      req.headers['accept'],
      req.headers['accept-language'],
      req.headers['accept-encoding'],
      req.headers['connection'],
      req.headers['sec-fetch-site'],
      req.headers['sec-fetch-mode'],
      req.headers['sec-ch-ua-platform'],
      req.headers['sec-ch-ua-mobile'],
      this.getClientIP(req),
    ].filter(Boolean);
    return crypto.createHash('sha256').update(factors.join('|')).digest('hex');
  }

  static getClientIP(req) {
    const cf = req.headers['cf-connecting-ip'];
    const xff = req.headers['x-forwarded-for'];
    const xri = req.headers['x-real-ip'];
    let ip = cf || xff?.split(',')[0]?.trim() || xri || req.ip || '127.0.0.1';
    if (ip.startsWith('::ffff:')) ip = ip.substring(7);
    return ip;
  }

  static getLocationFromIP(ip) {
    try {
      if (
        ip === '127.0.0.1' || ip === 'localhost' || ip === '::1' ||
        ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')
      ) {
        return { country: 'Local', region: 'Local', city: 'Local', coordinates: { lat: null, lng: null }, timezone: null, isLocal: true };
      }
      const geo = geoip.lookup(ip);
      if (geo) {
        return {
          country: geo.country,
          region:  geo.region,
          city:    geo.city,
          coordinates: { lat: geo.ll?.[0] || null, lng: geo.ll?.[1] || null },
          timezone: geo.timezone || null,
          isLocal: false,
        };
      }
    } catch { /* ignore */ }
    return { country: null, region: null, city: null, coordinates: { lat: null, lng: null }, timezone: null };
  }

  static analyzeSecurityIndicators(req) {
    const ua          = req.headers['user-agent'] || '';
    const headerCount = Object.keys(req.headers).length;
    let suspiciousScore = 0;
    const flags = [];

    if (ua.length < 20)    { suspiciousScore += 30; flags.push('short_user_agent'); }
    if (headerCount < 4)   { suspiciousScore += 20; flags.push('few_headers'); }
    if (/bot|crawl|spider|scraper/i.test(ua)) { suspiciousScore += 50; flags.push('bot_pattern'); }

    return {
      suspiciousScore,
      riskLevel: suspiciousScore >= 50 ? 'high' : suspiciousScore >= 20 ? 'medium' : 'low',
      flags,
      analysis: {
        userAgentLength: ua.length,
        headerCount,
        timestamp: new Date(),
      },
    };
  }

  static extractRelevantHeaders(req) {
    const keys = [
      'user-agent', 'accept', 'accept-language', 'accept-encoding',
      'connection', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
    ];
    return keys.reduce((acc, key) => {
      if (req.headers[key]) acc[key] = req.headers[key];
      return acc;
    }, {});
  }
}

module.exports = DeviceDetector;
