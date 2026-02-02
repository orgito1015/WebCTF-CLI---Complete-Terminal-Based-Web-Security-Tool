/**
 * Security Analysis Module
 * Advanced security testing features for CTF challenges
 */

const chalk = require('chalk');

class SecurityAnalyzer {
  constructor(page) {
    this.page = page;
  }

  /**
   * Analyze security headers
   */
  async analyzeSecurityHeaders(response) {
    const headers = response.headers();
    const analysis = {
      score: 0,
      findings: [],
      headers: {}
    };

    const securityHeaders = {
      'strict-transport-security': { weight: 15, name: 'HSTS' },
      'content-security-policy': { weight: 20, name: 'CSP' },
      'x-frame-options': { weight: 10, name: 'X-Frame-Options' },
      'x-content-type-options': { weight: 10, name: 'X-Content-Type-Options' },
      'x-xss-protection': { weight: 5, name: 'X-XSS-Protection' },
      'referrer-policy': { weight: 5, name: 'Referrer-Policy' },
      'permissions-policy': { weight: 10, name: 'Permissions-Policy' }
    };

    // Check for security headers
    Object.entries(securityHeaders).forEach(([header, config]) => {
      if (headers[header]) {
        analysis.score += config.weight;
        analysis.headers[config.name] = headers[header];
        analysis.findings.push({
          type: 'good',
          message: `${config.name} header present`
        });
      } else {
        analysis.findings.push({
          type: 'warning',
          message: `${config.name} header missing`
        });
      }
    });

    // Check for server disclosure
    if (headers['server']) {
      analysis.findings.push({
        type: 'info',
        message: `Server header disclosed: ${headers['server']}`
      });
    }

    // Check for X-Powered-By
    if (headers['x-powered-by']) {
      analysis.findings.push({
        type: 'warning',
        message: `X-Powered-By header disclosed: ${headers['x-powered-by']}`
      });
    }

    // Analyze CSP if present
    if (headers['content-security-policy']) {
      const cspAnalysis = this.analyzeCSP(headers['content-security-policy']);
      analysis.findings.push(...cspAnalysis);
    }

    return analysis;
  }

  /**
   * Analyze Content Security Policy
   */
  analyzeCSP(csp) {
    const findings = [];
    
    if (csp.includes("'unsafe-inline'")) {
      findings.push({
        type: 'critical',
        message: "CSP allows 'unsafe-inline' - vulnerable to XSS"
      });
    }

    if (csp.includes("'unsafe-eval'")) {
      findings.push({
        type: 'critical',
        message: "CSP allows 'unsafe-eval' - vulnerable to code injection"
      });
    }

    if (csp.includes('*')) {
      findings.push({
        type: 'warning',
        message: 'CSP contains wildcard (*) - overly permissive'
      });
    }

    return findings;
  }

  /**
   * Test for XSS vulnerabilities
   */
  async testXSS(url, params) {
    const payloads = [
      '<script>alert(1)</script>',
      '"><script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      'javascript:alert(1)',
      '<svg/onload=alert(1)>',
      '\'-alert(1)-\'',
      '"><svg/onload=alert(1)>',
      '<iframe src="javascript:alert(1)">',
    ];

    const results = [];

    for (const payload of payloads) {
      try {
        const testUrl = new URL(url);
        Object.entries(params).forEach(([key, value]) => {
          testUrl.searchParams.set(key, payload);
        });

        let alertFired = false;
        this.page.once('dialog', async dialog => {
          alertFired = true;
          await dialog.dismiss();
        });

        await this.page.goto(testUrl.toString(), { 
          waitUntil: 'networkidle2',
          timeout: 5000 
        });

        if (alertFired) {
          results.push({
            type: 'critical',
            payload,
            vulnerable: true,
            message: `XSS found with payload: ${payload}`
          });
        }
      } catch (error) {
        // Timeout or navigation error
      }
    }

    return results;
  }

  /**
   * Test for SQL injection patterns
   */
  async testSQLi(url, params) {
    const payloads = [
      "' OR '1'='1",
      "1' OR '1'='1",
      "admin'--",
      "1' UNION SELECT NULL--",
      "' AND 1=0 UNION ALL SELECT 'admin",
      "1' AND '1'='1",
      "1' AND '1'='2"
    ];

    const results = [];

    for (const payload of payloads) {
      try {
        const testUrl = new URL(url);
        Object.entries(params).forEach(([key, value]) => {
          testUrl.searchParams.set(key, payload);
        });

        const response = await this.page.goto(testUrl.toString(), {
          waitUntil: 'networkidle2',
          timeout: 5000
        });

        const content = await this.page.content();
        const text = await response.text();

        // Check for SQL error messages
        const sqlErrors = [
          /SQL syntax/i,
          /mysql_fetch/i,
          /Warning.*mysql/i,
          /valid MySQL result/i,
          /PostgreSQL.*ERROR/i,
          /Driver.*SQL/i,
          /SQLite.*error/i,
          /Microsoft.*Database/i,
          /ODBC.*Drivers/i
        ];

        const errorFound = sqlErrors.some(pattern => 
          pattern.test(content) || pattern.test(text)
        );

        if (errorFound) {
          results.push({
            type: 'critical',
            payload,
            vulnerable: true,
            message: `Possible SQLi with payload: ${payload}`
          });
        }
      } catch (error) {
        // Continue testing
      }
    }

    return results;
  }

  /**
   * Analyze CORS configuration
   */
  async analyzeCORS(response) {
    const headers = response.headers();
    const findings = [];

    const acao = headers['access-control-allow-origin'];
    const acac = headers['access-control-allow-credentials'];

    if (acao === '*') {
      findings.push({
        type: 'warning',
        message: 'CORS allows all origins (*)'
      });

      if (acac === 'true') {
        findings.push({
          type: 'critical',
          message: 'CORS wildcard with credentials - severe misconfiguration!'
        });
      }
    }

    if (acao && acao.includes('null')) {
      findings.push({
        type: 'critical',
        message: 'CORS allows null origin - vulnerable to sandbox bypass'
      });
    }

    return findings;
  }

  /**
   * Extract hidden form fields and tokens
   */
  async extractTokens() {
    const tokens = await this.page.evaluate(() => {
      const results = {
        csrf: [],
        hidden: [],
        meta: []
      };

      // Find CSRF tokens
      document.querySelectorAll('input[name*="csrf"], input[name*="token"]').forEach(input => {
        results.csrf.push({
          name: input.name,
          value: input.value,
          form: input.form ? input.form.action : null
        });
      });

      // Find hidden inputs
      document.querySelectorAll('input[type="hidden"]').forEach(input => {
        results.hidden.push({
          name: input.name,
          value: input.value
        });
      });

      // Find meta tokens
      document.querySelectorAll('meta[name*="csrf"], meta[name*="token"]').forEach(meta => {
        results.meta.push({
          name: meta.getAttribute('name'),
          content: meta.getAttribute('content')
        });
      });

      return results;
    });

    return tokens;
  }

  /**
   * Detect JavaScript frameworks and libraries
   */
  async detectFrameworks() {
    const frameworks = await this.page.evaluate(() => {
      const detected = [];

      // Check for common frameworks
      if (window.React) detected.push({ name: 'React', version: window.React.version || 'unknown' });
      if (window.Vue) detected.push({ name: 'Vue', version: window.Vue.version || 'unknown' });
      if (window.angular) detected.push({ name: 'Angular', version: window.angular.version?.full || 'unknown' });
      if (window.jQuery) detected.push({ name: 'jQuery', version: window.jQuery.fn.jquery || 'unknown' });
      if (window.Ember) detected.push({ name: 'Ember', version: window.Ember.VERSION || 'unknown' });
      if (window.Backbone) detected.push({ name: 'Backbone', version: window.Backbone.VERSION || 'unknown' });

      // Check for common libraries
      if (window.axios) detected.push({ name: 'Axios', version: 'detected' });
      if (window.moment) detected.push({ name: 'Moment.js', version: window.moment.version || 'unknown' });
      if (window._ && window._.VERSION) detected.push({ name: 'Lodash', version: window._.VERSION });
      if (window.d3) detected.push({ name: 'D3.js', version: window.d3.version || 'unknown' });

      return detected;
    });

    return frameworks;
  }

  /**
   * Print security analysis report
   */
  printSecurityReport(analysis) {
    console.log(chalk.cyan.bold('\n🔒 Security Analysis Report\n'));
    
    console.log(chalk.yellow(`Security Score: ${analysis.score}/75`));
    console.log();

    if (Object.keys(analysis.headers).length > 0) {
      console.log(chalk.green('Security Headers Present:'));
      Object.entries(analysis.headers).forEach(([name, value]) => {
        console.log(chalk.gray(`  ${name}: ${value.substring(0, 60)}...`));
      });
      console.log();
    }

    analysis.findings.forEach(finding => {
      const icon = {
        critical: chalk.red('✗'),
        warning: chalk.yellow('⚠'),
        info: chalk.blue('ℹ'),
        good: chalk.green('✓')
      }[finding.type] || '•';

      console.log(`${icon} ${finding.message}`);
    });

    console.log();
  }
}

module.exports = SecurityAnalyzer;
