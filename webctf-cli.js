#!/usr/bin/env node

/**
 * WebCTF CLI - Terminal-based Web Security Tool
 * A comprehensive tool for interacting with web applications from the terminal
 * Features: Network inspection, DOM analysis, JS debugging, cookie management, etc.
 */

const puppeteer = require('puppeteer');
const readline = require('readline');
const chalk = require('chalk');
const Table = require('cli-table3');
const fs = require('fs').promises;
const path = require('path');

class WebCTFCLI {
  constructor() {
    this.browser = null;
    this.page = null;
    this.context = null;
    this.requests = [];
    this.responses = [];
    this.cookies = [];
    this.localStorage = {};
    this.sessionStorage = {};
    this.consoleLogs = [];
    this.currentUrl = '';
    this.history = [];
    this.interceptEnabled = false;
    this.recordingHAR = false;
    this.harEntries = [];
  }

  async init() {
    console.log(chalk.cyan.bold('\n🔒 WebCTF CLI - Web Security Terminal Tool\n'));
    
    this.browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process'
      ]
    });

    this.context = await this.browser.createBrowserContext();
    this.page = await this.context.newPage();

    // Set up network interception
    await this.page.setRequestInterception(true);
    this.setupNetworkMonitoring();
    this.setupConsoleMonitoring();
    
    console.log(chalk.green('✓ Browser context initialized'));
    console.log(chalk.gray('Type "help" for available commands\n'));
  }

  setupNetworkMonitoring() {
    this.page.on('request', (request) => {
      const req = {
        timestamp: new Date().toISOString(),
        method: request.method(),
        url: request.url(),
        headers: request.headers(),
        postData: request.postData(),
        resourceType: request.resourceType()
      };
      this.requests.push(req);

      if (this.recordingHAR) {
        this.harEntries.push({
          startedDateTime: req.timestamp,
          request: {
            method: req.method,
            url: req.url,
            headers: Object.entries(req.headers).map(([name, value]) => ({ name, value })),
            postData: req.postData ? { text: req.postData } : undefined
          }
        });
      }

      if (this.interceptEnabled) {
        console.log(chalk.yellow(`\n→ ${req.method} ${req.url}`));
      }

      request.continue();
    });

    this.page.on('response', async (response) => {
      const resp = {
        timestamp: new Date().toISOString(),
        status: response.status(),
        statusText: response.statusText(),
        url: response.url(),
        headers: response.headers(),
        method: response.request().method()
      };

      try {
        const contentType = resp.headers['content-type'] || '';
        if (contentType.includes('application/json') || 
            contentType.includes('text/html') ||
            contentType.includes('text/plain')) {
          resp.body = await response.text();
        }
      } catch (e) {
        // Binary content or error
      }

      this.responses.push(resp);

      if (this.interceptEnabled) {
        console.log(chalk.green(`← ${resp.status} ${resp.url}`));
      }
    });
  }

  setupConsoleMonitoring() {
    this.page.on('console', (msg) => {
      const log = {
        timestamp: new Date().toISOString(),
        type: msg.type(),
        text: msg.text(),
        location: msg.location()
      };
      this.consoleLogs.push(log);
    });

    this.page.on('pageerror', (error) => {
      this.consoleLogs.push({
        timestamp: new Date().toISOString(),
        type: 'error',
        text: error.message,
        stack: error.stack
      });
    });
  }

  async navigate(url) {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }

    try {
      console.log(chalk.blue(`\n⟳ Navigating to ${url}...`));
      
      const response = await this.page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: 30000
      });

      this.currentUrl = url;
      this.history.push(url);

      // Capture storage
      this.localStorage = await this.page.evaluate(() => {
        return Object.assign({}, localStorage);
      });

      this.sessionStorage = await this.page.evaluate(() => {
        return Object.assign({}, sessionStorage);
      });

      this.cookies = await this.page.cookies();

      const title = await this.page.title();
      console.log(chalk.green(`✓ Loaded: ${title}`));
      console.log(chalk.gray(`  Status: ${response.status()}`));
      console.log(chalk.gray(`  URL: ${this.currentUrl}\n`));

      return response;
    } catch (error) {
      console.log(chalk.red(`✗ Navigation failed: ${error.message}\n`));
      throw error;
    }
  }

  async showHeaders(type = 'response', filter = '') {
    const data = type === 'request' ? this.requests : this.responses;
    
    if (data.length === 0) {
      console.log(chalk.yellow('No data captured yet.\n'));
      return;
    }

    const latest = filter ? 
      data.filter(item => item.url.includes(filter)).slice(-1)[0] :
      data.slice(-1)[0];

    if (!latest) {
      console.log(chalk.yellow(`No ${type}s matching "${filter}"\n`));
      return;
    }

    console.log(chalk.cyan.bold(`\n${type.toUpperCase()} Headers: ${latest.url}\n`));
    
    const table = new Table({
      head: [chalk.white('Header'), chalk.white('Value')],
      colWidths: [30, 70],
      wordWrap: true
    });

    Object.entries(latest.headers).forEach(([key, value]) => {
      table.push([chalk.yellow(key), value]);
    });

    console.log(table.toString());
    
    if (type === 'response') {
      console.log(chalk.gray(`\nStatus: ${latest.status} ${latest.statusText}`));
    }
    
    console.log();
  }

  async showRequests(filter = '', limit = 10) {
    let reqs = this.requests;
    
    if (filter) {
      reqs = reqs.filter(r => 
        r.url.includes(filter) || 
        r.method.toLowerCase() === filter.toLowerCase()
      );
    }

    reqs = reqs.slice(-limit);

    if (reqs.length === 0) {
      console.log(chalk.yellow('No requests found.\n'));
      return;
    }

    const table = new Table({
      head: ['#', 'Method', 'Status', 'Type', 'URL'].map(h => chalk.white(h)),
      colWidths: [5, 8, 8, 12, 60]
    });

    reqs.forEach((req, idx) => {
      const resp = this.responses.find(r => r.url === req.url);
      const statusColor = resp && resp.status >= 200 && resp.status < 300 ? chalk.green : 
                         resp && resp.status >= 400 ? chalk.red : chalk.yellow;
      
      table.push([
        idx + 1,
        this.colorMethod(req.method),
        resp ? statusColor(resp.status) : chalk.gray('?'),
        chalk.gray(req.resourceType),
        this.truncate(req.url, 55)
      ]);
    });

    console.log(chalk.cyan.bold(`\n📡 Network Requests (${reqs.length})\n`));
    console.log(table.toString());
    console.log();
  }

  async showCookies() {
    if (this.cookies.length === 0) {
      console.log(chalk.yellow('No cookies found.\n'));
      return;
    }

    const table = new Table({
      head: ['Name', 'Value', 'Domain', 'Path', 'Secure', 'HttpOnly'].map(h => chalk.white(h)),
      colWidths: [20, 30, 25, 10, 8, 10]
    });

    this.cookies.forEach(cookie => {
      table.push([
        chalk.yellow(cookie.name),
        this.truncate(cookie.value, 25),
        chalk.gray(cookie.domain),
        chalk.gray(cookie.path),
        cookie.secure ? chalk.green('✓') : chalk.red('✗'),
        cookie.httpOnly ? chalk.green('✓') : chalk.red('✗')
      ]);
    });

    console.log(chalk.cyan.bold('\n🍪 Cookies\n'));
    console.log(table.toString());
    console.log();
  }

  async showStorage() {
    console.log(chalk.cyan.bold('\n💾 Storage\n'));
    
    // LocalStorage
    if (Object.keys(this.localStorage).length > 0) {
      console.log(chalk.yellow('LocalStorage:'));
      const table = new Table({
        head: ['Key', 'Value'].map(h => chalk.white(h)),
        colWidths: [30, 70]
      });
      
      Object.entries(this.localStorage).forEach(([key, value]) => {
        table.push([chalk.cyan(key), this.truncate(value, 65)]);
      });
      console.log(table.toString());
      console.log();
    }

    // SessionStorage
    if (Object.keys(this.sessionStorage).length > 0) {
      console.log(chalk.yellow('SessionStorage:'));
      const table = new Table({
        head: ['Key', 'Value'].map(h => chalk.white(h)),
        colWidths: [30, 70]
      });
      
      Object.entries(this.sessionStorage).forEach(([key, value]) => {
        table.push([chalk.cyan(key), this.truncate(value, 65)]);
      });
      console.log(table.toString());
      console.log();
    }

    if (Object.keys(this.localStorage).length === 0 && 
        Object.keys(this.sessionStorage).length === 0) {
      console.log(chalk.gray('No storage data found.\n'));
    }
  }

  async showConsole(filter = '', limit = 20) {
    let logs = this.consoleLogs;
    
    if (filter) {
      logs = logs.filter(log => 
        log.type === filter || 
        log.text.toLowerCase().includes(filter.toLowerCase())
      );
    }

    logs = logs.slice(-limit);

    if (logs.length === 0) {
      console.log(chalk.yellow('No console logs found.\n'));
      return;
    }

    console.log(chalk.cyan.bold(`\n📋 Console Logs (${logs.length})\n`));
    
    logs.forEach(log => {
      const typeColor = {
        log: chalk.white,
        info: chalk.blue,
        warn: chalk.yellow,
        error: chalk.red,
        debug: chalk.gray
      }[log.type] || chalk.white;

      console.log(typeColor(`[${log.type.toUpperCase()}] ${log.text}`));
      if (log.stack) {
        console.log(chalk.gray(log.stack));
      }
    });
    console.log();
  }

  async executeJS(code) {
    try {
      console.log(chalk.blue(`\n⚡ Executing JavaScript...\n`));
      const result = await this.page.evaluate(code);
      console.log(chalk.green('Result:'));
      console.log(JSON.stringify(result, null, 2));
      console.log();
      return result;
    } catch (error) {
      console.log(chalk.red(`Error: ${error.message}\n`));
      throw error;
    }
  }

  async extractDOM(selector = 'body') {
    try {
      const elements = await this.page.evaluate((sel) => {
        const els = document.querySelectorAll(sel);
        return Array.from(els).map(el => ({
          tag: el.tagName.toLowerCase(),
          id: el.id,
          classes: Array.from(el.classList),
          text: el.textContent.trim().substring(0, 100),
          attributes: Array.from(el.attributes).reduce((acc, attr) => {
            acc[attr.name] = attr.value;
            return acc;
          }, {})
        }));
      }, selector);

      console.log(chalk.cyan.bold(`\n🌳 DOM Elements: ${selector}\n`));
      console.log(JSON.stringify(elements, null, 2));
      console.log();
      
      return elements;
    } catch (error) {
      console.log(chalk.red(`Error: ${error.message}\n`));
      throw error;
    }
  }

  async screenshot(filename = 'screenshot.png') {
    try {
      const filepath = path.join('/mnt/user-data/outputs', filename);
      await this.page.screenshot({ path: filepath, fullPage: true });
      console.log(chalk.green(`✓ Screenshot saved: ${filename}\n`));
      return filepath;
    } catch (error) {
      console.log(chalk.red(`Error: ${error.message}\n`));
      throw error;
    }
  }

  async exportHAR(filename = 'traffic.har') {
    const har = {
      log: {
        version: '1.2',
        creator: { name: 'WebCTF CLI', version: '1.0' },
        entries: this.harEntries
      }
    };

    const filepath = path.join('/mnt/user-data/outputs', filename);
    await fs.writeFile(filepath, JSON.stringify(har, null, 2));
    console.log(chalk.green(`✓ HAR file exported: ${filename}\n`));
    return filepath;
  }

  async setCookie(name, value, options = {}) {
    const cookie = {
      name,
      value,
      domain: options.domain || new URL(this.currentUrl).hostname,
      path: options.path || '/',
      secure: options.secure || false,
      httpOnly: options.httpOnly || false,
      sameSite: options.sameSite || 'Lax'
    };

    await this.page.setCookie(cookie);
    this.cookies = await this.page.cookies();
    console.log(chalk.green(`✓ Cookie set: ${name}\n`));
  }

  async setHeader(name, value) {
    await this.page.setExtraHTTPHeaders({ [name]: value });
    console.log(chalk.green(`✓ Header set: ${name}\n`));
  }

  async submitForm(selector, data) {
    try {
      await this.page.evaluate((sel, formData) => {
        const form = document.querySelector(sel);
        if (!form) throw new Error('Form not found');

        Object.entries(formData).forEach(([name, value]) => {
          const input = form.querySelector(`[name="${name}"]`);
          if (input) input.value = value;
        });

        form.submit();
      }, selector, data);

      await this.page.waitForNavigation({ waitUntil: 'networkidle2' });
      console.log(chalk.green('✓ Form submitted\n'));
    } catch (error) {
      console.log(chalk.red(`Error: ${error.message}\n`));
      throw error;
    }
  }

  async searchHTML(pattern) {
    try {
      const html = await this.page.content();
      const regex = new RegExp(pattern, 'gi');
      const matches = [...html.matchAll(regex)];

      console.log(chalk.cyan.bold(`\n🔍 Search Results: "${pattern}"\n`));
      
      if (matches.length === 0) {
        console.log(chalk.yellow('No matches found.\n'));
        return [];
      }

      matches.slice(0, 20).forEach((match, idx) => {
        const context = html.substring(
          Math.max(0, match.index - 50),
          Math.min(html.length, match.index + match[0].length + 50)
        );
        console.log(chalk.gray(`${idx + 1}. ...${context}...`));
      });

      console.log(chalk.green(`\nTotal matches: ${matches.length}\n`));
      return matches;
    } catch (error) {
      console.log(chalk.red(`Error: ${error.message}\n`));
      throw error;
    }
  }

  colorMethod(method) {
    const colors = {
      GET: chalk.blue,
      POST: chalk.green,
      PUT: chalk.yellow,
      DELETE: chalk.red,
      PATCH: chalk.magenta
    };
    return (colors[method] || chalk.white)(method);
  }

  truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len - 3) + '...' : str;
  }

  async showHelp() {
    console.log(chalk.cyan.bold('\n📚 WebCTF CLI Commands\n'));
    
    const commands = [
      ['Navigation', ''],
      ['  go <url>', 'Navigate to URL'],
      ['  reload', 'Reload current page'],
      ['  back', 'Go back in history'],
      ['', ''],
      ['Network', ''],
      ['  requests [filter] [limit]', 'Show network requests'],
      ['  headers [req|res] [filter]', 'Show request/response headers'],
      ['  intercept [on|off]', 'Toggle request interception logging'],
      ['  har [filename]', 'Export traffic as HAR file'],
      ['', ''],
      ['DOM & JavaScript', ''],
      ['  dom [selector]', 'Extract DOM elements'],
      ['  js <code>', 'Execute JavaScript'],
      ['  search <pattern>', 'Search HTML source'],
      ['  console [filter] [limit]', 'Show console logs'],
      ['', ''],
      ['Cookies & Storage', ''],
      ['  cookies', 'Show cookies'],
      ['  setcookie <name> <value>', 'Set a cookie'],
      ['  storage', 'Show localStorage/sessionStorage'],
      ['  setheader <name> <value>', 'Set custom header'],
      ['', ''],
      ['Tools', ''],
      ['  screenshot [filename]', 'Take screenshot'],
      ['  form <selector> <data>', 'Submit form with data'],
      ['  proxy [url]', 'Set proxy server'],
      ['', ''],
      ['Utility', ''],
      ['  clear', 'Clear network/console logs'],
      ['  info', 'Show current page info'],
      ['  help', 'Show this help'],
      ['  exit', 'Exit the tool']
    ];

    const table = new Table({
      colWidths: [35, 50],
      chars: { 'mid': '', 'left-mid': '', 'mid-mid': '', 'right-mid': '' }
    });

    commands.forEach(([cmd, desc]) => {
      if (desc) {
        table.push([chalk.yellow(cmd), chalk.gray(desc)]);
      } else if (cmd) {
        table.push([chalk.white.bold(cmd), '']);
      } else {
        table.push(['', '']);
      }
    });

    console.log(table.toString());
    console.log();
  }

  async showInfo() {
    console.log(chalk.cyan.bold('\n📄 Current Page Info\n'));
    
    const title = await this.page.title();
    const url = this.page.url();
    
    console.log(chalk.yellow('Title: ') + title);
    console.log(chalk.yellow('URL: ') + url);
    console.log(chalk.yellow('Requests: ') + this.requests.length);
    console.log(chalk.yellow('Responses: ') + this.responses.length);
    console.log(chalk.yellow('Cookies: ') + this.cookies.length);
    console.log(chalk.yellow('Console Logs: ') + this.consoleLogs.length);
    console.log();
  }

  async clear() {
    this.requests = [];
    this.responses = [];
    this.consoleLogs = [];
    this.harEntries = [];
    console.log(chalk.green('✓ Logs cleared\n'));
  }

  async cleanup() {
    if (this.browser) {
      await this.browser.close();
    }
  }
}

async function main() {
  const cli = new WebCTFCLI();
  await cli.init();

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: chalk.cyan('webctf> ')
  });

  rl.prompt();

  rl.on('line', async (line) => {
    const input = line.trim();
    
    if (!input) {
      rl.prompt();
      return;
    }

    const [cmd, ...args] = input.split(/\s+/);

    try {
      switch (cmd.toLowerCase()) {
        case 'go':
        case 'navigate':
          if (args.length === 0) {
            console.log(chalk.red('Usage: go <url>\n'));
          } else {
            await cli.navigate(args[0]);
          }
          break;

        case 'reload':
          await cli.page.reload({ waitUntil: 'networkidle2' });
          console.log(chalk.green('✓ Page reloaded\n'));
          break;

        case 'back':
          await cli.page.goBack({ waitUntil: 'networkidle2' });
          console.log(chalk.green('✓ Navigated back\n'));
          break;

        case 'requests':
        case 'req':
          await cli.showRequests(args[0] || '', parseInt(args[1]) || 10);
          break;

        case 'headers':
        case 'head':
          await cli.showHeaders(args[0] || 'response', args[1] || '');
          break;

        case 'cookies':
        case 'cookie':
          await cli.showCookies();
          break;

        case 'setcookie':
          if (args.length < 2) {
            console.log(chalk.red('Usage: setcookie <name> <value>\n'));
          } else {
            await cli.setCookie(args[0], args.slice(1).join(' '));
          }
          break;

        case 'storage':
          await cli.storage();
          break;

        case 'console':
        case 'logs':
          await cli.showConsole(args[0] || '', parseInt(args[1]) || 20);
          break;

        case 'js':
        case 'exec':
          if (args.length === 0) {
            console.log(chalk.red('Usage: js <code>\n'));
          } else {
            await cli.executeJS(args.join(' '));
          }
          break;

        case 'dom':
          await cli.extractDOM(args[0] || 'body');
          break;

        case 'screenshot':
        case 'snap':
          await cli.screenshot(args[0] || 'screenshot.png');
          break;

        case 'search':
        case 'grep':
          if (args.length === 0) {
            console.log(chalk.red('Usage: search <pattern>\n'));
          } else {
            await cli.searchHTML(args.join(' '));
          }
          break;

        case 'intercept':
          if (args[0] === 'on') {
            cli.interceptEnabled = true;
            console.log(chalk.green('✓ Interception logging enabled\n'));
          } else if (args[0] === 'off') {
            cli.interceptEnabled = false;
            console.log(chalk.green('✓ Interception logging disabled\n'));
          } else {
            cli.interceptEnabled = !cli.interceptEnabled;
            console.log(chalk.green(`✓ Interception ${cli.interceptEnabled ? 'enabled' : 'disabled'}\n`));
          }
          break;

        case 'har':
          cli.recordingHAR = true;
          await cli.exportHAR(args[0] || 'traffic.har');
          break;

        case 'setheader':
          if (args.length < 2) {
            console.log(chalk.red('Usage: setheader <name> <value>\n'));
          } else {
            await cli.setHeader(args[0], args.slice(1).join(' '));
          }
          break;

        case 'clear':
          await cli.clear();
          break;

        case 'info':
          await cli.showInfo();
          break;

        case 'help':
        case '?':
          await cli.showHelp();
          break;

        case 'exit':
        case 'quit':
          console.log(chalk.cyan('\n👋 Goodbye!\n'));
          await cli.cleanup();
          process.exit(0);
          break;

        default:
          console.log(chalk.red(`Unknown command: ${cmd}`));
          console.log(chalk.gray('Type "help" for available commands\n'));
      }
    } catch (error) {
      console.log(chalk.red(`Error: ${error.message}\n`));
    }

    rl.prompt();
  });

  rl.on('close', async () => {
    await cli.cleanup();
    process.exit(0);
  });

  // Handle Ctrl+C
  process.on('SIGINT', async () => {
    console.log(chalk.cyan('\n\n👋 Goodbye!\n'));
    await cli.cleanup();
    process.exit(0);
  });
}

if (require.main === module) {
  main().catch(console.error);
}

module.exports = WebCTFCLI;
