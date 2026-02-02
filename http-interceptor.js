/**
 * HTTP Interceptor Module
 * Advanced request/response interception and modification
 */

const chalk = require('chalk');

class HTTPInterceptor {
  constructor(page) {
    this.page = page;
    this.rules = [];
    this.requestModifiers = new Map();
    this.responseModifiers = new Map();
    this.blockList = new Set();
    this.mockResponses = new Map();
  }

  /**
   * Add a request modification rule
   */
  addRequestRule(matcher, modifier) {
    const rule = {
      id: Date.now(),
      matcher: typeof matcher === 'string' ? (url) => url.includes(matcher) : matcher,
      modifier,
      type: 'request'
    };
    this.rules.push(rule);
    return rule.id;
  }

  /**
   * Add a response modification rule
   */
  addResponseRule(matcher, modifier) {
    const rule = {
      id: Date.now(),
      matcher: typeof matcher === 'string' ? (url) => url.includes(matcher) : matcher,
      modifier,
      type: 'response'
    };
    this.rules.push(rule);
    return rule.id;
  }

  /**
   * Block requests matching pattern
   */
  blockRequests(pattern) {
    this.blockList.add(pattern);
  }

  /**
   * Mock response for a URL
   */
  mockResponse(urlPattern, response) {
    this.mockResponses.set(urlPattern, response);
  }

  /**
   * Modify request headers
   */
  modifyRequestHeaders(url, headers) {
    this.requestModifiers.set(url, {
      type: 'headers',
      data: headers
    });
  }

  /**
   * Modify request body
   */
  modifyRequestBody(url, body) {
    this.requestModifiers.set(url, {
      type: 'body',
      data: body
    });
  }

  /**
   * Apply interception rules
   */
  async intercept(request) {
    const url = request.url();
    
    // Check blocklist
    for (const pattern of this.blockList) {
      if (url.includes(pattern)) {
        console.log(chalk.red(`✗ Blocked: ${url}`));
        return request.abort();
      }
    }

    // Check mock responses
    for (const [pattern, mockResp] of this.mockResponses.entries()) {
      if (url.includes(pattern)) {
        console.log(chalk.yellow(`↻ Mocked: ${url}`));
        return request.respond({
          status: mockResp.status || 200,
          contentType: mockResp.contentType || 'application/json',
          body: mockResp.body
        });
      }
    }

    // Apply request modification rules
    let overrides = {};
    
    for (const rule of this.rules) {
      if (rule.type === 'request' && rule.matcher(url)) {
        const modifications = rule.modifier(request);
        overrides = { ...overrides, ...modifications };
      }
    }

    // Apply stored modifiers
    if (this.requestModifiers.has(url)) {
      const modifier = this.requestModifiers.get(url);
      if (modifier.type === 'headers') {
        overrides.headers = { ...request.headers(), ...modifier.data };
      } else if (modifier.type === 'body') {
        overrides.postData = modifier.data;
      }
    }

    if (Object.keys(overrides).length > 0) {
      console.log(chalk.blue(`→ Modified: ${request.method()} ${url}`));
      return request.continue(overrides);
    }

    return request.continue();
  }

  /**
   * Clear all rules
   */
  clearRules() {
    this.rules = [];
    this.requestModifiers.clear();
    this.responseModifiers.clear();
    this.blockList.clear();
    this.mockResponses.clear();
  }

  /**
   * Remove specific rule
   */
  removeRule(id) {
    this.rules = this.rules.filter(rule => rule.id !== id);
  }

  /**
   * List all active rules
   */
  listRules() {
    console.log(chalk.cyan.bold('\n📋 Active Interception Rules\n'));
    
    if (this.rules.length === 0 && this.blockList.size === 0 && this.mockResponses.size === 0) {
      console.log(chalk.gray('No rules active.\n'));
      return;
    }

    this.rules.forEach((rule, idx) => {
      console.log(chalk.yellow(`${idx + 1}. ${rule.type} rule (ID: ${rule.id})`));
    });

    if (this.blockList.size > 0) {
      console.log(chalk.red('\nBlocked patterns:'));
      this.blockList.forEach(pattern => {
        console.log(chalk.gray(`  - ${pattern}`));
      });
    }

    if (this.mockResponses.size > 0) {
      console.log(chalk.blue('\nMocked responses:'));
      this.mockResponses.forEach((resp, pattern) => {
        console.log(chalk.gray(`  - ${pattern} → ${resp.status || 200}`));
      });
    }

    console.log();
  }
}

/**
 * Request/Response Logger
 */
class HTTPLogger {
  constructor() {
    this.logs = [];
    this.filters = {
      methods: null,
      status: null,
      contentType: null,
      url: null
    };
  }

  /**
   * Log a request/response pair
   */
  log(request, response) {
    const entry = {
      timestamp: new Date(),
      method: request.method,
      url: request.url,
      requestHeaders: request.headers,
      requestBody: request.body,
      status: response?.status,
      responseHeaders: response?.headers,
      responseBody: response?.body,
      size: response?.size || 0,
      duration: response?.duration || 0
    };

    this.logs.push(entry);
    return entry;
  }

  /**
   * Filter logs
   */
  filter(criteria) {
    return this.logs.filter(log => {
      if (criteria.method && log.method !== criteria.method) return false;
      if (criteria.status && log.status !== criteria.status) return false;
      if (criteria.url && !log.url.includes(criteria.url)) return false;
      return true;
    });
  }

  /**
   * Export logs as JSON
   */
  export() {
    return JSON.stringify(this.logs, null, 2);
  }

  /**
   * Clear logs
   */
  clear() {
    this.logs = [];
  }

  /**
   * Get statistics
   */
  getStats() {
    const stats = {
      total: this.logs.length,
      methods: {},
      statuses: {},
      totalSize: 0,
      avgDuration: 0
    };

    this.logs.forEach(log => {
      stats.methods[log.method] = (stats.methods[log.method] || 0) + 1;
      stats.statuses[log.status] = (stats.statuses[log.status] || 0) + 1;
      stats.totalSize += log.size;
      stats.avgDuration += log.duration;
    });

    if (this.logs.length > 0) {
      stats.avgDuration /= this.logs.length;
    }

    return stats;
  }

  /**
   * Print statistics
   */
  printStats() {
    const stats = this.getStats();
    
    console.log(chalk.cyan.bold('\n📊 HTTP Traffic Statistics\n'));
    console.log(chalk.yellow(`Total Requests: ${stats.total}`));
    console.log(chalk.yellow(`Total Size: ${(stats.totalSize / 1024).toFixed(2)} KB`));
    console.log(chalk.yellow(`Avg Duration: ${stats.avgDuration.toFixed(2)} ms\n`));

    console.log(chalk.white('Methods:'));
    Object.entries(stats.methods).forEach(([method, count]) => {
      console.log(chalk.gray(`  ${method}: ${count}`));
    });

    console.log(chalk.white('\nStatus Codes:'));
    Object.entries(stats.statuses).forEach(([status, count]) => {
      const color = status >= 200 && status < 300 ? chalk.green :
                   status >= 400 ? chalk.red : chalk.yellow;
      console.log(color(`  ${status}: ${count}`));
    });

    console.log();
  }
}

/**
 * Request Builder
 * Build and send custom HTTP requests
 */
class RequestBuilder {
  constructor(page) {
    this.page = page;
  }

  /**
   * Build a custom request
   */
  async send(options) {
    const {
      method = 'GET',
      url,
      headers = {},
      body = null,
      followRedirects = true
    } = options;

    try {
      const response = await this.page.evaluate(async (opts) => {
        const fetchOptions = {
          method: opts.method,
          headers: opts.headers,
          redirect: opts.followRedirects ? 'follow' : 'manual'
        };

        if (opts.body) {
          fetchOptions.body = opts.body;
        }

        const resp = await fetch(opts.url, fetchOptions);
        const text = await resp.text();

        return {
          status: resp.status,
          statusText: resp.statusText,
          headers: Object.fromEntries(resp.headers.entries()),
          body: text,
          redirected: resp.redirected,
          url: resp.url
        };
      }, { method, url, headers, body, followRedirects });

      return response;
    } catch (error) {
      console.error(chalk.red(`Request failed: ${error.message}`));
      throw error;
    }
  }

  /**
   * Send a POST request with JSON body
   */
  async post(url, data, headers = {}) {
    return this.send({
      method: 'POST',
      url,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      },
      body: JSON.stringify(data)
    });
  }

  /**
   * Send a PUT request
   */
  async put(url, data, headers = {}) {
    return this.send({
      method: 'PUT',
      url,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      },
      body: JSON.stringify(data)
    });
  }

  /**
   * Send a PATCH request
   */
  async patch(url, data, headers = {}) {
    return this.send({
      method: 'PATCH',
      url,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      },
      body: JSON.stringify(data)
    });
  }

  /**
   * Send a DELETE request
   */
  async delete(url, headers = {}) {
    return this.send({
      method: 'DELETE',
      url,
      headers
    });
  }
}

module.exports = {
  HTTPInterceptor,
  HTTPLogger,
  RequestBuilder
};
