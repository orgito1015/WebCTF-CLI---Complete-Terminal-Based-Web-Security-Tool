#!/usr/bin/env node

/**
 * Example CTF Scenarios
 * Demonstrates common usage patterns for web CTF challenges
 */

const WebCTFCLI = require('./webctf-cli');
const chalk = require('chalk');

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Scenario 1: Finding Hidden API Endpoints
 */
async function scenario1_apiDiscovery() {
  console.log(chalk.cyan.bold('\n=== Scenario 1: API Endpoint Discovery ===\n'));
  
  const cli = new WebCTFCLI();
  await cli.init();

  try {
    // Navigate to target
    await cli.navigate('https://jsonplaceholder.typicode.com');
    await sleep(2000);

    // Show all requests
    console.log(chalk.yellow('Analyzing network traffic...'));
    await cli.showRequests('', 20);

    // Check response headers
    await cli.showHeaders('response', 'posts');

    // Search for API patterns in source
    await cli.searchHTML('api|endpoint|/v[0-9]');

  } finally {
    await cli.cleanup();
  }
}

/**
 * Scenario 2: Cookie-Based Authentication Bypass
 */
async function scenario2_cookieManipulation() {
  console.log(chalk.cyan.bold('\n=== Scenario 2: Cookie Manipulation ===\n'));
  
  const cli = new WebCTFCLI();
  await cli.init();

  try {
    // Navigate to a site with cookies
    await cli.navigate('https://httpbin.org/cookies/set?session=user123');
    await sleep(2000);

    // Show cookies
    console.log(chalk.yellow('Current cookies:'));
    await cli.showCookies();

    // Modify cookie
    console.log(chalk.yellow('\nSetting admin cookie...'));
    await cli.setCookie('admin', 'true', { path: '/' });
    await cli.setCookie('role', 'administrator', { path: '/' });

    // Show updated cookies
    await cli.showCookies();

    // Navigate to protected area
    await cli.navigate('https://httpbin.org/cookies');
    
    // Check if admin cookie is sent
    await cli.showHeaders('request');

  } finally {
    await cli.cleanup();
  }
}

/**
 * Scenario 3: JavaScript Variable Extraction
 */
async function scenario3_jsExtraction() {
  console.log(chalk.cyan.bold('\n=== Scenario 3: JavaScript Variable Extraction ===\n'));
  
  const cli = new WebCTFCLI();
  await cli.init();

  try {
    // Navigate to target
    await cli.navigate('https://example.com');
    await sleep(2000);

    // List all global variables
    console.log(chalk.yellow('Enumerating global variables...'));
    const globals = await cli.executeJS(`
      Object.keys(window).filter(key => 
        !key.startsWith('webkit') && 
        !key.startsWith('chrome') &&
        typeof window[key] !== 'function'
      )
    `);

    // Extract document properties
    console.log(chalk.yellow('\nDocument cookies:'));
    await cli.executeJS('document.cookie');

    // Check for common secret variables
    console.log(chalk.yellow('\nChecking for common secret variables...'));
    const secretVars = ['API_KEY', 'SECRET', 'TOKEN', 'CONFIG', 'FLAG'];
    for (const varName of secretVars) {
      try {
        await cli.executeJS(`window.${varName} || window.${varName.toLowerCase()}`);
      } catch (e) {
        // Variable doesn't exist
      }
    }

  } finally {
    await cli.cleanup();
  }
}

/**
 * Scenario 4: Form Analysis and CSRF Token Extraction
 */
async function scenario4_formAnalysis() {
  console.log(chalk.cyan.bold('\n=== Scenario 4: Form Analysis & CSRF Tokens ===\n'));
  
  const cli = new WebCTFCLI();
  await cli.init();

  try {
    // Navigate to page with forms
    await cli.navigate('https://httpbin.org/forms/post');
    await sleep(2000);

    // Extract all forms
    console.log(chalk.yellow('Extracting forms...'));
    await cli.extractDOM('form');

    // Find hidden inputs
    console.log(chalk.yellow('\nFinding hidden fields...'));
    const hiddenFields = await cli.executeJS(`
      Array.from(document.querySelectorAll('input[type="hidden"]')).map(inp => ({
        name: inp.name,
        value: inp.value
      }))
    `);

    // Find CSRF tokens
    console.log(chalk.yellow('\nSearching for CSRF tokens...'));
    await cli.executeJS(`
      Array.from(document.querySelectorAll('[name*="csrf"], [name*="token"]')).map(el => ({
        tag: el.tagName,
        name: el.name || el.getAttribute('name'),
        value: el.value || el.getAttribute('content')
      }))
    `);

  } finally {
    await cli.cleanup();
  }
}

/**
 * Scenario 5: Source Code Secret Search
 */
async function scenario5_secretSearch() {
  console.log(chalk.cyan.bold('\n=== Scenario 5: Source Code Secret Search ===\n'));
  
  const cli = new WebCTFCLI();
  await cli.init();

  try {
    // Navigate to target
    await cli.navigate('https://example.com');
    await sleep(2000);

    // Search for common patterns
    console.log(chalk.yellow('Searching for flags...'));
    await cli.searchHTML('flag\\{[^}]+\\}');

    console.log(chalk.yellow('Searching for API keys...'));
    await cli.searchHTML('api[_-]?key|apikey|api_secret');

    console.log(chalk.yellow('Searching for passwords...'));
    await cli.searchHTML('password|passwd|pwd');

    console.log(chalk.yellow('Searching for TODOs...'));
    await cli.searchHTML('TODO|FIXME|HACK|XXX');

    // Check comments
    console.log(chalk.yellow('Searching for HTML comments...'));
    await cli.searchHTML('<!--[\\s\\S]*?-->');

  } finally {
    await cli.cleanup();
  }
}

/**
 * Scenario 6: Storage Enumeration
 */
async function scenario6_storageEnum() {
  console.log(chalk.cyan.bold('\n=== Scenario 6: Storage Enumeration ===\n'));
  
  const cli = new WebCTFCLI();
  await cli.init();

  try {
    // Navigate and set some test storage
    await cli.navigate('https://example.com');
    await sleep(2000);

    // Set test data
    await cli.executeJS(`
      localStorage.setItem('test_key', 'test_value');
      localStorage.setItem('user_token', 'abc123def456');
      sessionStorage.setItem('session_id', 'xyz789');
    `);

    // Show storage
    console.log(chalk.yellow('Current storage:'));
    await cli.showStorage();

    // Enumerate all storage keys
    console.log(chalk.yellow('\nAll localStorage keys:'));
    await cli.executeJS('Object.keys(localStorage)');

    // Look for JWT tokens
    console.log(chalk.yellow('\nSearching for JWT tokens in storage...'));
    await cli.executeJS(`
      Object.entries(localStorage).filter(([key, value]) => 
        value.match(/^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]*$/)
      )
    `);

  } finally {
    await cli.cleanup();
  }
}

/**
 * Scenario 7: Console Log Analysis
 */
async function scenario7_consoleAnalysis() {
  console.log(chalk.cyan.bold('\n=== Scenario 7: Console Log Analysis ===\n'));
  
  const cli = new WebCTFCLI();
  await cli.init();

  try {
    // Navigate to page
    await cli.navigate('https://example.com');
    await sleep(2000);

    // Trigger some console logs
    await cli.executeJS(`
      console.log('Application started');
      console.warn('This is a warning');
      console.error('This is an error');
      console.log('Debug info:', {secret: 'value123'});
    `);

    await sleep(500);

    // Show all console logs
    console.log(chalk.yellow('Console logs:'));
    await cli.showConsole('', 50);

    // Filter for errors
    console.log(chalk.yellow('Error logs only:'));
    await cli.showConsole('error', 10);

  } finally {
    await cli.cleanup();
  }
}

/**
 * Scenario 8: Header Injection Testing
 */
async function scenario8_headerInjection() {
  console.log(chalk.cyan.bold('\n=== Scenario 8: Custom Header Injection ===\n'));
  
  const cli = new WebCTFCLI();
  await cli.init();

  try {
    // Set custom headers
    console.log(chalk.yellow('Setting custom headers...'));
    await cli.setHeader('X-Forwarded-For', '127.0.0.1');
    await cli.setHeader('X-Original-URL', '/admin');
    await cli.setHeader('X-Custom-Header', 'test-value');

    // Navigate with custom headers
    await cli.navigate('https://httpbin.org/headers');
    await sleep(2000);

    // Check if headers were sent
    console.log(chalk.yellow('Checking sent headers...'));
    await cli.showHeaders('request');

    // View response
    const response = await cli.executeJS('document.body.textContent');

  } finally {
    await cli.cleanup();
  }
}

// Main menu
async function main() {
  console.log(chalk.cyan.bold('\n🔒 WebCTF CLI - Example Scenarios\n'));
  console.log('1. API Endpoint Discovery');
  console.log('2. Cookie Manipulation');
  console.log('3. JavaScript Variable Extraction');
  console.log('4. Form Analysis & CSRF Tokens');
  console.log('5. Source Code Secret Search');
  console.log('6. Storage Enumeration');
  console.log('7. Console Log Analysis');
  console.log('8. Custom Header Injection');
  console.log('0. Run all scenarios\n');

  const readline = require('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  rl.question('Select scenario (0-8): ', async (answer) => {
    rl.close();

    const scenarios = [
      scenario1_apiDiscovery,
      scenario2_cookieManipulation,
      scenario3_jsExtraction,
      scenario4_formAnalysis,
      scenario5_secretSearch,
      scenario6_storageEnum,
      scenario7_consoleAnalysis,
      scenario8_headerInjection
    ];

    const choice = parseInt(answer);

    if (choice === 0) {
      // Run all scenarios
      for (let i = 0; i < scenarios.length; i++) {
        try {
          await scenarios[i]();
          await sleep(1000);
        } catch (error) {
          console.error(chalk.red(`Scenario ${i + 1} failed: ${error.message}`));
        }
      }
    } else if (choice >= 1 && choice <= 8) {
      try {
        await scenarios[choice - 1]();
      } catch (error) {
        console.error(chalk.red(`Error: ${error.message}`));
      }
    } else {
      console.log(chalk.red('Invalid choice'));
    }
  });
}

if (require.main === module) {
  main().catch(console.error);
}

module.exports = {
  scenario1_apiDiscovery,
  scenario2_cookieManipulation,
  scenario3_jsExtraction,
  scenario4_formAnalysis,
  scenario5_secretSearch,
  scenario6_storageEnum,
  scenario7_consoleAnalysis,
  scenario8_headerInjection
};
