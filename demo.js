#!/usr/bin/env node

/**
 * Interactive Demo - WebCTF CLI
 * Demonstrates all major features with explanations
 */

const chalk = require('chalk');
const readline = require('readline');

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function printHeader(title) {
  console.log('\n' + '='.repeat(60));
  console.log(chalk.cyan.bold(title.toUpperCase().padStart(30 + title.length / 2)));
  console.log('='.repeat(60) + '\n');
}

function printStep(step, description) {
  console.log(chalk.yellow(`\n[${step}] ${description}`));
}

async function waitForEnter(message = 'Press Enter to continue...') {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise(resolve => {
    rl.question(chalk.gray(`\n${message}\n`), () => {
      rl.close();
      resolve();
    });
  });
}

async function demo() {
  console.clear();
  
  console.log(chalk.cyan.bold(`
╦ ╦┌─┐┌┐ ┌─┐╔╦╗╔═╗  ╔═╗╦  ╦
║║║├┤ ├┴┐│   ║ ╠╣   ║  ║  ║
╚╩╝└─┘└─┘└─┘ ╩ ╚    ╚═╝╩═╝╩
  `));
  
  console.log(chalk.white.bold('Terminal-Based Web Security Tool'));
  console.log(chalk.gray('Interactive Feature Demonstration\n'));
  
  await waitForEnter('Press Enter to start the demo...');

  // Feature 1: Overview
  printHeader('Feature Overview');
  
  console.log(chalk.white('WebCTF CLI provides comprehensive tools for web security testing:\n'));
  
  const features = [
    '🌐 Network Traffic Analysis',
    '🔒 Security Header Inspection',
    '🍪 Cookie & Session Management',
    '💾 Storage Analysis (localStorage/sessionStorage)',
    '🎨 DOM Inspection & Manipulation',
    '⚡ JavaScript Execution',
    '📋 Console Log Monitoring',
    '🔍 Source Code Search',
    '📸 Screenshot Capture',
    '📦 HAR Export',
    '🛠️ Custom Request Building'
  ];

  features.forEach(feature => {
    console.log(chalk.green('  ✓ ') + chalk.white(feature));
  });

  await waitForEnter();

  // Feature 2: Basic Usage
  printHeader('Basic Usage');
  
  printStep('1', 'Starting the tool');
  console.log(chalk.gray('Command: ') + chalk.white('node webctf-cli.js'));
  console.log(chalk.gray('\nThis launches an interactive terminal session where you can execute commands.'));
  
  await waitForEnter();

  printStep('2', 'Navigating to a website');
  console.log(chalk.gray('Command: ') + chalk.white('go https://example.com'));
  console.log(chalk.gray('\nNavigates to the specified URL and captures all network traffic.'));
  console.log(chalk.gray('Also captures: cookies, storage, console logs'));
  
  await waitForEnter();

  // Feature 3: Network Analysis
  printHeader('Network Traffic Analysis');
  
  printStep('1', 'Viewing all requests');
  console.log(chalk.gray('Command: ') + chalk.white('requests'));
  console.log(chalk.gray('\nShows all HTTP requests with:'));
  console.log(chalk.white('  • Method (GET, POST, PUT, DELETE)'));
  console.log(chalk.white('  • Status code'));
  console.log(chalk.white('  • Resource type (document, script, xhr)'));
  console.log(chalk.white('  • URL'));
  
  console.log(chalk.yellow('\nExample output:'));
  console.log(chalk.gray('┌───┬────────┬────────┬──────────┬─────────────────────────────┐'));
  console.log(chalk.gray('│ # │ Method │ Status │ Type     │ URL                         │'));
  console.log(chalk.gray('├───┼────────┼────────┼──────────┼─────────────────────────────┤'));
  console.log(chalk.gray('│ 1 │ ') + chalk.blue('GET') + chalk.gray('    │ ') + chalk.green('200') + chalk.gray('    │ document │ https://example.com         │'));
  console.log(chalk.gray('│ 2 │ ') + chalk.green('POST') + chalk.gray('   │ ') + chalk.green('201') + chalk.gray('    │ xhr      │ https://example.com/api     │'));
  console.log(chalk.gray('└───┴────────┴────────┴──────────┴─────────────────────────────┘'));
  
  await waitForEnter();

  printStep('2', 'Filtering requests');
  console.log(chalk.gray('Commands:'));
  console.log(chalk.white('  requests POST      ') + chalk.gray('# Show only POST requests'));
  console.log(chalk.white('  requests api       ') + chalk.gray('# Show requests with "api" in URL'));
  console.log(chalk.white('  requests "" 5      ') + chalk.gray('# Show last 5 requests'));
  
  await waitForEnter();

  printStep('3', 'Inspecting headers');
  console.log(chalk.gray('Commands:'));
  console.log(chalk.white('  headers response   ') + chalk.gray('# Show response headers'));
  console.log(chalk.white('  headers request    ') + chalk.gray('# Show request headers'));
  console.log(chalk.white('  headers response api ') + chalk.gray('# Headers for URL containing "api"'));
  
  console.log(chalk.yellow('\n💡 Tip: ') + chalk.white('Look for these in headers:'));
  console.log(chalk.white('  • X-Powered-By: Technology disclosure'));
  console.log(chalk.white('  • Server: Version information'));
  console.log(chalk.white('  • X-Flag: CTF flags in custom headers'));
  console.log(chalk.white('  • Set-Cookie: Session tokens'));
  
  await waitForEnter();

  // Feature 4: Cookie Management
  printHeader('Cookie & Session Management');
  
  printStep('1', 'Viewing cookies');
  console.log(chalk.gray('Command: ') + chalk.white('cookies'));
  console.log(chalk.gray('\nDisplays all cookies with:'));
  console.log(chalk.white('  • Name and value'));
  console.log(chalk.white('  • Domain and path'));
  console.log(chalk.white('  • Secure and HttpOnly flags'));
  
  await waitForEnter();

  printStep('2', 'Manipulating cookies');
  console.log(chalk.gray('Commands:'));
  console.log(chalk.white('  setcookie admin true     ') + chalk.gray('# Set admin flag'));
  console.log(chalk.white('  setcookie role administrator ') + chalk.gray('# Change role'));
  
  console.log(chalk.yellow('\n💡 CTF Tip: ') + chalk.white('Common cookie exploits:'));
  console.log(chalk.white('  • Change role from "user" to "admin"'));
  console.log(chalk.white('  • Set "is_admin" to "true"'));
  console.log(chalk.white('  • Modify session IDs'));
  console.log(chalk.white('  • Look for base64-encoded data in cookies'));
  
  await waitForEnter();

  // Feature 5: JavaScript Execution
  printHeader('JavaScript Execution & DOM Analysis');
  
  printStep('1', 'Running JavaScript');
  console.log(chalk.gray('Command: ') + chalk.white('js <code>'));
  console.log(chalk.gray('\nExecute any JavaScript in the page context:'));
  console.log(chalk.white('  js document.title'));
  console.log(chalk.white('  js window.location.href'));
  console.log(chalk.white('  js localStorage.getItem("token")'));
  
  await waitForEnter();

  printStep('2', 'Finding secrets in JavaScript');
  console.log(chalk.gray('Useful commands:'));
  console.log(chalk.white('  js Object.keys(window)              ') + chalk.gray('# List all globals'));
  console.log(chalk.white('  js window.API_KEY                   ') + chalk.gray('# Check for API key'));
  console.log(chalk.white('  js window.SECRET                    ') + chalk.gray('# Check for secrets'));
  console.log(chalk.white('  js JSON.stringify(localStorage)     ') + chalk.gray('# Dump all storage'));
  
  console.log(chalk.yellow('\n💡 CTF Tip: ') + chalk.white('Developers often store flags in:'));
  console.log(chalk.white('  • window.FLAG'));
  console.log(chalk.white('  • window.config.secret'));
  console.log(chalk.white('  • localStorage["flag"]'));
  console.log(chalk.white('  • Hidden DOM elements'));
  
  await waitForEnter();

  printStep('3', 'DOM extraction');
  console.log(chalk.gray('Commands:'));
  console.log(chalk.white('  dom form                ') + chalk.gray('# Extract all forms'));
  console.log(chalk.white('  dom input               ') + chalk.gray('# Get all inputs'));
  console.log(chalk.white('  dom [type="hidden"]     ') + chalk.gray('# Find hidden fields'));
  
  await waitForEnter();

  // Feature 6: Storage Analysis
  printHeader('Storage Analysis');
  
  printStep('1', 'Viewing storage');
  console.log(chalk.gray('Command: ') + chalk.white('storage'));
  console.log(chalk.gray('\nShows both localStorage and sessionStorage'));
  console.log(chalk.gray('Useful for finding:'));
  console.log(chalk.white('  • JWT tokens'));
  console.log(chalk.white('  • API keys'));
  console.log(chalk.white('  • Cached data'));
  console.log(chalk.white('  • Feature flags'));
  
  await waitForEnter();

  // Feature 7: Console Monitoring
  printHeader('Console Log Monitoring');
  
  printStep('1', 'Viewing console logs');
  console.log(chalk.gray('Command: ') + chalk.white('console'));
  console.log(chalk.gray('\nCaptures all console output:'));
  console.log(chalk.white('  • console.log()'));
  console.log(chalk.white('  • console.warn()'));
  console.log(chalk.white('  • console.error()'));
  console.log(chalk.white('  • JavaScript errors'));
  
  console.log(chalk.yellow('\n💡 Tip: ') + chalk.white('Developers often log sensitive data:'));
  console.log(chalk.white('  • Debug messages with tokens'));
  console.log(chalk.white('  • Error messages with paths'));
  console.log(chalk.white('  • API responses'));
  
  await waitForEnter();

  // Feature 8: Search & Pattern Matching
  printHeader('Source Code Search');
  
  printStep('1', 'Searching for patterns');
  console.log(chalk.gray('Command: ') + chalk.white('search <pattern>'));
  console.log(chalk.gray('\nCommon searches:'));
  console.log(chalk.white('  search flag{.*}              ') + chalk.gray('# Find flags'));
  console.log(chalk.white('  search api[_-]?key           ') + chalk.gray('# Find API keys'));
  console.log(chalk.white('  search password              ') + chalk.gray('# Find passwords'));
  console.log(chalk.white('  search TODO|FIXME            ') + chalk.gray('# Developer comments'));
  console.log(chalk.white('  search <!--[\\s\\S]*?-->        ') + chalk.gray('# HTML comments'));
  
  await waitForEnter();

  // Feature 9: Request Interception
  printHeader('Request Interception');
  
  printStep('1', 'Live traffic monitoring');
  console.log(chalk.gray('Command: ') + chalk.white('intercept on'));
  console.log(chalk.gray('\nEnables live logging of all requests:'));
  console.log(chalk.yellow('→ GET https://example.com/api/user'));
  console.log(chalk.green('← 200 https://example.com/api/user'));
  console.log(chalk.yellow('→ POST https://example.com/api/login'));
  console.log(chalk.red('← 401 https://example.com/api/login'));
  
  await waitForEnter();

  // Feature 10: Tools & Export
  printHeader('Tools & Export Features');
  
  printStep('1', 'Taking screenshots');
  console.log(chalk.gray('Command: ') + chalk.white('screenshot evidence.png'));
  console.log(chalk.gray('\nCaptures full-page screenshot for evidence'));
  
  await waitForEnter();

  printStep('2', 'Exporting traffic');
  console.log(chalk.gray('Command: ') + chalk.white('har traffic.har'));
  console.log(chalk.gray('\nExports all network traffic as HAR file'));
  console.log(chalk.gray('Can be imported into Burp Suite or ZAP'));
  
  await waitForEnter();

  printStep('3', 'Custom headers');
  console.log(chalk.gray('Command: ') + chalk.white('setheader X-Forwarded-For 127.0.0.1'));
  console.log(chalk.gray('\nUseful for:'));
  console.log(chalk.white('  • IP spoofing'));
  console.log(chalk.white('  • Testing authorization bypass'));
  console.log(chalk.white('  • Custom authentication headers'));
  
  await waitForEnter();

  // CTF Workflow Example
  printHeader('Example CTF Workflow');
  
  console.log(chalk.white('Here\'s a typical workflow for solving a web CTF challenge:\n'));
  
  const workflow = [
    { step: '1', action: 'Navigate to challenge URL', cmd: 'go https://ctf.challenge.com' },
    { step: '2', action: 'Enable traffic monitoring', cmd: 'intercept on' },
    { step: '3', action: 'Check network requests', cmd: 'requests' },
    { step: '4', action: 'Inspect response headers', cmd: 'headers response' },
    { step: '5', action: 'View cookies', cmd: 'cookies' },
    { step: '6', action: 'Check storage', cmd: 'storage' },
    { step: '7', action: 'Look for flags in source', cmd: 'search flag{.*}' },
    { step: '8', action: 'Check console logs', cmd: 'console' },
    { step: '9', action: 'Execute JS to find globals', cmd: 'js Object.keys(window)' },
    { step: '10', action: 'Take screenshot as evidence', cmd: 'screenshot solved.png' }
  ];

  workflow.forEach(({ step, action, cmd }) => {
    console.log(chalk.yellow(`${step}. `) + chalk.white(action));
    console.log(chalk.gray('   → ') + chalk.cyan(cmd));
    console.log();
  });

  await waitForEnter();

  // Common CTF Patterns
  printHeader('Common CTF Patterns');
  
  console.log(chalk.white('What to look for in web CTF challenges:\n'));
  
  const patterns = [
    { category: 'Cookies', items: ['admin=false → admin=true', 'role=user → role=admin', 'Base64-encoded flags'] },
    { category: 'Headers', items: ['X-Flag: flag{...}', 'X-Secret: ...', 'Server version disclosure'] },
    { category: 'JavaScript', items: ['window.FLAG', 'window.SECRET', 'Commented code'] },
    { category: 'Storage', items: ['localStorage["flag"]', 'JWT tokens', 'API keys'] },
    { category: 'Source', items: ['HTML comments', 'TODO/FIXME notes', 'Hidden forms'] },
    { category: 'Network', items: ['API endpoints', 'Hidden routes', 'Admin panels'] }
  ];

  patterns.forEach(({ category, items }) => {
    console.log(chalk.cyan.bold(category + ':'));
    items.forEach(item => {
      console.log(chalk.white('  • ' + item));
    });
    console.log();
  });

  await waitForEnter();

  // Quick Reference
  printHeader('Quick Command Reference');
  
  console.log(chalk.white('Essential commands:\n'));
  
  const commands = [
    ['go <url>', 'Navigate to URL'],
    ['requests [filter]', 'Show network traffic'],
    ['headers [req|res]', 'Show headers'],
    ['cookies', 'Show cookies'],
    ['storage', 'Show localStorage/sessionStorage'],
    ['console', 'Show console logs'],
    ['search <pattern>', 'Search HTML source'],
    ['js <code>', 'Execute JavaScript'],
    ['dom <selector>', 'Extract DOM elements'],
    ['screenshot [file]', 'Take screenshot'],
    ['intercept on', 'Enable live monitoring'],
    ['help', 'Show all commands']
  ];

  const maxLen = Math.max(...commands.map(c => c[0].length));
  commands.forEach(([cmd, desc]) => {
    console.log(chalk.yellow('  ' + cmd.padEnd(maxLen + 2)) + chalk.gray(desc));
  });

  await waitForEnter();

  // Final Tips
  printHeader('Pro Tips');
  
  console.log(chalk.white('Remember these tips for success:\n'));
  
  const tips = [
    'Always check EVERYTHING: network, cookies, storage, console, source',
    'Enable intercept mode to see all traffic in real-time',
    'Search for common patterns: flag{, api_key, password, secret',
    'Check JavaScript global variables with: js Object.keys(window)',
    'Look at cookies - many CTFs hide flags or admin flags there',
    'Console logs often contain debug information',
    'Take screenshots of your findings for write-ups',
    'Export HAR files for offline analysis',
    'Try cookie manipulation for authentication bypass',
    'Read ALL the source code, including comments'
  ];

  tips.forEach((tip, idx) => {
    console.log(chalk.green(`${idx + 1}. `) + chalk.white(tip));
  });

  console.log();
  await waitForEnter();

  // Conclusion
  printHeader('Ready to Start!');
  
  console.log(chalk.white('You\'re now ready to use WebCTF CLI for web security testing!\n'));
  console.log(chalk.cyan('To get started:'));
  console.log(chalk.white('  1. Run: ') + chalk.yellow('node webctf-cli.js'));
  console.log(chalk.white('  2. Type: ') + chalk.yellow('help'));
  console.log(chalk.white('  3. Start with: ') + chalk.yellow('go <url>'));
  console.log();
  console.log(chalk.gray('For more examples, check out:'));
  console.log(chalk.gray('  • README.md - Basic usage'));
  console.log(chalk.gray('  • ADVANCED_GUIDE.md - Advanced techniques'));
  console.log(chalk.gray('  • examples.js - Code examples'));
  console.log();
  console.log(chalk.green('Happy hacking! 🚀'));
  console.log();
}

// Run demo
if (require.main === module) {
  demo().catch(console.error);
}

module.exports = demo;
