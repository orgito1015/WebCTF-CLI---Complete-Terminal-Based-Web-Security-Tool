#!/usr/bin/env node

/**
 * Test Suite for WebCTF CLI
 * Tests basic functionality without requiring network access
 */

const WebCTFCLI = require('./webctf-cli');
const CTFTools = require('./ctf-tools');
const chalk = require('chalk');

let testsRun = 0;
let testsPassed = 0;
let testsFailed = 0;

function assert(condition, message) {
  testsRun++;
  if (condition) {
    testsPassed++;
    console.log(chalk.green('✓ ' + message));
  } else {
    testsFailed++;
    console.log(chalk.red('✗ ' + message));
  }
}

function assertEquals(actual, expected, message) {
  testsRun++;
  if (JSON.stringify(actual) === JSON.stringify(expected)) {
    testsPassed++;
    console.log(chalk.green('✓ ' + message));
  } else {
    testsFailed++;
    console.log(chalk.red('✗ ' + message));
    console.log(chalk.gray('  Expected:', JSON.stringify(expected)));
    console.log(chalk.gray('  Actual:', JSON.stringify(actual)));
  }
}

console.log(chalk.cyan.bold('\n🧪 WebCTF CLI Test Suite\n'));

// Test CTFTools
console.log(chalk.yellow('\n--- CTF Tools Tests ---\n'));

try {
  // Base64 encoding/decoding
  const text = 'Hello World';
  const encoded = CTFTools.base64Encode(text);
  const decoded = CTFTools.base64Decode(encoded);
  assertEquals(decoded, text, 'Base64 encode/decode');

  // URL encoding/decoding
  const urlText = 'hello world@test.com';
  const urlEncoded = CTFTools.urlEncode(urlText);
  const urlDecoded = CTFTools.urlDecode(urlEncoded);
  assertEquals(urlDecoded, urlText, 'URL encode/decode');

  // Hex encoding/decoding
  const hexText = 'Test';
  const hexEncoded = CTFTools.hexEncode(hexText);
  const hexDecoded = CTFTools.hexDecode(hexEncoded);
  assertEquals(hexDecoded, hexText, 'Hex encode/decode');

  // MD5 hashing
  const md5Hash = CTFTools.md5('password');
  assertEquals(md5Hash.length, 32, 'MD5 hash length is 32 characters');

  // SHA256 hashing
  const sha256Hash = CTFTools.sha256('password');
  assertEquals(sha256Hash.length, 64, 'SHA256 hash length is 64 characters');

  // JWT decoding
  const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const decodedJWT = CTFTools.decodeJWT(jwt);
  assertEquals(decodedJWT.payload.name, 'John Doe', 'JWT decoding - payload extraction');
  assertEquals(decodedJWT.header.alg, 'HS256', 'JWT decoding - header extraction');

  // ROT13
  const rot13Text = 'hello';
  const rot13Result = CTFTools.rot13(rot13Text);
  const rot13Back = CTFTools.rot13(rot13Result);
  assertEquals(rot13Back, rot13Text, 'ROT13 encode/decode');

  // Password strength analysis
  const weakPass = '123456';
  const weakAnalysis = CTFTools.analyzePasswordStrength(weakPass);
  assertEquals(weakAnalysis.level, 'Weak', 'Password strength - weak password');

  const strongPass = 'P@ssw0rd!2024XYZ';
  const strongAnalysis = CTFTools.analyzePasswordStrength(strongPass);
  assertEquals(strongAnalysis.level, 'Strong', 'Password strength - strong password');

  // Hash identification
  const md5Hash2 = '5f4dcc3b5aa765d61d8327deb882cf99'; // password
  const identified = CTFTools.identifyHash(md5Hash2);
  assert(identified.includes('MD5'), 'Hash identification - MD5');

  // URL analysis
  const maliciousUrl = "http://test.com/page?id=' OR '1'='1";
  const urlFindings = CTFTools.analyzeURL(maliciousUrl);
  assert(urlFindings.length > 0, 'URL analysis detects SQLi patterns');

  // Extract utilities
  const textWithEmails = 'Contact: admin@test.com and support@example.org';
  const emails = CTFTools.extractEmails(textWithEmails);
  assertEquals(emails.length, 2, 'Email extraction');

  const textWithUrls = 'Visit https://example.com and http://test.org';
  const urls = CTFTools.extractURLs(textWithUrls);
  assertEquals(urls.length, 2, 'URL extraction');

  // HTML encoding
  const htmlText = '<script>alert("XSS")</script>';
  const htmlEncoded = CTFTools.htmlEncode(htmlText);
  assert(!htmlEncoded.includes('<script>'), 'HTML encoding removes script tags');
  const htmlDecoded = CTFTools.htmlDecode(htmlEncoded);
  assertEquals(htmlDecoded, htmlText, 'HTML decode reverses encoding');

} catch (error) {
  console.log(chalk.red('✗ CTF Tools test error: ' + error.message));
  testsFailed++;
  testsRun++;
}

// Test WebCTFCLI class instantiation
console.log(chalk.yellow('\n--- WebCTF CLI Class Tests ---\n'));

try {
  const cli = new WebCTFCLI();
  assert(cli !== null, 'WebCTFCLI instantiation');
  assert(typeof cli.init === 'function', 'WebCTFCLI has init method');
  assert(typeof cli.navigate === 'function', 'WebCTFCLI has navigate method');
  assert(typeof cli.showStorage === 'function', 'WebCTFCLI has showStorage method');
  assert(typeof cli.showCookies === 'function', 'WebCTFCLI has showCookies method');
  assert(typeof cli.executeJS === 'function', 'WebCTFCLI has executeJS method');
  assert(typeof cli.screenshot === 'function', 'WebCTFCLI has screenshot method');
  assert(typeof cli.exportHAR === 'function', 'WebCTFCLI has exportHAR method');
  assert(typeof cli.searchHTML === 'function', 'WebCTFCLI has searchHTML method');
  assert(typeof cli.showRequests === 'function', 'WebCTFCLI has showRequests method');
  assert(typeof cli.showHeaders === 'function', 'WebCTFCLI has showHeaders method');
  assert(typeof cli.showConsole === 'function', 'WebCTFCLI has showConsole method');
  assert(typeof cli.extractDOM === 'function', 'WebCTFCLI has extractDOM method');
  assert(typeof cli.setCookie === 'function', 'WebCTFCLI has setCookie method');
  assert(typeof cli.setHeader === 'function', 'WebCTFCLI has setHeader method');
  assert(typeof cli.cleanup === 'function', 'WebCTFCLI has cleanup method');
  
  // Test utility methods
  assert(cli.truncate('hello world', 5) === 'he...', 'truncate method works correctly');
  assert(cli.truncate('hi', 10) === 'hi', 'truncate does not truncate short strings');
  assert(cli.truncate('', 5) === '', 'truncate handles empty strings');
  
} catch (error) {
  console.log(chalk.red('✗ WebCTFCLI class test error: ' + error.message));
  testsFailed++;
  testsRun++;
}

// Test regex patterns for common CTF challenges
console.log(chalk.yellow('\n--- Pattern Matching Tests ---\n'));

try {
  const flagPattern = /flag\{[^}]+\}/gi;
  const htmlWithFlag = '<div>flag{test_flag_123}</div>';
  const matches = htmlWithFlag.match(flagPattern);
  assert(matches && matches.length === 1, 'Flag pattern detection');
  
  const apiKeyPattern = /api[_-]?key|apikey|api_secret/gi;
  const textWithKey = 'const API_KEY = "abc123"';
  const apiMatches = textWithKey.match(apiKeyPattern);
  assert(apiMatches && apiMatches.length === 1, 'API key pattern detection');
  
} catch (error) {
  console.log(chalk.red('✗ Pattern matching test error: ' + error.message));
  testsFailed++;
  testsRun++;
}

// Summary
console.log(chalk.cyan.bold('\n--- Test Summary ---\n'));
console.log(chalk.white(`Total tests: ${testsRun}`));
console.log(chalk.green(`Passed: ${testsPassed}`));
console.log(chalk.red(`Failed: ${testsFailed}`));

if (testsFailed === 0) {
  console.log(chalk.green.bold('\n✓ All tests passed!\n'));
  process.exit(0);
} else {
  console.log(chalk.red.bold(`\n✗ ${testsFailed} test(s) failed\n`));
  process.exit(1);
}
