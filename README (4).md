# WebCTF CLI - Terminal-Based Web Security Tool

A powerful terminal-based tool for web security testing and CTF challenges. Think of it as browser DevTools + Burp Suite, but entirely from your terminal.

## Features

### 🌐 Network Analysis
- **Request/Response Inspection**: View all HTTP traffic with detailed headers and bodies
- **Request Interception**: Intercept and modify requests in real-time
- **HAR Export**: Export network traffic for analysis
- **Custom Request Builder**: Send arbitrary HTTP requests with custom headers and bodies

### 🔒 Security Testing
- **Security Header Analysis**: Automatic analysis of security headers (CSP, HSTS, etc.)
- **XSS Detection**: Test for cross-site scripting vulnerabilities
- **SQLi Detection**: Identify SQL injection vulnerabilities
- **CORS Analysis**: Detect CORS misconfigurations
- **Framework Detection**: Identify JavaScript frameworks and libraries

### 🍪 Cookie & Storage Management
- **Cookie Inspection**: View and modify cookies
- **Storage Access**: Read localStorage and sessionStorage
- **Session Management**: Manage authentication tokens

### 🎨 DOM & JavaScript
- **DOM Extraction**: Query and extract DOM elements
- **JavaScript Execution**: Run arbitrary JavaScript in page context
- **Console Monitoring**: Capture all console logs and errors
- **Source Search**: Search through HTML source code

### 🛠️ CTF Tools
- **Screenshot Capture**: Take full-page screenshots
- **Token Extraction**: Find CSRF tokens and hidden form fields
- **Form Submission**: Programmatically submit forms
- **Pattern Matching**: Search for flags, secrets, and patterns

## Installation

```bash
npm install
chmod +x webctf-cli.js
```

## Quick Start

```bash
node webctf-cli.js
```

## Usage Examples

### Basic Navigation

```
webctf> go https://example.com
webctf> reload
webctf> back
```

### Network Traffic Analysis

```
# View all requests
webctf> requests

# Filter requests by URL pattern
webctf> requests api

# Show only GET requests (limit to 5)
webctf> requests GET 5

# View response headers
webctf> headers response

# View request headers for specific URL
webctf> headers request api/login

# Enable live interception logging
webctf> intercept on
```

### Cookie & Storage Inspection

```
# View all cookies
webctf> cookies

# Set a custom cookie
webctf> setcookie session_id abc123def456

# View localStorage and sessionStorage
webctf> storage
```

### JavaScript Execution

```
# Execute JavaScript
webctf> js document.title

# Access local variables
webctf> js window.secret_key

# Modify the DOM
webctf> js document.querySelector('h1').textContent = 'Hacked'

# Extract data
webctf> js JSON.stringify(window.appConfig)
```

### DOM Analysis

```
# Extract all forms
webctf> dom form

# Find all links
webctf> dom a

# Get all input fields
webctf> dom input

# View console logs
webctf> console

# Filter error logs only
webctf> console error
```

### Security Testing

```
# Search for patterns (flags, secrets, etc.)
webctf> search flag{.*}
webctf> search api[_-]?key
webctf> search password

# Take a screenshot
webctf> screenshot evidence.png

# Export HAR file
webctf> har capture.har
```

### Advanced Request Manipulation

```
# Set custom headers
webctf> setheader X-Forwarded-For 127.0.0.1
webctf> setheader Authorization Bearer token123
```

## CTF Challenge Examples

### Example 1: Finding Hidden API Endpoints

```
webctf> go https://ctf.challenge.com
webctf> requests
# Analyze network traffic to find API calls
webctf> headers response api
# Look for interesting endpoints in responses
```

### Example 2: Cookie Manipulation

```
webctf> go https://ctf.challenge.com/login
webctf> cookies
# Note the admin flag cookie
webctf> setcookie admin true
webctf> go https://ctf.challenge.com/dashboard
```

### Example 3: JavaScript Variable Extraction

```
webctf> go https://ctf.challenge.com
webctf> js Object.keys(window)
# Look for suspicious global variables
webctf> js window.SECRET_CONFIG
webctf> js localStorage
```

### Example 4: Finding CSRF Tokens

```
webctf> go https://ctf.challenge.com/form
webctf> dom input[type="hidden"]
# Extract CSRF token
webctf> js document.querySelector('[name="csrf_token"]').value
```

### Example 5: Source Code Analysis

```
webctf> go https://ctf.challenge.com
webctf> search flag\{
webctf> search TODO
webctf> search password
webctf> console
# Check for developer comments and debug logs
```

### Example 6: Response Header Analysis

```
webctf> go https://ctf.challenge.com
webctf> headers response
# Look for:
# - Server version disclosure
# - Custom headers with hints
# - Security misconfigurations
```

### Example 7: Storage Enumeration

```
webctf> go https://ctf.challenge.com
webctf> storage
# Check localStorage for:
# - JWT tokens
# - API keys
# - Feature flags
# - Cached data
```

## Advanced Features

### Request Interception

Enable request interception to see all network traffic in real-time:

```
webctf> intercept on
→ GET https://example.com/api/user
← 200 https://example.com/api/user
→ POST https://example.com/api/login
← 401 https://example.com/api/login
```

### HAR Export

Capture all network traffic and export as HAR for offline analysis:

```
webctf> har traffic.har
✓ HAR file exported: traffic.har
```

### Console Monitoring

Capture JavaScript console output, including errors and debug logs:

```
webctf> console
[LOG] Application initialized
[WARN] Deprecated API usage
[ERROR] Network request failed
```

### Full-Page Screenshots

Capture evidence with full-page screenshots:

```
webctf> screenshot flag_found.png
✓ Screenshot saved: flag_found.png
```

## Commands Reference

### Navigation
- `go <url>` - Navigate to URL
- `reload` - Reload current page
- `back` - Go back in history

### Network
- `requests [filter] [limit]` - Show network requests
- `headers [req|res] [filter]` - Show headers
- `intercept [on|off]` - Toggle request interception
- `har [filename]` - Export traffic as HAR

### DOM & JavaScript
- `dom [selector]` - Extract DOM elements
- `js <code>` - Execute JavaScript
- `search <pattern>` - Search HTML source
- `console [filter] [limit]` - Show console logs

### Cookies & Storage
- `cookies` - Show cookies
- `setcookie <name> <value>` - Set cookie
- `storage` - Show storage
- `setheader <name> <value>` - Set custom header

### Tools
- `screenshot [filename]` - Take screenshot
- `form <selector> <data>` - Submit form

### Utility
- `clear` - Clear logs
- `info` - Show page info
- `help` - Show commands
- `exit` - Exit tool

## Tips for CTF Challenges

1. **Always check network traffic first** - Many flags are hidden in API responses
2. **Inspect all cookies** - Look for admin flags, role cookies, or encoded data
3. **Search for common patterns** - `flag{`, `ctf{`, `TODO`, `password`, `secret`
4. **Check JavaScript variables** - Developers often leave secrets in global variables
5. **Analyze security headers** - Missing CSP or CORS issues can be the vulnerability
6. **Look at localStorage** - JWTs and API keys are often stored here
7. **Monitor console logs** - Debug messages can leak sensitive information
8. **Inspect form tokens** - CSRF tokens sometimes contain hints
9. **Check response timing** - Slow responses might indicate SQL injection
10. **Screenshot everything** - Evidence is crucial for write-ups

## Security Features

### Security Header Analysis
Automatically analyzes security headers and provides a security score:
- HSTS
- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- And more...

### Vulnerability Testing
Built-in testing for common vulnerabilities:
- XSS (Cross-Site Scripting)
- SQL Injection
- CORS Misconfigurations

### Token Extraction
Automatically finds and extracts:
- CSRF tokens
- Hidden form fields
- Meta tokens

## Architecture

The tool is built with:
- **Puppeteer** - Headless Chrome automation
- **Node.js** - Runtime environment
- **Chalk** - Terminal styling
- **CLI Table** - Beautiful table output

## Contributing

This tool is designed for CTF challenges and security research. Use responsibly and only on systems you have permission to test.

## License

MIT License - Use at your own risk

## Author

Senior Security Engineer & CTF Enthusiast

---

**Remember**: This tool is for educational purposes and authorized security testing only. Always get permission before testing systems you don't own.
