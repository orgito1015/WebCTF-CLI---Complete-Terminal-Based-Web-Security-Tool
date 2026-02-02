# WebCTF CLI - Project Overview

## 🎯 Project Summary

WebCTF CLI is a comprehensive terminal-based web security tool designed specifically for CTF (Capture The Flag) challenges. It combines the functionality of browser DevTools, Burp Suite, and custom security testing tools into a single, powerful command-line interface.

## 📁 Project Structure

```
webctf-cli/
├── webctf-cli.js           # Main CLI application
├── security-analyzer.js     # Security testing & analysis module
├── http-interceptor.js      # Request/response interception
├── ctf-tools.js            # CTF-specific utilities (encoding, payloads)
├── examples.js             # Usage examples for common scenarios
├── demo.js                 # Interactive feature demonstration
├── package.json            # Node.js dependencies
├── quickstart.sh           # Quick setup script
├── README.md               # Basic usage guide
└── ADVANCED_GUIDE.md       # Advanced techniques & tips
```

## 🔧 Core Components

### 1. webctf-cli.js (Main Application)
The primary interactive CLI that provides:
- Browser automation via Puppeteer
- Network traffic monitoring and inspection
- Cookie and session management
- DOM analysis and manipulation
- JavaScript execution in page context
- Console log capture
- Screenshot and HAR export
- Interactive command-line interface

**Key Features:**
- Real-time request/response interception
- Comprehensive header analysis
- Storage access (localStorage/sessionStorage)
- Pattern matching in source code
- Custom header injection
- Form submission automation

### 2. security-analyzer.js
Advanced security analysis module:
- Security header evaluation (CSP, HSTS, X-Frame-Options, etc.)
- XSS vulnerability testing
- SQL injection detection
- CORS misconfiguration analysis
- CSRF token extraction
- JavaScript framework detection
- Automated security scoring

### 3. http-interceptor.js
Request/response manipulation toolkit:
- Request interception and modification
- Response blocking and mocking
- Custom header injection
- HTTP traffic logging
- Request builder for custom HTTP requests
- HAR export functionality
- Traffic statistics and analysis

### 4. ctf-tools.js
CTF-specific utilities:
- JWT token decoder
- Base64/URL/Hex encoding/decoding
- Hash generation (MD5, SHA256)
- ROT13 and Caesar cipher
- XOR encoding
- Email/URL/IP extraction
- Flag pattern matching
- Common payload generators (SQLi, XSS)
- Password analysis and generation

### 5. examples.js
Practical examples covering:
- API endpoint discovery
- Cookie manipulation
- JavaScript variable extraction
- Form analysis and CSRF tokens
- Source code secret search
- Storage enumeration
- Console log analysis
- Header injection testing

### 6. demo.js
Interactive demonstration:
- Feature overview
- Step-by-step walkthroughs
- CTF workflow examples
- Common patterns guide
- Quick command reference
- Pro tips and best practices

## 🚀 Key Features

### Network Analysis
- ✅ Capture all HTTP/HTTPS traffic
- ✅ Filter by method, URL, status code
- ✅ Inspect request/response headers
- ✅ View request/response bodies
- ✅ Export as HAR files
- ✅ Real-time traffic monitoring

### Security Testing
- ✅ Security header analysis
- ✅ XSS payload testing
- ✅ SQL injection detection
- ✅ CORS analysis
- ✅ CSRF token extraction
- ✅ Framework fingerprinting

### Cookie & Session Management
- ✅ View all cookies
- ✅ Modify cookie values
- ✅ Set custom cookies
- ✅ Analyze security flags
- ✅ Session token manipulation

### DOM & JavaScript
- ✅ Execute arbitrary JavaScript
- ✅ Extract DOM elements
- ✅ Modify page content
- ✅ Access global variables
- ✅ Enumerate window properties
- ✅ Extract hidden form fields

### Storage Analysis
- ✅ Read localStorage
- ✅ Read sessionStorage
- ✅ Search for JWT tokens
- ✅ Find API keys
- ✅ Extract cached data

### Developer Tools
- ✅ Console log monitoring
- ✅ JavaScript error capture
- ✅ Source code search
- ✅ Pattern matching (regex)
- ✅ Full-page screenshots
- ✅ Custom header injection

## 📖 Usage Examples

### Basic Navigation
```bash
webctf> go https://example.com
webctf> requests
webctf> cookies
webctf> storage
```

### Finding Flags
```bash
webctf> search flag{.*}
webctf> js window.FLAG
webctf> console
webctf> storage
```

### Cookie Manipulation
```bash
webctf> cookies
webctf> setcookie admin true
webctf> go /admin
```

### API Discovery
```bash
webctf> intercept on
webctf> requests api
webctf> headers response api
```

## 🎓 Common CTF Scenarios

### Scenario 1: Hidden Admin Panel
1. Navigate to site: `go https://target.com`
2. Check cookies: `cookies`
3. Look for role/admin flags
4. Modify: `setcookie admin true`
5. Access admin: `go /admin`

### Scenario 2: API Key in JavaScript
1. Load page: `go https://target.com`
2. List globals: `js Object.keys(window)`
3. Check for API_KEY: `js window.API_KEY`
4. Check storage: `storage`

### Scenario 3: Flag in Response Headers
1. Navigate: `go https://target.com`
2. Check headers: `headers response`
3. Look for X-Flag or custom headers

### Scenario 4: CSRF Token Bypass
1. Load form: `go https://target.com/form`
2. Extract token: `js document.querySelector('[name="csrf"]').value`
3. Analyze token pattern
4. Test token reuse

## 🔒 Security Features

- **Header Analysis**: Automatic security header evaluation
- **Vulnerability Testing**: Built-in XSS and SQLi detection
- **CORS Analysis**: Identify misconfigurations
- **Token Extraction**: Find CSRF tokens and secrets
- **Framework Detection**: Identify JavaScript libraries
- **Payload Generation**: SQLi and XSS payload templates

## 🛠️ Installation

```bash
# Clone or download the project
cd webctf-cli

# Run quick setup
./quickstart.sh

# Or manual setup
npm install
chmod +x webctf-cli.js
node webctf-cli.js
```

## 📚 Documentation

- **README.md**: Basic usage and command reference
- **ADVANCED_GUIDE.md**: Advanced techniques and CTF tips
- **examples.js**: Code examples for common scenarios
- **demo.js**: Interactive feature demonstration

## 🎯 Target Audience

- CTF participants
- Security researchers
- Penetration testers
- Bug bounty hunters
- Web security students
- Anyone doing web security testing

## 💡 Design Philosophy

1. **Terminal-First**: Everything accessible from command line
2. **CTF-Focused**: Features tailored for CTF challenges
3. **Comprehensive**: All DevTools features + security tools
4. **Easy to Use**: Simple commands, clear output
5. **Powerful**: Advanced features for complex scenarios
6. **Educational**: Learn web security through usage

## 🔄 Workflow Integration

WebCTF CLI integrates seamlessly with:
- **Burp Suite**: Export HAR files for analysis
- **OWASP ZAP**: Compatible traffic export
- **Custom Scripts**: Programmatic API access
- **CTF Platforms**: Direct testing of challenges
- **Write-ups**: Screenshot evidence capture

## 🚦 Getting Started

1. **Run the demo**: `node demo.js`
2. **Try examples**: `node examples.js`
3. **Start the CLI**: `node webctf-cli.js`
4. **Read the guides**: Check README.md and ADVANCED_GUIDE.md

## 📊 Feature Matrix

| Feature | WebCTF CLI | Browser DevTools | Burp Suite |
|---------|-----------|------------------|------------|
| Terminal-based | ✅ | ❌ | ✅ |
| Network inspection | ✅ | ✅ | ✅ |
| Cookie management | ✅ | ✅ | ✅ |
| JS execution | ✅ | ✅ | ❌ |
| Storage access | ✅ | ✅ | ❌ |
| Security analysis | ✅ | ❌ | ✅ |
| CTF-optimized | ✅ | ❌ | ⚠️ |
| Free & open | ✅ | ✅ | ⚠️ |

## 🏆 Why Use WebCTF CLI?

- **Speed**: Faster than switching between DevTools tabs
- **Automation**: Script repetitive tasks easily
- **History**: All traffic captured automatically
- **Evidence**: Easy screenshot and export capabilities
- **Learning**: Educational tool for web security
- **Flexibility**: Combine multiple tools in one interface

## 📝 License

MIT License - Free for educational and security research purposes

## ⚠️ Disclaimer

This tool is for educational purposes and authorized security testing only. Always obtain permission before testing systems you don't own.

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional security tests
- More CTF payload templates
- Enhanced reporting features
- Plugin system
- Configuration persistence

## 📞 Support

For issues, questions, or suggestions:
- Read the documentation
- Check the examples
- Run the demo for guidance

---

**Happy Hacking! 🚀**

Remember: With great power comes great responsibility. Use this tool ethically and legally.
