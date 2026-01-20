# TfaBuster - Smart 2FA Bypass Detection Tool

Automated tool untuk mendeteksi bypass 2FA dengan teknik yang umum ditemukan di bug bounty programs.

## Features

✅ **Smart Request Engine** - WAF evasion dengan UA rotation, jitter delays, dan browser-like headers  
✅ **Baseline Comparison** - Deteksi bypass dengan membandingkan response attack vs baseline  
✅ **Session Management** - Maintain cookies dan auth tokens  
✅ **13+ Logic Bypass Payloads** - Null, array injection, type juggling, dll  
✅ **Race Condition Testing** - Concurrent requests untuk detect OTP reuse  
✅ **CSRF Testing** - Session validation bypass  

## Installation

```bash
# Install dependencies
pip install requests fastapi uvicorn

# Clone atau download folder ini
cd learnhk
```

## Usage

### 1. Test Against Mock Server

Terminal 1 - Start vulnerable server:
```bash
cd tests
python mock_server.py
```

Terminal 2 - Run TfaBuster:
```bash
# Test null bypass
python main.py --target http://localhost:8000/verify-null \
               --payload '{"code":"000000"}' \
               --verbose

# Test array injection
python main.py --target http://localhost:8000/verify-array \
               --payload '{"code":"123456"}' 

# Test race condition
python main.py --target http://localhost:8000/verify-race \
               --payload '{"code":"123456"}' \
               --include-race
```

### 2. Test Against Real Target

```bash
python main.py \
  --target https://api.example.com/api/v1/verify \
  --payload '{"otp":"000000","user_id":"123"}' \
  --otp-param otp \
  --cookies "session=abc123; csrftoken=xyz" \
  --output results/example_com.json
```

### 3. Manual Response Manipulation Guide

```bash
python main.py --manual-guide
```

## Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--target` | Target 2FA endpoint (required) | `https://api.site.com/verify` |
| `--payload` | JSON payload dengan INVALID code (required) | `'{"code":"000000"}'` |
| `--cookies` | Session cookies | `"session=abc; token=xyz"` |
| `--auth` | Bearer token (without prefix) | `"eyJhbG..."` |
| `--otp-param` | OTP parameter name (default: code) | `otp` |
| `--include-race` | Enable race condition test | flag |
| `--output` | Output file path | `output/results.json` |
| `--proxy` | Proxy untuk Burp Suite | `http://127.0.0.1:8080` |
| `--verbose` | Debug logging | flag |

## Example Output

```
[+] Baseline established: Status 403, Length 1200
[*] Testing logic bypasses...
[!] BYPASS DETECTED: Null OTP Value (confidence: HIGH)
    - Status code change: 403 → 200
    - Significant length change: 1200 → 5000 (316.7%)
    - JSON key 'success' changed: False → True

[*] Scan complete: 2 potential bypasses found out of 23 tests
[*] Results saved to: output/results.json
```

## Directory Structure

```
learnhk/
├── main.py              # CLI entry point
├── core/
│   ├── engine.py        # Attack orchestration
│   ├── requester.py     # Smart HTTP wrapper (WAF evasion)
│   ├── analyzer.py      # Response comparison logic
│   └── session_manager.py
├── modules/
│   ├── logic.py         # Logic bypass payloads
│   ├── csrf.py          # Session manipulation
│   ├── race.py          # Race condition
│   └── status.py        # Manual response manipulation guide
├── tests/
│   └── mock_server.py   # Vulnerable test server
└── output/              # Results output directory
```

## How It Works

1. **Baseline Phase**: Send request dengan invalid OTP code → capture response (status, length, JSON structure)
2. **Attack Phase**: Kirim berbagai payload variants (null, array, boolean, dll)
3. **Analysis Phase**: Bandingkan setiap response vs baseline:
   - Status code changes (403 → 200)
   - Response length deltas (>10%)
   - JSON key changes (`success: false` → `true`)
   - New cookies/redirects
4. **Scoring**: Assign confidence score berdasarkan anomaly severity

## Tested Bypass Techniques

### Logic Bypasses
- Missing OTP parameter
- Null values
- Empty strings
- Array injection (`code[]`)
- Boolean true/false
- Integer 0, 1, -1
- Float values
- Very long strings
- SQL-like injection
- Object/dict values

### Session Bypasses
- Missing cookies
- Missing Authorization header
- Invalid/expired tokens
- Cross-user sessions
- Missing CORS headers

### Race Conditions
- OTP reuse via concurrent requests
- Rate limit bypass

## Integration with Burp Suite

Use TfaBuster untuk automated scanning, lalu verify manually di Burp:

```bash
# Run dengan Burp proxy
python main.py --target https://target.com/verify \
               --payload '{"code":"000000"}' \
               --proxy http://127.0.0.1:8080

# Check Burp HTTP History untuk detail requests
# Apply Match & Replace rules dari --manual-guide
```

## Disclaimer

⚠️ **For authorized security testing only!**  
Tool ini dibuat untuk ethical hacking dan bug bounty programs. Pastikan kamu punya izin sebelum testing.

## References

Inspired by real bug bounty findings dan techniques dari:
- Burp Suite Turbo Intruder
- Common 2FA bypass methodologies
- OWASP Testing Guide
