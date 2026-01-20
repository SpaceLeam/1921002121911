# TfaBuster

Tool otomatis untuk mendeteksi bypass 2FA yang sering muncul di bug bounty programs. Fokus utama adalah meniru cara kerja Burp Suite tapi dengan deteksi payload yang lebih cerdas.

## Core Features

Tool ini punya empat komponen utama:

**Smart Requester**: HTTP wrapper yang bisa evade WAF sederhana dengan cara rotate User-Agent (10 browser strings), kasih random delay antar request (jitter), dan pake header yang mirip browser asli. Ada retry logic dengan exponential backoff kalau request gagal.

**Response Analyzer**: Ini otak dari tool. Dia bandingkan response dari serangan vs baseline (request normal yang gagal). Deteksi bypass dari perubahan status code (403 jadi 200), perbedaan panjang response lebih dari 20%, cookie baru yang muncul, keyword sukses di body response, atau perubahan struktur JSON.

**Attack Modules**: Ada tiga jenis serangan yang di-automate. Logic bypass (13 payload: null, missing param, array injection, type juggling). CSRF testing (8 variasi header manipulation). Race condition (concurrent requests pake ThreadPoolExecutor).

**Session Manager**: Jaga state autentikasi tetap konsisten. Bisa handle cookies atau Bearer tokens.

## Installation

```bash
pip install requests fastapi uvicorn
cd learnhk
```

## Basic Usage

Cara paling simple:

```bash
python main.py --target http://target.com/verify --payload '{"code":"000000"}'
```

Dengan session cookies:

```bash
python main.py \
  --target https://api.example.com/verify-otp \
  --payload '{"user_id":"123","otp":"000000"}' \
  --cookies "session=abc123; csrf=xyz" \
  --otp-param otp
```

Test race condition:

```bash
python main.py --target http://target.com/verify \
               --payload '{"code":"123456"}' \
               --include-race
```

Route traffic lewat Burp:

```bash
python main.py --target https://target.com/verify \
               --payload '{"code":"000000"}' \
               --proxy http://127.0.0.1:8080
```

## Testing Against Mock Server

Gw udah bikin server vulnerable untuk testing. Buka dua terminal:

Terminal 1:
```bash
cd tests
python mock_server.py
```

Terminal 2:
```bash
# Test null bypass
python main.py --target http://localhost:8000/verify-null --payload '{"code":"000000"}'

# Test array injection
python main.py --target http://localhost:8000/verify-array --payload '{"code":"123456"}'

# Test boolean bypass
python main.py --target http://localhost:8000/verify-boolean --payload '{"code":"000000"}'
```

Mock server punya 6 endpoint vulnerable:
- `/verify` - Normal endpoint (baseline)
- `/verify-null` - Pass kalau parameter `code` missing atau null
- `/verify-array` - Pass kalau pakai `code[]` instead of `code`
- `/verify-boolean` - Pass kalau `code=true`
- `/verify-race` - OTP bisa dipake berkali-kali (race condition)
- `/verify-csrf` - Ga validate session cookie

## Command Line Options

```
--target       Target URL (required)
--payload      JSON body dengan OTP SALAH untuk baseline (required)
--otp-param    Nama parameter OTP (default: code)
--cookies      Cookie string format "name=value; name2=value2"
--auth         Bearer token tanpa prefix "Bearer"
--include-race Enable race condition test
--output       File output (default: output/results.json)
--proxy        Proxy URL untuk Burp Suite
--verbose      Debug logging
--manual-guide Print panduan response manipulation
```

## How It Works

Workflow tool ini straightforward. Pertama establish baseline dengan kirim request pake OTP yang salah. Capture semua detail response (status 403, length 1200, JSON body, cookies). Ini jadi patokan "normal failure".

Terus jalankan semua attack modules. Logic module kirim 13 payload variant. CSRF module test 8 kombinasi header manipulation. Kalau lu enable race, dia fire concurrent requests.

Setiap response dari attack dibandingkan sama baseline. Kalau beda signifikan, di-flag sebagai bypass. Confidence score dihitung berdasarkan severity anomaly. Status code shift dari 403 ke 200 = confidence 90%. Length deviation 20% = confidence 70%. New auth cookies = 85%.

Output disave ke JSON dan ditampilin summary di terminal.

## Bypass Techniques

Logic bypass yang di-test:
- Parameter OTP dihapus total
- `code: null`
- `code: ""`
- `code[]: "123456"` (array injection)
- `code: true` atau `code: false`
- `code: 0`, `code: 1`, `code: -1`
- `code: 123.456` (float)
- String super panjang (1000 char)
- SQL injection pattern
- Nested object

CSRF testing:
- Request tanpa Cookie header
- Request tanpa Authorization header
- Invalid session token
- Missing Referer
- Missing Origin
- Changed User-Agent

Race condition:
- 10 thread kirim OTP sama simultaneously
- Deteksi kalau server ga invalidate code setelah use pertama

## Example Output

```
[*] Target: http://localhost:8000/verify-null
[*] Establishing baseline with invalid OTP...
[+] Baseline established: Status 403, Length 42

[*] Running Logic Bypass Module...

[!] BYPASS DETECTED: Null OTP Value
    Confidence: HIGH (90%)
    Reason: Status Code Shift: 403 → 200

[!] BYPASS DETECTED: Array Injection (code[])
    Confidence: HIGH (90%)
    Reason: Status Code Shift: 403 → 200

SUMMARY
Total tests run: 21
Bypasses detected: 2

[*] Full results saved to: output/results.json
```

## Response Manipulation

Perlu diingat, tool ini cuma bisa test REQUEST manipulation. Kalau lu mau test response manipulation (ubah 401 jadi 200 di proxy), itu ga bisa di-automate. Harus manual pake Burp Suite.

Jalankan ini buat panduan:
```bash
python main.py --manual-guide
```

Tool bakal print list Match & Replace rules yang bisa lu apply di Burp untuk test client-side bypass.

## Workflow for Bug Bounty

1. Capture legitimate 2FA request di Burp Suite
2. Copy JSON payload dan cookies
3. Ganti OTP code jadi yang salah (misal 000000)
4. Run TfaBuster dengan payload tersebut
5. Review bypasses yang detected
6. Verify secara manual yang confidence HIGH
7. Report ke program kalau confirmed

## Project Structure

```
learnhk/
├── main.py                    # Entry point
├── core/
│   ├── engine.py             # Orchestrator
│   ├── requester.py          # HTTP wrapper + WAF evasion
│   ├── analyzer.py           # Baseline comparison
│   └── session_manager.py    # Cookie/token handler
├── modules/
│   ├── logic.py              # 13 payload generator
│   ├── csrf.py               # 8 header variants
│   ├── race.py               # ThreadPoolExecutor
│   └── status.py             # Manual testing guide
├── tests/
│   └── mock_server.py        # FastAPI vulnerable server
└── output/                   # JSON results
```

## Technical Notes

Ada satu bug penting yang gw fix: `requests.Response` object dengan status 4xx/5xx evaluate ke `False` di Python. Jadi kalau lu cek `if not response:` buat detect request failure, itu bakal trigger meskipun response valid tapi error. Harus pake `if response is None:` explicitly.

Exception handler di retry loop juga harus ada `continue` statement. Kalau engga, loop bakal fall through dan ga retry properly.

## Disclaimer

Tool ini strictly untuk authorized security testing. Jangan dipake buat nge-test target yang lu ga punya permission. Ini dibuat untuk ethical hacking dan legal bug bounty programs.

## Credits

Idenya dari real BBP findings, Burp Suite Turbo Intruder methodology, sama OWASP testing guidelines.
