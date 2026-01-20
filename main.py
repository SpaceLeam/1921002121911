#!/usr/bin/env python3
"""
TfaBuster - Smart 2FA Bypass Detection Tool
Main CLI entry point.
"""
import argparse
import logging
import sys
import json
from core.session_manager import SessionManager
from core.engine import AttackEngine
from modules.status import print_manual_guide

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger(__name__)


def print_banner():
    """Print tool banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                       TfaBuster v1.0                          ║
║           Smart 2FA Bypass Detection Tool                     ║
║                                                               ║
║  [!] For authorized security testing only                    ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='TfaBuster - Automated 2FA bypass detection tool',
        epilog='Example: python main.py --target https://api.example.com/verify --cookies "session=abc123" --payload \'{"code":"000000"}\''
    )
    
    parser.add_argument(
        '--target',
        required=True,
        help='Target 2FA verification endpoint URL'
    )
    
    parser.add_argument(
        '--payload',
        required=True,
        help='JSON payload with INVALID OTP code for baseline (e.g., \'{"code":"000000","user_id":"123"}\')'
    )
    
    parser.add_argument(
        '--cookies',
        help='Session cookies as string (e.g., "session=abc123; token=xyz")'
    )
    
    parser.add_argument(
        '--auth',
        help='Authorization token (without Bearer prefix)'
    )
    
    parser.add_argument(
        '--otp-param',
        default='code',
        help='Name of OTP parameter in payload (default: code)'
    )
    
    parser.add_argument(
        '--include-race',
        action='store_true',
        help='Include race condition testing (can be noisy)'
    )
    
    parser.add_argument(
        '--output',
        default='output/results.json',
        help='Output file for results (default: output/results.json)'
    )
    
    parser.add_argument(
        '--proxy',
        help='Proxy URL (e.g., http://127.0.0.1:8080 for Burp)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose debug logging'
    )
    
    parser.add_argument(
        '--manual-guide',
        action='store_true',
        help='Print manual response manipulation guide and exit'
    )
    
    return parser.parse_args()


def main():
    """Main execution flow."""
    args = parse_args()
    
    print_banner()
    
    # Special mode: print manual guide
    if args.manual_guide:
        print_manual_guide()
        return
    
    # Set verbose logging if requested
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Parse JSON payload
    try:
        test_payload = json.loads(args.payload)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON payload: {e}")
        sys.exit(1)
    
    # Validate OTP parameter exists in payload
    if args.otp_param not in test_payload:
        logger.warning(f"OTP parameter '{args.otp_param}' not found in payload!")
        logger.warning(f"Available keys: {list(test_payload.keys())}")
        logger.warning("Continuing anyway, but results may be unexpected...")
    
    # Initialize session manager
    session_manager = SessionManager()
    if args.cookies:
        session_manager = SessionManager.from_cookie_string(args.cookies)
    if args.auth:
        session_manager.set_auth_token(args.auth)
    
    logger.info(f"[*] Target: {args.target}")
    logger.info(f"[*] OTP Parameter: {args.otp_param}")
    if args.cookies:
        logger.info(f"[*] Session: {len(session_manager.get_cookies())} cookies loaded")
    if args.auth:
        logger.info(f"[*] Authorization: Bearer {args.auth[:10]}...")
    if args.proxy:
        logger.info(f"[*] Proxy: {args.proxy}")
    
    print("\n" + "="*70)
    
    # Initialize attack engine
    # Note: Proxy support needs to be passed to requester
    engine = AttackEngine(
        target_url=args.target,
        session_manager=session_manager,
        test_payload=test_payload,
        otp_param=args.otp_param
    )
    
    # If proxy is set, update requester
    if args.proxy:
        engine.requester.proxy = {"http": args.proxy, "https": args.proxy}
    
    # Run all attacks
    try:
        results = engine.run_all_attacks(include_race=args.include_race)
        
        # Save results
        engine.save_results(args.output)
        
        # Print summary
        bypasses = [r for r in results if r['bypass_detected']]
        
        print("\n" + "="*70)
        print("SUMMARY")
        print("="*70)
        print(f"Total tests run: {len(results)}")
        print(f"Bypasses detected: {len(bypasses)}")
        
        if bypasses:
            print("\n[!] POTENTIAL BYPASSES:")
            for bypass in bypasses:
                print(f"\n  • {bypass['attack_name']}")
                print(f"    Confidence: {bypass['confidence_level']} ({bypass['confidence_score']}%)")
                print(f"    Status: {bypass['baseline_status']} → {bypass['response_status']}")
        else:
            print("\n[+] No bypasses detected. Target appears secure against automated attacks.")
            print("    Consider manual testing with Burp Suite (run with --manual-guide)")
        
        print("\n" + "="*70)
        print(f"[*] Full results saved to: {args.output}")
        print("="*70 + "\n")
        
    except KeyboardInterrupt:
        logger.warning("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\n[!] Error during scan: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
