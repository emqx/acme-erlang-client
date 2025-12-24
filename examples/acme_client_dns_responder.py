#!/usr/bin/env python3
"""
ACME DNS-01 Challenge Responder

A simple DNS server that responds to TXT record queries for ACME DNS-01 challenges.
Exposes an HTTP API to dynamically set challenge tokens.

Usage:
    python3 acme_client_dns_responder.py

The server listens on:
    - Port 53 (UDP/TCP) for DNS queries
    - Port 8053 (HTTP) for challenge management API

API Endpoints:
    POST /set-challenge
        Body: {"domain": "example.com", "record_name": "_acme-challenge.example.com", "record_value": "digest"}

    DELETE /clear-challenge?domain=example.com
        Clears challenge for a domain

    GET /health
        Health check endpoint
"""

import json
import socket
import signal
import sys
import threading
import http.server
import socketserver
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional

# DNS response codes
DNS_RCODE_NOERROR = 0
DNS_RCODE_NXDOMAIN = 3

# Challenge storage: domain -> record_value
challenges: Dict[str, str] = {}
challenges_lock = threading.Lock()


class DNSHandler:
    """Handles DNS queries for TXT records"""

    @staticmethod
    def parse_dns_query(data: bytes) -> tuple:
        """Parse DNS query packet"""
        if len(data) < 12:
            return None, None

        # Extract transaction ID (first 2 bytes)
        transaction_id = data[0:2]

        # Extract question section
        # Skip header (12 bytes) to get to question section
        question_start = 12

        # Find end of QNAME (null byte)
        qname_end = question_start
        while qname_end < len(data) and data[qname_end] != 0:
            qname_end += 1

        if qname_end >= len(data) - 4:
            return None, None

        # Extract QNAME
        qname = data[question_start:qname_end+1]

        # Extract QTYPE and QCLASS (2 bytes each, after QNAME)
        qtype_start = qname_end + 1
        if qtype_start + 4 > len(data):
            return None, None

        qtype = data[qtype_start:qtype_start+2]
        qclass = data[qtype_start+2:qtype_start+4]

        # Decode domain name
        domain = DNSHandler.decode_domain_name(qname)

        return transaction_id, (domain, qtype, qclass)

    @staticmethod
    def decode_domain_name(data: bytes) -> str:
        """Decode DNS domain name from packet format"""
        parts = []
        i = 0
        while i < len(data):
            length = data[i]
            if length == 0:
                break
            if length & 0xC0:  # Compressed name
                offset = ((length & 0x3F) << 8) | data[i+1]
                # For simplicity, return empty string for compressed names
                return ""
            i += 1
            if i + length > len(data):
                return ""
            parts.append(data[i:i+length].decode('ascii', errors='ignore'))
            i += length
        return '.'.join(parts)

    @staticmethod
    def encode_domain_name(domain: str) -> bytes:
        """Encode domain name to DNS packet format"""
        result = bytearray()
        for part in domain.split('.'):
            if part:
                result.append(len(part))
                result.extend(part.encode('ascii'))
        result.append(0)  # Null terminator
        return bytes(result)

    @staticmethod
    def build_dns_response(transaction_id: bytes, domain: str, record_value: Optional[str]) -> bytes:
        """Build DNS response packet"""
        response = bytearray()

        # Transaction ID
        response.extend(transaction_id)

        # Flags: QR=1 (response), Opcode=0 (query), AA=1 (authoritative), TC=0, RD=0, RA=0
        # RCODE: NOERROR (0) or NXDOMAIN (3)
        if record_value:
            flags = 0x8400  # QR=1, AA=1, RCODE=0
        else:
            flags = 0x8403  # QR=1, AA=1, RCODE=3 (NXDOMAIN)
        response.extend(flags.to_bytes(2, 'big'))

        # QDCOUNT: 1 question
        response.extend((1).to_bytes(2, 'big'))

        # ANCOUNT: 1 answer if record exists, 0 otherwise
        ancount = 1 if record_value else 0
        response.extend(ancount.to_bytes(2, 'big'))

        # NSCOUNT: 0
        response.extend((0).to_bytes(2, 'big'))

        # ARCOUNT: 0
        response.extend((0).to_bytes(2, 'big'))

        # Question section
        encoded_domain = DNSHandler.encode_domain_name(domain)
        response.extend(encoded_domain)
        response.extend((16).to_bytes(2, 'big'))  # QTYPE: TXT (16)
        response.extend((1).to_bytes(2, 'big'))   # QCLASS: IN (1)

        # Answer section (if record exists)
        if record_value:
            # NAME: pointer to question (0xC0 0x0C)
            response.extend(b'\xC0\x0C')

            # TYPE: TXT (16)
            response.extend((16).to_bytes(2, 'big'))

            # CLASS: IN (1)
            response.extend((1).to_bytes(2, 'big'))

            # TTL: 300 seconds
            response.extend((300).to_bytes(4, 'big'))

            # RDLENGTH: length of TXT record data
            txt_data = record_value.encode('ascii')
            rdlength = len(txt_data) + 1  # +1 for length byte
            response.extend(rdlength.to_bytes(2, 'big'))

            # TXT record: length byte + data
            response.append(len(txt_data))
            response.extend(txt_data)

        return bytes(response)

    @staticmethod
    def handle_dns_query(data: bytes, addr: tuple) -> Optional[bytes]:
        """Handle incoming DNS query"""
        transaction_id, query = DNSHandler.parse_dns_query(data)
        if not transaction_id or not query:
            return None

        domain, qtype, qclass = query

        # Only handle TXT queries (QTYPE 16)
        if qtype != (16).to_bytes(2, 'big'):
            return None

        # Check if we have a challenge for this domain
        with challenges_lock:
            record_value = challenges.get(domain)

        # Build response
        response = DNSHandler.build_dns_response(transaction_id, domain, record_value)

        print(f"[DNS] Query for {domain} -> {record_value if record_value else 'NXDOMAIN'}")
        return response


class HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP API handler for challenge management"""

    def do_POST(self):
        """Handle POST /set-challenge"""
        if self.path == '/set-challenge':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)

            try:
                data = json.loads(body.decode('utf-8'))
                domain = data.get('domain')
                record_name = data.get('record_name')
                record_value = data.get('record_value')

                if not all([domain, record_name, record_value]):
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'error': 'Missing required fields'}).encode())
                    return

                with challenges_lock:
                    challenges[record_name] = record_value

                print(f"[HTTP] Set challenge: {record_name} -> {record_value}")

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'ok'}).encode())

            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Invalid JSON'}).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        """Handle DELETE /clear-challenge?domain=example.com"""
        if self.path.startswith('/clear-challenge'):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            domain = params.get('domain', [None])[0]

            if domain:
                with challenges_lock:
                    # Remove all challenges for this domain
                    keys_to_remove = [k for k in challenges.keys() if k.endswith(domain)]
                    for k in keys_to_remove:
                        del challenges[k]
                        print(f"[HTTP] Cleared challenge: {k}")

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'ok'}).encode())
            else:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Missing domain parameter'}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        """Handle GET /health"""
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            with challenges_lock:
                self.wfile.write(json.dumps({
                    'status': 'ok',
                    'challenges': len(challenges)
                }).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Override to use print instead of stderr"""
        print(f"[HTTP] {format % args}")


# Global flag for graceful shutdown
shutdown_flag = threading.Event()

def start_dns_server(port=53):
    """Start DNS server on UDP port"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(1.0)  # Set timeout to allow checking shutdown flag
    sock.bind(('0.0.0.0', port))

    print(f"[DNS] Server listening on UDP port {port}")

    while not shutdown_flag.is_set():
        try:
            data, addr = sock.recvfrom(512)
            response = DNSHandler.handle_dns_query(data, addr)
            if response:
                sock.sendto(response, addr)
        except socket.timeout:
            # Timeout is expected, check shutdown flag
            continue
        except Exception as e:
            if not shutdown_flag.is_set():
                print(f"[DNS] Error: {e}")

    sock.close()
    print("[DNS] Server stopped")


def start_http_server(port=8053):
    """Start HTTP API server"""
    handler = HTTPRequestHandler
    httpd = socketserver.TCPServer(("0.0.0.0", port), handler)
    httpd.timeout = 0.5  # Short timeout to allow checking shutdown flag frequently
    print(f"[HTTP] Server listening on port {port}")

    while not shutdown_flag.is_set():
        try:
            httpd.handle_request()
        except OSError as e:
            # Socket closed or other OS error during shutdown
            if not shutdown_flag.is_set():
                print(f"[HTTP] Error: {e}")
            break
        except Exception as e:
            if not shutdown_flag.is_set():
                print(f"[HTTP] Error: {e}")

    httpd.server_close()
    print("[HTTP] Server stopped")


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print(f"\n[DNS-RESPONDER] Received signal {signum}, shutting down...")
    shutdown_flag.set()
    sys.exit(0)

def main():
    """Start both DNS and HTTP servers"""
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    print("[DNS-RESPONDER] Starting ACME DNS-01 Challenge Responder")

    # Start DNS server in background thread
    dns_thread = threading.Thread(target=start_dns_server, daemon=False)
    dns_thread.start()

    # Start HTTP server in main thread
    try:
        start_http_server()
    except KeyboardInterrupt:
        print("\n[DNS-RESPONDER] Shutting down...")
        shutdown_flag.set()

    # Wait for DNS thread to finish
    dns_thread.join(timeout=2)
    print("[DNS-RESPONDER] Shutdown complete")


if __name__ == '__main__':
    main()
