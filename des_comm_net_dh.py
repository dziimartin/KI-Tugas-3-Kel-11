import os
import sys
import base64
import argparse
import socket
import struct
import json
import time
from typing import Tuple

from tugas2 import (
    bytes_to_bits, bits_to_bytes,
    pad_text, unpad_text,
    des_encrypt_block, des_decrypt_block,
    generate_subkeys,
)
from diffie_hellman import DiffieHellman, derive_des_key

BLOCK_SIZE = 8


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def des_cbc_encrypt(plaintext: bytes, key: str) -> bytes:
    """Encrypt bytes with DES-CBC. Returns bytes: IV || ciphertext."""
    if not isinstance(key, str):
        key = key.decode("utf-8")
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 characters")

    subkeys = generate_subkeys(key)
    iv = os.urandom(BLOCK_SIZE)

    pt = pad_text(plaintext)
    prev = iv
    out = bytearray()

    for i in range(0, len(pt), BLOCK_SIZE):
        block = pt[i:i+BLOCK_SIZE]
        x = _xor_bytes(block, prev)
        bits = bytes_to_bits(x)
        enc_bits = des_encrypt_block(bits, subkeys)
        ct_block = bits_to_bytes(enc_bits)
        out.extend(ct_block)
        prev = ct_block

    return iv + bytes(out)


def des_cbc_decrypt(iv_ct: bytes, key: str) -> bytes:
    if len(iv_ct) < BLOCK_SIZE:
        raise ValueError("ciphertext too short")
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 characters")

    iv, ct = iv_ct[:BLOCK_SIZE], iv_ct[BLOCK_SIZE:]
    subkeys = generate_subkeys(key)
    prev = iv
    out = bytearray()

    for i in range(0, len(ct), BLOCK_SIZE):
        ct_block = ct[i:i+BLOCK_SIZE]
        bits = bytes_to_bits(ct_block)
        dec_bits = des_decrypt_block(bits, subkeys)
        dec = bits_to_bytes(dec_bits)
        pt_block = _xor_bytes(dec, prev)
        out.extend(pt_block)
        prev = ct_block

    return unpad_text(bytes(out))


# ================= TCP helpers =================

def _send_framed(conn: socket.socket, data: bytes) -> None:
    conn.sendall(struct.pack('!I', len(data)) + data)


def _recv_framed(conn: socket.socket) -> bytes:
    hdr = _recvn(conn, 4)
    if not hdr:
        return b''
    (length,) = struct.unpack('!I', hdr)
    return _recvn(conn, length)


def _recvn(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


# ================= DH Handshake for TCP =================

def tcp_dh_handshake_client(conn: socket.socket, bits: int = 512) -> str:
    """
    Client-side DH handshake for TCP.
    Returns the derived 8-byte DES key.
    """
    alice = DiffieHellman(bits=bits)
    alice_pub = alice.generate_keys()
    
    handshake_msg = {
        'p': alice.p,
        'g': alice.g,
        'public_key': alice_pub
    }
    
    handshake_json = json.dumps(handshake_msg)
    _send_framed(conn, handshake_json.encode('utf-8'))
    
    bob_data = _recv_framed(conn)
    bob_msg = json.loads(bob_data.decode('utf-8'))
    bob_pub = bob_msg['public_key']
    
    shared_secret = alice.compute_shared_secret(bob_pub)
    des_key = derive_des_key(shared_secret)
    
    print(f"[TCP DH CLIENT] Handshake complete. Derived DES key: {des_key!r}")
    return des_key


def tcp_dh_handshake_server(conn: socket.socket) -> str:
    """
    Server-side DH handshake for TCP.
    Returns the derived 8-byte DES key.
    """
    alice_data = _recv_framed(conn)
    alice_msg = json.loads(alice_data.decode('utf-8'))
    
    bob = DiffieHellman(
        p=alice_msg['p'],
        g=alice_msg['g']
    )
    bob_pub = bob.generate_keys()
    
    bob_response = {
        'public_key': bob_pub
    }
    
    _send_framed(conn, json.dumps(bob_response).encode('utf-8'))
    
    alice_pub = alice_msg['public_key']
    shared_secret = bob.compute_shared_secret(alice_pub)
    des_key = derive_des_key(shared_secret)
    
    print(f"[TCP DH SERVER] Handshake complete. Derived DES key: {des_key!r}")
    return des_key


# ================= DH Handshake for UDP =================

def udp_dh_handshake_client(sock: socket.socket, server_addr: Tuple[str, int], bits: int = 512) -> str:
    """Client-side DH handshake for UDP"""
    alice = DiffieHellman(bits=bits)
    alice_pub = alice.generate_keys()
    
    handshake_msg = {
        'p': alice.p,
        'g': alice.g,
        'public_key': alice_pub
    }
    
    handshake_json = json.dumps(handshake_msg)
    sock.sendto(handshake_json.encode('utf-8'), server_addr)
    
    sock.settimeout(5.0)
    bob_data, _ = sock.recvfrom(65535)
    bob_msg = json.loads(bob_data.decode('utf-8'))
    bob_pub = bob_msg['public_key']
    
    shared_secret = alice.compute_shared_secret(bob_pub)
    des_key = derive_des_key(shared_secret)
    
    print(f"[UDP DH CLIENT] Handshake complete. Derived DES key: {des_key!r}")
    return des_key


def udp_dh_handshake_server(sock: socket.socket, timeout: float = 5.0) -> Tuple[str, Tuple[str, int]]:
    """
    Server-side DH handshake for UDP.
    Returns (des_key, client_addr)
    """
    sock.settimeout(timeout)
    alice_data, alice_addr = sock.recvfrom(65535)
    alice_msg = json.loads(alice_data.decode('utf-8'))
    
    bob = DiffieHellman(
        p=alice_msg['p'],
        g=alice_msg['g']
    )
    bob_pub = bob.generate_keys()
    
    bob_response = {
        'public_key': bob_pub
    }
    
    sock.sendto(json.dumps(bob_response).encode('utf-8'), alice_addr)
    
    alice_pub = alice_msg['public_key']
    shared_secret = bob.compute_shared_secret(alice_pub)
    des_key = derive_des_key(shared_secret)
    
    print(f"[UDP DH SERVER] Handshake complete. Derived DES key: {des_key!r}")
    return des_key, alice_addr


# ================= DH Handshake for HTTP =================

def http_dh_handshake_client(host: str, port: int, bits: int = 512) -> str:
    """Client-side DH handshake for HTTP"""
    import http.client
    
    alice = DiffieHellman(bits=bits)
    alice_pub = alice.generate_keys()
    
    handshake_msg = {
        'p': alice.p,
        'g': alice.g,
        'public_key': alice_pub
    }
    
    handshake_json = json.dumps(handshake_msg)
    
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("POST", "/dh_init", body=handshake_json, headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    bob_data = resp.read()
    conn.close()
    
    bob_msg = json.loads(bob_data.decode('utf-8'))
    bob_pub = bob_msg['public_key']
    
    shared_secret = alice.compute_shared_secret(bob_pub)
    des_key = derive_des_key(shared_secret)
    
    print(f"[HTTP DH CLIENT] Handshake complete. Derived DES key: {des_key!r}")
    return des_key


# ================= Main TCP functions with DH =================

def run_tcp_server(host: str, port: int, auto_reply: str | None):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        print(f"[TCP SERVER] listening on {host}:{port}")
        conn, addr = s.accept()
        with conn:
            print(f"[TCP SERVER] connected by {addr}")
            
            key = tcp_dh_handshake_server(conn)
            
            frame = _recv_framed(conn)
            if not frame:
                print("[TCP SERVER] no data")
                return
            try:
                msg = des_cbc_decrypt(frame, key).decode('utf-8')
                print(f"[TCP SERVER] RECV: {msg!r}")
            except Exception as e:
                print(f"[TCP SERVER] decrypt error: {e}")
                return

            if auto_reply:
                cipher = des_cbc_encrypt(auto_reply.encode('utf-8'), key)
                _send_framed(conn, cipher)
                print(f"[TCP SERVER] SENT REPLY: {auto_reply!r}")


def run_tcp_client(host: str, port: int, message: str):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        
        key = tcp_dh_handshake_client(s)
        
        cipher = des_cbc_encrypt(message.encode('utf-8'), key)
        _send_framed(s, cipher)
        print(f"[TCP CLIENT] SENT: {message!r}")

        reply = _recv_framed(s)
        if reply:
            try:
                msg = des_cbc_decrypt(reply, key).decode('utf-8')
                print(f"[TCP CLIENT] RECV REPLY: {msg!r}")
            except Exception as e:
                print(f"[TCP CLIENT] decrypt reply error: {e}")


# ================= Main UDP functions with DH =================

def run_udp_server(host: str, port: int, auto_reply: str | None):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((host, port))
        print(f"[UDP SERVER] listening on {host}:{port}")
        
        key, client_addr = udp_dh_handshake_server(s)
        
        s.settimeout(3.0)
        try:
            data, addr = s.recvfrom(65535)
            iv_ct = base64.b64decode(data)
            msg = des_cbc_decrypt(iv_ct, key).decode('utf-8')
            print(f"[UDP SERVER] RECV from {addr}: {msg!r}")
        except socket.timeout:
            print("[UDP SERVER] timeout waiting for message")
            return
        except Exception as e:
            print(f"[UDP SERVER] error: {e}")
            return

        if auto_reply:
            cipher = des_cbc_encrypt(auto_reply.encode('utf-8'), key)
            token = base64.b64encode(cipher)
            s.sendto(token, client_addr)
            print(f"[UDP SERVER] SENT REPLY to {client_addr}: {auto_reply!r}")


def run_udp_client(host: str, port: int, message: str):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        key = udp_dh_handshake_client(s, (host, port))
        
        time.sleep(0.1)
        
        cipher = des_cbc_encrypt(message.encode('utf-8'), key)
        token = base64.b64encode(cipher)
        s.sendto(token, (host, port))
        print(f"[UDP CLIENT] SENT to {(host, port)}: {message!r}")
        
        s.settimeout(3.0)
        try:
            data, addr = s.recvfrom(65535)
            reply_iv_ct = base64.b64decode(data)
            msg = des_cbc_decrypt(reply_iv_ct, key).decode('utf-8')
            print(f"[UDP CLIENT] RECV REPLY from {addr}: {msg!r}")
        except socket.timeout:
            print("[UDP CLIENT] no reply (timeout)")
        except Exception as e:
            print(f"[UDP CLIENT] decrypt reply error: {e}")


# ================= Main HTTP functions with DH =================

from http.server import BaseHTTPRequestHandler, HTTPServer

class HTTPHandler(BaseHTTPRequestHandler):
    server_dh_params: dict = {}
    server_des_key: str = ""
    server_auto_reply: str | None = None

    def do_POST(self):
        if self.path == '/dh_init':
            self.handle_dh_init()
        elif self.path == '/send':
            self.handle_send()
        else:
            self.send_response(404)
            self.end_headers()

    def handle_dh_init(self):
        """Handle DH key exchange init"""
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length)
        
        alice_msg = json.loads(body.decode('utf-8'))
        
        bob = DiffieHellman(p=alice_msg['p'], g=alice_msg['g'])
        bob_pub = bob.generate_keys()
        
        alice_pub = alice_msg['public_key']
        shared_secret = bob.compute_shared_secret(alice_pub)
        des_key = derive_des_key(shared_secret)
        
        HTTPHandler.server_des_key = des_key
        
        bob_response = {'public_key': bob_pub}
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(bob_response).encode('utf-8'))
        
        print(f"[HTTP DH SERVER] Handshake complete. Derived DES key: {des_key!r}")

    def handle_send(self):
        """Handle encrypted message"""
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length)
        
        key = HTTPHandler.server_des_key
        
        if not key:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"handshake not completed")
            return
        
        try:
            iv_ct = base64.b64decode(body)
            msg = des_cbc_decrypt(iv_ct, key).decode('utf-8')
            print(f"[HTTP SERVER] RECV: {msg!r}")
        except Exception as e:
            print(f"[HTTP SERVER] decrypt error: {e}")
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"bad request")
            return

        reply_plain = HTTPHandler.server_auto_reply or ""
        if reply_plain:
            cipher = des_cbc_encrypt(reply_plain.encode('utf-8'), key)
            token = base64.b64encode(cipher)
        else:
            token = b""

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(token)

    def log_message(self, fmt, *args):
        return


def run_http_server(host: str, port: int, auto_reply: str | None):
    HTTPHandler.server_auto_reply = auto_reply
    httpd = HTTPServer((host, port), HTTPHandler)
    print(f"[HTTP SERVER] listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[HTTP SERVER] shutting down")
        httpd.server_close()


def run_http_client(host: str, port: int, message: str):
    import http.client
    
    key = http_dh_handshake_client(host, port)
    
    time.sleep(0.1)
    
    cipher = des_cbc_encrypt(message.encode('utf-8'), key)
    token_b64 = base64.b64encode(cipher)

    conn = http.client.HTTPConnection(host, port, timeout=5)
    headers = {"Content-Type": "text/plain"}
    conn.request("POST", "/send", body=token_b64, headers=headers)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()

    print(f"[HTTP CLIENT] SENT: {message!r} -> status {resp.status}")
    if resp.status == 200 and body:
        try:
            reply_iv_ct = base64.b64decode(body)
            msg = des_cbc_decrypt(reply_iv_ct, key).decode('utf-8')
            print(f"[HTTP CLIENT] RECV REPLY: {msg!r}")
        except Exception as e:
            print(f"[HTTP CLIENT] decrypt reply error: {e}")


# ================= CLI =================

def parse_args():
    p = argparse.ArgumentParser(description="DES + DH key exchange over TCP/UDP/HTTP")
    p.add_argument('--mode', choices=['server', 'client'], required=True)
    p.add_argument('--proto', choices=['tcp', 'udp', 'http'], required=True)
    p.add_argument('--host', default='127.0.0.1', help='bind/target host')
    p.add_argument('--port', type=int, required=True, help='bind/target port')
    p.add_argument('--message', help='message to send (client mode)')
    p.add_argument('--auto-reply', dest='auto_reply', help='optional one-shot reply (server mode)')
    return p.parse_args()


def main():
    a = parse_args()

    if a.mode == 'server':
        if a.proto == 'tcp':
            run_tcp_server(a.host, a.port, a.auto_reply)
        elif a.proto == 'udp':
            run_udp_server(a.host, a.port, a.auto_reply)
        elif a.proto == 'http':
            run_http_server(a.host, a.port, a.auto_reply)
    else:
        if not a.message:
            print("[ERR] client mode requires --message")
            sys.exit(1)
        if a.proto == 'tcp':
            run_tcp_client(a.host, a.port, a.message)
        elif a.proto == 'udp':
            run_udp_client(a.host, a.port, a.message)
        elif a.proto == 'http':
            run_http_client(a.host, a.port, a.message)


if __name__ == '__main__':
    main()
