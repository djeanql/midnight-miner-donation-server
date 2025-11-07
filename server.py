import http.server
import socketserver
import json
import os
import threading
from datetime import datetime, timezone, timedelta
from pycardano import PaymentSigningKey, PaymentVerificationKey, Address, Network
import requests
import cbor2

# Rate limiting state
rate_limit_tracker = {}
RATE_LIMIT_SECONDS = 10
API_BASE = "https://scavenger.prod.gd.midnighttge.io/"

class WalletManager:

    def __init__(self, wallet_file="developer_wallets.json"):
        self.wallet_file = wallet_file
        self.wallets = []
        self._lock = threading.Lock()
        if os.path.exists(self.wallet_file):
            with open(self.wallet_file, 'r') as f:
                self.wallets = json.load(f)

    def generate_wallet(self):
        signing_key = PaymentSigningKey.generate()
        verification_key = PaymentVerificationKey.from_signing_key(signing_key)
        address = Address(verification_key.hash(), network=Network.MAINNET)
        pubkey = bytes(verification_key.to_primitive()).hex()

        return {
            'address': str(address),
            'pubkey': pubkey,
            'signing_key': signing_key.to_primitive().hex(),
            'created_at': datetime.now(timezone.utc).isoformat()
        }

    def save_wallets(self):
        """Save current wallet list to file"""
        with self._lock:
            with open(self.wallet_file, 'w') as f:
                json.dump(self.wallets, f, indent=2)

    def add_wallet(self, wallet_data):
        """Add a new wallet to the manager"""
        with self._lock:
            self.wallets.append(wallet_data)
        self.save_wallets()

    def sign_terms(self, wallet_data, api_base):
        try:
            response = requests.get(f"{api_base}/TandC")
            message = response.json()["message"]
        except:
            message = "I agree to abide by the terms and conditions as described in version 1-0 of the Midnight scavenger mining process: 281ba5f69f4b943e3fb8a20390878a232787a04e4be22177f2472b63df01c200"

        signing_key_bytes = bytes.fromhex(wallet_data['signing_key'])
        signing_key = PaymentSigningKey.from_primitive(signing_key_bytes)
        address = Address.from_primitive(wallet_data['address'])

        address_bytes = bytes(address.to_primitive())

        protected = {1: -8, "address": address_bytes}
        protected_encoded = cbor2.dumps(protected)
        unprotected = {"hashed": False}
        payload = message.encode('utf-8')

        sig_structure = ["Signature1", protected_encoded, b'', payload]
        to_sign = cbor2.dumps(sig_structure)
        signature_bytes = signing_key.sign(to_sign)

        cose_sign1 = [protected_encoded, unprotected, payload, signature_bytes]
        wallet_data['signature'] = cbor2.dumps(cose_sign1).hex()

    def _register_wallet_with_api(self, wallet_data, api_base):
        """Register a wallet with the API. Returns True if successful or already registered."""
        url = f"{api_base}/register/{wallet_data['address']}/{wallet_data['signature']}/{wallet_data['pubkey']}"
        try:
            response = requests.post(url, json={})
            response.raise_for_status()
            return True
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400:
                error_msg = e.response.json().get('message', '')
                if 'already' in error_msg.lower():
                    return True
            return False
        except Exception:
            return False

    def register_wallet(self, wallet_data):
        self.sign_terms(wallet_data, API_BASE)
        return self._register_wallet_with_api(wallet_data, API_BASE)

class MyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/get_dev_address':
            client_ip = self.client_address[0]
            current_time = datetime.now(timezone.utc)

            if client_ip in rate_limit_tracker:
                last_request_time = rate_limit_tracker[client_ip]
                if current_time - last_request_time < timedelta(seconds=RATE_LIMIT_SECONDS):
                    self.send_response(429)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    response = {'error': 'Too Many Requests'}
                    self.wfile.write(json.dumps(response).encode('utf-8'))
                    return

            rate_limit_tracker[client_ip] = current_time

            try:
                # Generate a new wallet
                new_wallet = wallet_manager.generate_wallet()

                # Register the wallet with the Midnight API
                if wallet_manager.register_wallet(new_wallet):
                    print(f"Successfully registered wallet: {new_wallet['address']}")
                else:
                    print(f"Failed to register wallet: {new_wallet['address']}")

                # Add the new wallet to the manager and save it
                wallet_manager.add_wallet(new_wallet)

                # Prepare the response
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {'address': new_wallet['address']}
                self.wfile.write(json.dumps(response).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {'error': str(e)}
                self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Not Found')

if __name__ == '__main__':
    wallet_manager = WalletManager()

    PORT = 8000
    with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
        print("serving at port", PORT)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.server_close()
