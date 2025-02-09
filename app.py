import sys
import re
import requests
import pyperclip
import time
import threading
import os
from solders.pubkey import Pubkey  # Corrected Solana public key import
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QLabel, QVBoxLayout

# API Key for external crypto address validation (replace with real key if needed)
API_KEY = 'YOUR_API_KEY'  

def auto_push_to_github():
    print("\n🔄 Auto-updating GitHub with the latest script changes...")
    os.system("git add app.py")
    os.system('git commit -m "Auto-update app.py"')
    os.system("git push origin main")

def auto_pull_from_github():
    print("\n🔄 Checking for updates from GitHub before running the script...")
    os.system("git pull origin main")

# Run Git auto-update before executing the script
auto_push_to_github()
auto_pull_from_github()

class DBRApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Don't Be Retarded (DBR) - Crypto Checker")
        self.setGeometry(100, 100, 400, 300)

        self.label = QLabel("Copy a crypto address and press 'Staking'", self)
        self.button = QPushButton("Staking", self)
        self.button.clicked.connect(self.check_clipboard)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.button)
        self.setLayout(layout)

    def check_clipboard(self):
        address = pyperclip.paste().strip()
        if is_valid_crypto_address(address):
            self.label.setText(f"✅ Valid Address: {address}")
            check_crypto_address(address)  # Perform website checks
        else:
            self.label.setText("❌ Invalid Crypto Address")

# --- Crypto Address Validation ---
def is_valid_solana_address(address):
    try:
        Pubkey.from_string(address)
        return True
    except ValueError:
        return False

def is_valid_crypto_address(address):
    crypto_address_pattern = re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^0x[a-fA-F0-9]{40}$|^[A-Za-z0-9]{32,44}$')

    if not crypto_address_pattern.match(address):
        return False

    if is_valid_solana_address(address):
        return True

    url = 'https://api.checkcryptoaddress.com/wallet-checks'
    headers = {'X-Api-Key': API_KEY, 'Content-Type': 'application/json'}
    data = {'address': address}

    try:
        response = requests.post(url, headers=headers, json=data)
        result = response.json()
        return result.get('valid', False)
    except Exception:
        return False

def check_crypto_address(address):
    print(f"\n🔍 Checking address: {address}\n")

    if address.startswith("0x") and len(address) == 42:
        sources = {
            "Etherscan": f"https://etherscan.io/address/{address}",
            "Dexscreener": f"https://dexscreener.com/search?q={address}",
            "Photon": f"https://photon.network/search/{address}"
        }
    elif address.startswith("1") or address.startswith("3"):
        sources = {
            "Blockchain.com": f"https://www.blockchain.com/explorer/addresses/btc/{address}",
            "Photon": f"https://photon.network/search/{address}"
        }
    else:
        print("❌ Invalid crypto address detected. No checks performed.")
        return

    for source, url in sources.items():
        print(f"✅ {source}: {url}")

# --- Run GUI ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DBRApp()
    window.show()
    sys.exit(app.exec_())
