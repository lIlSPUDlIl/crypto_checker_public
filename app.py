import re
import requests
import pyperclip
import time
import threading
from solders.pubkey import Pubkey  # Corrected Solana public key import

# API Key for external crypto address validation (replace with real key if needed)
API_KEY = 'YOUR_API_KEY'  

def is_valid_solana_address(address):
    """
    Validates if the provided address is a valid Solana address.
    """
    try:
        public_key = Pubkey.from_string(address)
        print("✅ The address is a valid Solana address.")
        return True
    except ValueError:
        print("❌ The address is not a valid Solana address.")
        return False

def is_valid_crypto_address(address):
    """
    Validates if the provided address is a cryptocurrency address.
    """
    # General regex pattern for detecting common crypto addresses
    crypto_address_pattern = re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^0x[a-fA-F0-9]{40}$|^[A-Za-z0-9]{32,44}$')

    if not crypto_address_pattern.match(address):
        print("❌ The address does not match common crypto address formats.")
        return False

    # Check if it's a Solana address
    if is_valid_solana_address(address):
        return True

    # Fallback: Use an external API to validate unknown addresses
    url = 'https://api.checkcryptoaddress.com/wallet-checks'
    headers = {'X-Api-Key': API_KEY, 'Content-Type': 'application/json'}
    data = {'address': address}

    try:
        response = requests.post(url, headers=headers, json=data)
        result = response.json()

        if result.get('valid'):
            network = result.get('network', {}).get('name', 'Unknown Network')
            print(f"✅ The address is valid and belongs to the {network} network.")
            return True
        else:
            print("❌ The address is not a valid cryptocurrency address.")
            return False

    except Exception as e:
        print(f"⚠️ Error validating address: {e}")
        return False

def check_crypto_address(address):
    """
    Checks a crypto address against multiple sources.
    """
    print(f"\n🔍 Checking address: {address}\n")

    # Ethereum & Tokens (Etherscan, Dexscreener)
    if address.startswith("0x") and len(address) == 42:
        sources = {
            "Etherscan": f"https://etherscan.io/address/{address}",
            "Dexscreener": f"https://dexscreener.com/search?q={address}",
            "Photon": f"https://photon.network/search/{address}"  # Replace with correct Photon URL
        }

    # Bitcoin (Blockchain.com)
    elif address.startswith("1") or address.startswith("3"):
        sources = {
            "Blockchain.com": f"https://www.blockchain.com/explorer/addresses/btc/{address}",
            "Photon": f"https://photon.network/search/{address}"  # Replace with correct Photon URL
        }

    # If the address is invalid, do not proceed
    else:
        print("❌ Invalid crypto address detected. No checks performed.")
        return

    # Print the sources where the address will be checked
    for source, url in sources.items():
        print(f"✅ {source}: {url}")

stop_monitoring = False  # Global flag to stop monitoring

def listen_for_stop():
    """Waits for user input in a separate thread to stop monitoring."""
    global stop_monitoring
    while True:
        command = input("\n➡️ Type 'stop' to stop monitoring: ").strip().lower()
        if command == "stop":
            stop_monitoring = True
            print("\n🛑 Clipboard monitoring stopped.")
            break

def monitor_clipboard():
    global stop_monitoring
    last_clipboard = ""

    print("\n➡️ Type 'start' to begin monitoring, 'stop' to exit.")
    command = input("\n👉 Type 'start' to begin monitoring: ").strip().lower()

    if command == "start":
        print("\n🔍 Monitoring clipboard for crypto addresses... (Type 'stop' to end)")
        stop_monitoring = False

        # Start a separate thread to listen for "stop" command
        stop_thread = threading.Thread(target=listen_for_stop, daemon=True)
        stop_thread.start()

        while not stop_monitoring:
            clipboard_content = pyperclip.paste().strip()

            if clipboard_content != last_clipboard and clipboard_content:
                if is_valid_crypto_address(clipboard_content):
                    last_clipboard = clipboard_content
                    print(f"📋 New valid crypto address copied: {clipboard_content}")
                    check_crypto_address(clipboard_content)
                else:
                    print(f"🚫 Invalid crypto address: {clipboard_content}")

            time.sleep(3)  # Check clipboard every 3 seconds

if __name__ == "__main__":
    monitor_clipboard()

