#!/usr/bin/env python3
"""
NTLMv2 Random Session Key Calculator
Author: [Votre Nom]
Description: Calculate NTLMv2 Random Session Key for SMB decryption in Wireshark
"""

import hashlib
import hmac
import sys
from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import MD4


def clean_hex(input_str: str) -> str:
    """Clean hexadecimal string by removing common separators."""
    if not input_str:
        return ""
    return input_str.replace(':', '').replace(' ', '').replace('-', '').replace('.', '').lower()


def calculate_session_key(username: str, domain: str, ntproofstr: str, 
                         enc_key: str, password: str = None, 
                         ntlm_hash: str = None) -> tuple:
    """
    Calculate NTLMv2 Random Session Key.
    
    Args:
        username: Target username
        domain: Domain or workgroup
        ntproofstr: NTProofStr from Wireshark (32 hex chars)
        enc_key: Encrypted Session Key from Wireshark (hex)
        password: User password (optional, use password or ntlm_hash)
        ntlm_hash: NTLM hash (32 hex chars) (optional, use password or ntlm_hash)
    
    Returns:
        tuple: (session_key_hex, error_message) or (None, error_message)
    """
    try:
        # Get NTLM hash
        if password:
            # Calculate hash from password
            md4 = MD4.new()
            md4.update(password.encode("utf-16le"))
            nt_hash = md4.digest()
        elif ntlm_hash:
            # Use provided hash
            nt_hash = bytes.fromhex(ntlm_hash)
            if len(nt_hash) != 16:
                return None, "NTLM hash must be 16 bytes (32 hex characters)"
        else:
            return None, "Either password or NTLM hash must be provided"
        
        # Calculate NTv2 hash (HMAC-MD5)
        username_bytes = username.upper().encode("utf-16le")
        domain_bytes = domain.encode("utf-16le")
        respNTKey = hmac.new(nt_hash, username_bytes + domain_bytes, hashlib.md5).digest()
        
        # Calculate KeyExchangeKey
        NTproofStr = bytes.fromhex(ntproofstr)
        KeyExchKey = hmac.new(respNTKey, NTproofStr, hashlib.md5).digest()
        
        # Decrypt Random Session Key using RC4
        enc_session_key = bytes.fromhex(enc_key)
        cipher = ARC4.new(KeyExchKey)
        random_session_key = cipher.decrypt(enc_session_key)
        
        return random_session_key.hex(), None
        
    except ValueError as e:
        return None, f"Invalid hexadecimal input: {str(e)}"
    except Exception as e:
        return None, f"Calculation error: {str(e)}"


def get_input(prompt: str, required: bool = True, is_hex: bool = False, 
              hex_length: int = None) -> str:
    """Get and validate user input."""
    while True:
        value = input(prompt).strip()
        
        if not value and required:
            print("ERROR: This field is required")
            continue
        
        if is_hex:
            value = clean_hex(value)
            if hex_length and len(value) != hex_length:
                print(f"ERROR: Must be {hex_length} hex characters (got {len(value)})")
                continue
            
            try:
                bytes.fromhex(value)
            except ValueError:
                print("ERROR: Invalid hexadecimal format")
                continue
        
        return value


def main():
    """Main interactive function."""
    print("\n" + "="*60)
    print("NTLMv2 RANDOM SESSION KEY CALCULATOR")
    print("="*60)
    print("Calculate session keys for SMB traffic decryption in Wireshark")
    print("="*60)
    
    try:
        while True:
            print("\n" + "="*60)
            print("MAIN MENU")
            print("="*60)
            print("1. Calculate Session Key")
            print("2. Exit")
            print("-" * 60)
            
            choice = input("\nSelect option (1-2): ").strip()
            
            if choice == '1':
                calculate_session()
            elif choice == '2':
                print("\n" + "="*60)
                print("Goodbye! 👋")
                print("="*60 + "\n")
                break
            else:
                print("\nInvalid choice. Please enter 1 or 2.")
    
    except KeyboardInterrupt:
        print("\n\nProgram interrupted. Goodbye!\n")


def calculate_session():
    """Handle a single session calculation."""
    print("\n" + "="*60)
    print("SESSION CALCULATION")
    print("="*60)
    
    # Get authentication method
    print("\nAuthentication Method:")
    print("1. Use password")
    print("2. Use NTLM hash")
    print("-" * 60)
    
    while True:
        method = input("\nSelect method (1-2): ").strip()
        if method in ['1', '2']:
            break
        print("Please enter 1 or 2")
    
    print("\n" + "-"*60)
    print("USER INFORMATION")
    print("-" * 60)
    
    # Get user information
    username = get_input("\nUsername: ", required=True)
    domain = get_input("Domain: ", required=True)
    
    # Get credentials
    if method == '1':
        print("\n" + "-"*60)
        print("PASSWORD INPUT")
        print("-" * 60)
        print("Note: Password will be visible as you type")
        password = get_input("\nPassword: ", required=True)
        ntlm_hash = None
    else:
        print("\n" + "-"*60)
        print("NTLM HASH INPUT")
        print("-" * 60)
        print("Note: NTLM hash is 32 hexadecimal characters")
        ntlm_hash = get_input("\nNTLM Hash: ", required=True, is_hex=True, hex_length=32)
        password = None
    
    # Get Wireshark values
    print("\n" + "="*60)
    print("WIRESHARK VALUES")
    print("="*60)
    print("\nThese values can be found in Wireshark:")
    print("1. Filter for 'ntlmssp.messagetype == 3'")
    print("2. Look for 'NTProofStr' (32 hex characters)")
    print("3. Look for 'Encrypted Random Session Key'")
    print("-" * 60)
    
    ntproofstr = get_input("\nNTProofStr: ", required=True, is_hex=True, hex_length=32)
    enc_key = get_input("Encrypted Session Key: ", required=True, is_hex=True)
    
    # Calculate
    print("\n" + "="*60)
    print("CALCULATING...")
    print("="*60)
    
    session_key, error = calculate_session_key(
        username, domain, ntproofstr, enc_key, password, ntlm_hash
    )
    
    # Display results
    print("\n" + "="*60)
    print("RESULTS")
    print("="*60)
    
    if error:
        print(f"\n❌ ERROR: {error}")
    else:
        print(f"\n✅ SUCCESS!")
        print(f"\nRandom Session Key:")
        print(f"  {session_key}")
        
        print(f"\nFor Wireshark SMB2 Decryption:")
        print(f"  {username}:{domain}:{session_key}")
        
        # Try to copy to clipboard
        try:
            import pyperclip
            pyperclip.copy(f"{username}:{domain}:{session_key}")
            print(f"\n📋 Copied to clipboard!")
        except ImportError:
            pass
        
        print(f"\nUsage in Wireshark:")
        print(f"  1. Edit → Preferences → Protocols → SMB2")
        print(f"  2. Click 'Edit' next to 'Decryption keys'")
        print(f"  3. Add: {username}:{domain}:{session_key}")
    
    print("\n" + "="*60)


if __name__ == "__main__":
    # Check dependencies
    try:
        from Cryptodome.Cipher import ARC4
        from Cryptodome.Hash import MD4
    except ImportError:
        print("\n" + "="*60)
        print("DEPENDENCY ERROR")
        print("="*60)
        print("\nRequired package 'pycryptodome' is not installed.")
        print("\nTo install:")
        print("  pip install pycryptodome")
        print("\nOr on Kali Linux:")
        print("  sudo apt install python3-pycryptodome")
        print("\n" + "="*60)
        sys.exit(1)
    
    main()
