# NTLMv2 Random Session Key Calculator 🔐

A Python tool to calculate NTLMv2 Random Session Keys for decrypting SMB traffic in Wireshark.

## 📖 Description

This tool calculates the Random Session Key used in NTLMv2 authentication, which is essential for decrypting SMB2/SMB3 network traffic in Wireshark. It supports both password-based and NTLM hash-based calculations.

## ✨ Features

- ✅ Calculate NTLMv2 Random Session Keys
- ✅ Support for both password and NTLM hash inputs
- ✅ Interactive command-line interface
- ✅ Generate Wireshark-ready decryption strings
- ✅ Copy results to clipboard automatically
- ✅ Input validation and error handling
- ✅ SMB2 and SMB3 compatible

## 🛠️ Installation

### Prerequisites

- Python 3.6 or higher
- pip package manager

### Install Dependencies
```bash
# Install required package
pip install pycryptodome

# Optional: For clipboard support
pip install pyperclip
```

**On Kali Linux / Debian / Ubuntu:**
```bash
sudo apt install python3-pycryptodome python3-pyperclip
```

### Clone the Repository
```bash
git clone https://github.com/ItachiSN/ntlm-session-key-calculator.git
cd ntlm-session-key-calculator
chmod +x SMB-NTLM-RANDOM-KEY-CALCULATOR.py
```

## 🚀 Usage

### Run the Tool
```bash
python3 SMB-NTLM-RANDOM-KEY-CALCULATOR.py
```

### Interactive Mode

The tool will guide you through:

1. **Choose authentication method:**
   - Option 1: Use password
   - Option 2: Use NTLM hash

2. **Enter credentials:**
   - Username
   - Domain/Workgroup
   - Password OR NTLM hash

3. **Provide Wireshark values:**
   - NTProofStr (32 hex characters)
   - Encrypted Session Key (hex string)

### Example Output
```
✅ SUCCESS!

Random Session Key:
  f1e2d3c4b5a69788776655443322110

For Wireshark SMB2 Decryption:
  administrator:CORP:f1e2d3c4b5a69788776655443322110

📋 Copied to clipboard!
```

## 🔍 Finding Values in Wireshark

### Step 1: Filter NTLM Packets

In Wireshark, apply this filter:
```
ntlmssp.messagetype == 3
```

### Step 2: Extract Required Values

Open an NTLM AUTHENTICATE packet and navigate to:

1. **NTProofStr:**
   - Path: `NTLMSSP → NTLMv2 Response → NTProofStr`
   - Copy the 32 hex characters

2. **Encrypted Session Key:**
   - Path: `NTLMSSP → Encrypted Random Session Key`
   - Copy the hex string

### Step 3: Configure Wireshark

1. Go to: **Edit → Preferences → Protocols → SMB2**
2. Click **Edit** next to "Secret session keys for decryption"
3. Add the calculated key:
```
   username:domain:session_key
```
4. Click **OK** to decrypt SMB traffic

## 🔒 SMB3 Encryption Support

### Compatibility

This tool calculates the NTLMv2 Random Session Key which works for:
- ✅ **SMB2** (all versions)
- ✅ **SMB3** with signing only
- ⚠️ **SMB3** with encryption (limited support)

### SMB3 Encryption Notes

SMB3 uses AES encryption and derives additional keys from the session key:
- **SMB 3.0**: AES-128-CCM
- **SMB 3.1.1**: AES-128-GCM

The calculated session key serves as the base, but SMB3 derives additional keys for encryption:
- **Encryption Key**
- **Decryption Key**
- **Signing Key**

### What Works

✅ SMB3 traffic with NTLM authentication (unencrypted)  
✅ SMB3 with signing enabled only  
✅ SMB3 without encryption flags  

### What May Not Work

❌ SMB3 with **mandatory encryption** (flag `SMB2_GLOBAL_CAP_ENCRYPTION`)  
❌ Some recent Windows Server implementations with advanced encryption  

### Workaround for Encrypted SMB3

If Wireshark fails to decrypt SMB3 traffic after adding the session key:

1. **Capture from client side** - Client-side captures sometimes work better
2. **Check encryption flags** - Verify if `SMB2_GLOBAL_CAP_ENCRYPTION` is set
3. **Memory dumps** - Extract encryption keys directly from memory
4. **Wireshark version** - Ensure you have the latest Wireshark with updated SMB3 support
5. **Disable encryption** - If testing in a lab, disable SMB encryption:
```powershell
   Set-SmbServerConfiguration -EncryptData $false -Force
```

## 📝 Example Usage

### Using Password
```
Username: administrator
Domain: CORP
Password: P@ssw0rd123
NTProofStr: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
Encrypted Session Key: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d

Result: administrator:CORP:f1e2d3c4b5a69788776655443322110
```

### Using NTLM Hash
```
Username: administrator
Domain: CORP
NTLM Hash: 209c6174da490caeb422f3fa5a7ae634
NTProofStr: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
Encrypted Session Key: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d

Result: administrator:CORP:f1e2d3c4b5a69788776655443322110
```

## 🐛 Troubleshooting

### Dependency Error

**Error:** `Required package 'pycryptodome' is not installed`

**Solution:**
```bash
pip install pycryptodome
```

### Invalid Hexadecimal Input

**Error:** `Invalid hexadecimal format`

**Solution:** Ensure hex values contain only 0-9 and a-f. The tool accepts formats with `:`, `-`, `.` or spaces.

### Wireshark Not Decrypting

**Possible causes:**
- Incorrect username/domain format
- Wrong NTProofStr or Encrypted Session Key
- Multiple sessions require multiple keys
- SMB3 encryption is enabled

**Solution:** 
- Verify all input values and packet selection
- Check if SMB3 encryption flags are present
- Try capturing from the client side
- Ensure Wireshark is up to date

### SMB3 Encrypted Traffic Not Decrypting

**Error:** Traffic remains encrypted after adding session key

**Solution:**
- Check for `SMB2_GLOBAL_CAP_ENCRYPTION` capability flag
- Verify the SMB dialect negotiated (3.0, 3.0.2, 3.1.1)
- Consider disabling SMB encryption in test environments
- Use alternative methods like memory dumps for fully encrypted sessions

## 📚 How It Works

The tool implements the NTLMv2 session key derivation:

1. **Calculate NTLM Hash** (if using password):
```
   NT_Hash = MD4(UTF-16LE(password))
```

2. **Calculate NTLMv2 Hash:**
```
   NTLMv2_Hash = HMAC-MD5(NT_Hash, UPPERCASE(username) + domain)
```

3. **Calculate Key Exchange Key:**
```
   KeyExchangeKey = HMAC-MD5(NTLMv2_Hash, NTProofStr)
```

4. **Decrypt Random Session Key:**
```
   RandomSessionKey = RC4(KeyExchangeKey, EncryptedRandomSessionKey)
```

### SMB3 Key Derivation (Info)

For SMB3 encrypted traffic, additional keys are derived:
```
EncryptionKey = KDF(SessionKey, "SMB2AESCCM" or "SMB2AESGCM", context)
DecryptionKey = KDF(SessionKey, "SMB2AESCCM" or "SMB2AESGCM", context)
SigningKey = KDF(SessionKey, "SMB2AESCMAC" or "SMB2AESHMAC", context)
```

Wireshark handles this derivation automatically when the base session key is correct.

## ⚠️ Disclaimer

This tool is intended for:
- Authorized security testing
- Network troubleshooting
- Educational purposes
- Legitimate forensic analysis

**Warning:** Only use on systems you own or have explicit permission to analyze. Unauthorized access is illegal.

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Feel free to submit issues or pull requests.

## 📚 References

- [MS-NLMP: NT LAN Manager (NTLM) Authentication Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)
- [MS-SMB2: Server Message Block (SMB) Protocol Versions 2 and 3](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- [Wireshark SMB2 Decryption](https://wiki.wireshark.org/SMB2#Decryption)

## 📧 Contact

For questions or issues, please open an issue on GitHub.

---

**Made for the cybersecurity community** 🛡️
