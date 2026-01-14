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
