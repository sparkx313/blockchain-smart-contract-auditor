# 🔍 Blockchain Smart Contract Auditor

AI-powered static analysis tool for Solidity smart contracts.

## Vulnerability Detection
- ✅ Reentrancy attacks
- ✅ Integer overflow/underflow
- ✅ Access control issues
- ✅ Unchecked return values
- ✅ Front-running vulnerabilities
- ✅ Flash loan attack vectors

## Usage
```bash
pip install -r requirements.txt
python auditor.py --contract MyToken.sol --report html
```

## Severity Levels
| Level | Color | Description |
|-------|-------|-------------|
| CRITICAL | 🔴 | Immediate fund loss risk |
| HIGH | 🟠 | Significant vulnerability |
| MEDIUM | 🟡 | Exploitable under conditions |
| LOW | 🔵 | Best practice violation |
