import re
from dataclasses import dataclass, field
from typing import List

@dataclass
class Vulnerability:
    severity: str
    title: str
    line: int
    description: str
    recommendation: str

PATTERNS = [
    (r"\.call\.value\(", "CRITICAL", "Reentrancy Risk",
     "Use of .call.value() without reentrancy guard",
     "Add nonReentrant modifier or use pull-payment pattern"),
    (r"tx\.origin", "HIGH", "tx.origin Authentication",
     "tx.origin used for authentication is exploitable",
     "Use msg.sender instead of tx.origin"),
    (r"block\.timestamp", "MEDIUM", "Timestamp Dependence",
     "block.timestamp can be manipulated by miners ±15s",
     "Use block.number or Chainlink VRF for randomness"),
    (r"selfdestruct|suicide", "HIGH", "Selfdestruct Usage",
     "Contract can be destroyed, losing all funds",
     "Remove selfdestruct or add multi-sig guard"),
    (r"assembly\s*{", "MEDIUM", "Inline Assembly",
     "Inline assembly bypasses Solidity safety checks",
     "Review assembly block carefully for memory safety"),
    (r"\.transfer\(|\.send\(", "LOW", "Transfer/Send Gas Limit",
     ".transfer() and .send() forward only 2300 gas",
     "Use .call{value:}() with reentrancy guard"),
]

def audit_contract(source_code: str) -> List[Vulnerability]:
    vulns = []
    for i, line in enumerate(source_code.splitlines(), 1):
        for pattern, severity, title, desc, rec in PATTERNS:
            if re.search(pattern, line):
                vulns.append(Vulnerability(severity, title, i, desc, rec))
    return vulns

DEMO_CONTRACT = """
pragma solidity ^0.8.0;
contract VulnerableBank {
    mapping(address => uint) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call.value(amount)("");
        require(ok);
        balances[msg.sender] -= amount;
    }
    function getOwner() public view returns (address) { return tx.origin; }
    function destroy() public { selfdestruct(payable(msg.sender)); }
}
"""

if __name__ == "__main__":
    vulns = audit_contract(DEMO_CONTRACT)
    print(f"{'='*60}")
    print(f"Smart Contract Audit Report – {len(vulns)} issues found")
    print(f"{'='*60}")
    for v in vulns:
        icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}.get(v.severity,"⚪")
        print(f"\n{icon} [{v.severity}] Line {v.line}: {v.title}")
        print(f"   Issue : {v.description}")
        print(f"   Fix   : {v.recommendation}")
