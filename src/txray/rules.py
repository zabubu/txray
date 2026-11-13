"""Catalog of every rule txray can emit.

Analyzers create findings through :func:`finding`, which pulls the title and default
severity from this table, so the catalog served by ``txray rules`` and ``GET /v1/rules``
is always the exact set of rules the code can produce.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from txray.models import Finding, Severity


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    rationale: str


_S = Severity
RULES: dict[str, Rule] = {
    r.id: r
    for r in [
        # --- address intelligence -------------------------------------------------
        Rule(
            "INT001",
            _S.CRITICAL,
            "Interaction with a denylisted address",
            "The address is present in the configured denylist (known drainer, scam or "
            "sanctioned address).",
        ),
        Rule(
            "INT002",
            _S.CRITICAL,
            "Address resembles a trusted address (address poisoning)",
            "The address shares its leading and trailing characters with an address from "
            "the user's address book but is a different account. Attackers generate vanity "
            "addresses and seed them into the victim's history so they get copy-pasted.",
        ),
        # --- transactions ---------------------------------------------------------
        Rule(
            "TX001",
            _S.MEDIUM,
            "Unlimited token allowance",
            "The approval amount is effectively infinite; a compromised or malicious spender "
            "can move the whole balance now and in the future.",
        ),
        Rule(
            "TX002",
            _S.HIGH,
            "Allowance granted to an account without code",
            "Legitimate protocols receive approvals with contracts. Approving an EOA lets "
            "whoever holds its key pull the tokens directly.",
        ),
        Rule(
            "TX003",
            _S.HIGH,
            "Operator approval for an entire NFT collection",
            "setApprovalForAll(operator, true) gives the operator control over every token "
            "of the collection held by the signer, including tokens received later.",
        ),
        Rule(
            "TX004",
            _S.MEDIUM,
            "Long-lived or unlimited Permit2 allowance",
            "Permit2 allowances with a far expiration or the maximum uint160 amount stay "
            "usable long after the interaction.",
        ),
        Rule(
            "TX005",
            _S.MEDIUM,
            "Selector not implemented by the target contract",
            "The called function does not appear in the target's dispatcher; the call will "
            "reach the fallback function, which is what disguised drainer calls rely on.",
        ),
        Rule(
            "TX006",
            _S.HIGH,
            "Native value sent to a function named like a drainer lure",
            "Function names such as Claim(), SecurityUpdate() or Connect() are deployed by "
            "drainer kits to receive ETH from victims of fake airdrop pages.",
        ),
        Rule(
            "TX007",
            _S.HIGH,
            "Tokens sent to the token contract itself",
            "Most token contracts cannot send back tokens transferred to their own address; "
            "the funds are usually lost.",
        ),
        Rule(
            "TX008",
            _S.LOW,
            "Calldata sent to an account without code",
            "The destination has no code, so the calldata is not executed. Used to carry "
            "messages, but also by phishing pages that misrepresent what is being signed.",
        ),
        Rule(
            "TX009",
            _S.HIGH,
            "Called function can reach SELFDESTRUCT or DELEGATECALL",
            "The control-flow graph of the called function reaches an instruction that can "
            "sweep the contract balance or execute arbitrary code.",
        ),
        Rule("TX010", _S.INFO, "Contract deployment", "The transaction creates a contract."),
        Rule(
            "TX011",
            _S.INFO,
            "Batched calls",
            "The call wraps several inner calls; each one is analysed separately.",
        ),
        Rule(
            "TX012",
            _S.MEDIUM,
            "Known selector with non-canonical arguments",
            "The selector matches a known function but the arguments are not a valid ABI "
            "encoding. Wallet UIs may display something different from what executes.",
        ),
        # --- EIP-712 typed data ---------------------------------------------------
        Rule(
            "SIG001",
            _S.HIGH,
            "Signature domain targets another chain",
            "The domain chainId differs from the chain the wallet is connected to.",
        ),
        Rule(
            "SIG002",
            _S.HIGH,
            "verifyingContract has no code",
            "The domain names a verifying contract that does not exist on this chain.",
        ),
        Rule(
            "SIG003",
            _S.CRITICAL,
            "Domain impersonates a well-known protocol",
            "The domain name is one of a known protocol (Permit2, Seaport) but the "
            "verifyingContract is not that protocol's canonical deployment.",
        ),
        Rule(
            "SIG010",
            _S.MEDIUM,
            "Off-chain token approval (permit)",
            "Signing this message grants an allowance without any on-chain transaction; "
            "it does not appear in the wallet's transaction history.",
        ),
        Rule(
            "SIG011",
            _S.HIGH,
            "Unlimited allowance in permit signature",
            "The permit authorizes the maximum amount.",
        ),
        Rule(
            "SIG012",
            _S.CRITICAL,
            "Permit spender is an account without code",
            "A signed permit for an EOA is the usual shape of a drainer request.",
        ),
        Rule(
            "SIG013",
            _S.MEDIUM,
            "Long-lived permit",
            "The permit deadline or allowance expiration is far in the future.",
        ),
        Rule(
            "SIG020",
            _S.MEDIUM,
            "Permit2 allowance signature",
            "Grants an allowance through Permit2 for one or more tokens.",
        ),
        Rule(
            "SIG021",
            _S.CRITICAL,
            "Permit2 batch approval to an unknown spender",
            "A batch permit covering several tokens for a spender that is not a known "
            "router is the signature format used by most Permit2 drainers.",
        ),
        Rule(
            "SIG022",
            _S.HIGH,
            "Permit2 signature transfer",
            "PermitTransferFrom lets the spender move the tokens immediately; nothing else "
            "has to be signed.",
        ),
        Rule(
            "SIG030",
            _S.CRITICAL,
            "Marketplace order gives assets away",
            "The Seaport order offers assets while the offerer receives nothing (or only "
            "zero amounts) in return.",
        ),
        Rule(
            "SIG031",
            _S.HIGH,
            "Seaport bulk order signature",
            "One signature authorizes a whole tree of orders; wallets typically display "
            "only the root.",
        ),
        Rule(
            "SIG040",
            _S.MEDIUM,
            "Typed data grants permissions",
            "Unrecognized typed data containing spender/operator/delegate style fields.",
        ),
        # --- personal_sign / eth_sign -------------------------------------------
        Rule(
            "MSG001",
            _S.CRITICAL,
            "Blind signature of a raw hash (eth_sign)",
            "eth_sign signs an arbitrary 32-byte hash, which can be the hash of a "
            "transaction transferring the signer's assets.",
        ),
        Rule(
            "MSG002",
            _S.HIGH,
            "personal_sign of a 32-byte binary value",
            "The message is not text but a 32-byte value, typically a hash the user cannot verify.",
        ),
        Rule(
            "MSG003",
            _S.MEDIUM,
            "personal_sign of non-text data",
            "The message is not valid UTF-8 text.",
        ),
        Rule(
            "MSG010",
            _S.HIGH,
            "Sign-In with Ethereum domain mismatch",
            "The SIWE message is for a different domain than the requesting site: the "
            "page may be relaying a login challenge from another service.",
        ),
        Rule(
            "MSG011",
            _S.MEDIUM,
            "SIWE address differs from the signer",
            "The address in the SIWE message is not the account asked to sign.",
        ),
        Rule(
            "MSG012",
            _S.MEDIUM,
            "SIWE chain differs from the connected chain",
            "The Chain ID in the SIWE message is not the wallet's current chain.",
        ),
        Rule(
            "MSG013",
            _S.LOW,
            "SIWE message outside its validity window",
            "Expired or not yet valid according to Expiration Time / Not Before.",
        ),
        Rule(
            "MSG014",
            _S.MEDIUM,
            "Malformed SIWE message",
            "The message announces itself as Sign-In with Ethereum but violates EIP-4361.",
        ),
        # --- bytecode ---------------------------------------------------------------
        Rule(
            "BC001",
            _S.MEDIUM,
            "SELFDESTRUCT reachable",
            "The contract can execute SELFDESTRUCT, which sends its whole ETH balance to an "
            "arbitrary address.",
        ),
        Rule(
            "BC002",
            _S.MEDIUM,
            "DELEGATECALL to a dynamic target",
            "Code from another address runs with this contract's storage and balance.",
        ),
        Rule(
            "BC003",
            _S.LOW,
            "Uses tx.origin",
            "ORIGIN-based authorization can be abused by any contract the owner interacts with.",
        ),
        Rule(
            "BC004",
            _S.INFO,
            "EIP-1167 minimal proxy",
            "Clone forwarding to a fixed implementation.",
        ),
        Rule(
            "BC005",
            _S.MEDIUM,
            "Upgradeable proxy",
            "The executed code can be replaced by whoever controls the upgrade mechanism.",
        ),
        Rule(
            "BC006",
            _S.LOW,
            "Privileged administrative functions",
            "The contract exposes functions such as mint, pause, blacklist or fee setters.",
        ),
        Rule(
            "BC007",
            _S.HIGH,
            "Metamorphic contract pattern",
            "CREATE2 combined with SELFDESTRUCT allows redeploying different code at the "
            "same address.",
        ),
        Rule(
            "BC008",
            _S.INFO,
            "Partial control-flow analysis",
            "Some jump targets could not be resolved; reachability results are lower bounds.",
        ),
        Rule("BC009", _S.INFO, "Hard-coded addresses", "PUSH20 constants embedded in the code."),
        Rule("BC010", _S.INFO, "No code at address", "The account is an EOA or was destroyed."),
    ]
}


def finding(
    rule_id: str,
    detail: str,
    *,
    severity: Severity | None = None,
    **evidence: Any,
) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        severity=severity if severity is not None else rule.severity,
        title=rule.title,
        detail=detail,
        evidence=evidence,
    )
