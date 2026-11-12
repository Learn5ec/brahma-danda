#!/usr/bin/env python3
"""Reconstruct the HOST's `ufw status` To/Action/From table from read-only files.

Why this exists
---------------
`ufw status verbose` executed inside the scanner container reads the CONTAINER's
own /etc/ufw (the image ships its own), NOT the host being audited — and an
inactive UFW prints no per-port rules at all. So that probe can never show the
host's real firewall. We cannot `chroot /host ufw` either (the container drops
CAP_SYS_CHROOT). The correct, minimal-privilege path is to parse the host's UFW
rule files directly from the read-only /host mount and render them in the exact
`ufw status` table form, including the per-source IP and the `# comment` that
ufw stores inline in each rule.

Input (all optional — missing files degrade gracefully):
  <HOST_ROOT>/etc/ufw/ufw.conf         -> enabled state
  <HOST_ROOT>/etc/default/ufw          -> default INPUT/OUTPUT policies
  <HOST_ROOT>/etc/ufw/user.rules       -> IPv4 ruleset
  <HOST_ROOT>/etc/ufw/user6.rules      -> IPv6 ruleset
Reconciliation inputs (already produced by run_scan.sh, from the host netns):
  <IPT>  (iptables.txt)  <NFT> (nftables.txt)

Output: a human/LLM-readable report on stdout.
Stdlib only; no third-party deps.

Usage: ufw_rules_report.py [HOST_ROOT] [IPT_TXT] [NFT_TXT]
"""
import os
import shlex
import sys

HOST_ROOT = sys.argv[1] if len(sys.argv) > 1 else "/host"
IPT_TXT = sys.argv[2] if len(sys.argv) > 2 else ""
NFT_TXT = sys.argv[3] if len(sys.argv) > 3 else ""

# iptables target -> ufw status action verb
TARGET_ACTION = {
    "ACCEPT": "ALLOW",
    "DROP": "DENY",
    "REJECT": "REJECT",
    "ufw-user-limit": "LIMIT",
    "ufw6-user-limit": "LIMIT",
}
# Anywhere means "no source restriction" in ufw's own vocabulary.
ANY = {"0.0.0.0/0", "0.0.0.0", "::/0", "::", "any", ""}


def read(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def enabled_state():
    txt = read(os.path.join(HOST_ROOT, "etc/ufw/ufw.conf"))
    if txt is None:
        return None
    for line in txt.splitlines():
        s = line.strip()
        if s.startswith("ENABLED="):
            return s.split("=", 1)[1].strip().lower()
    return ""


def default_policies():
    txt = read(os.path.join(HOST_ROOT, "etc/default/ufw"))
    out = {}
    if txt is None:
        return out
    for line in txt.splitlines():
        s = line.strip()
        for key in ("DEFAULT_INPUT_POLICY", "DEFAULT_OUTPUT_POLICY",
                    "DEFAULT_APPLICATION_POLICY"):
            if s.startswith(key + "="):
                out[key] = s.split("=", 1)[1].strip().strip('"').strip("'").lower()
    return out


def parse_rule_line(line, v6):
    """Turn one `-A ufw-user-input ...` line into a (To, Action, From, comment)
    row, or None if it's not a user INPUT rule (logging/limit infra, etc.)."""
    try:
        tok = shlex.split(line)
    except ValueError:
        return None
    if not tok or tok[0] != "-A":
        return None
    chain = tok[1] if len(tok) > 1 else ""
    # Only the user INPUT chains are real firewall rules the operator authored.
    if chain not in ("ufw-user-input", "ufw6-user-input"):
        return None

    src = proto = dport = comment = target = ""
    i = 2
    while i < len(tok):
        t = tok[i]
        if t == "-s" and i + 1 < len(tok):
            src = tok[i + 1]; i += 2; continue
        if t == "-p" and i + 1 < len(tok):
            proto = tok[i + 1]; i += 2; continue
        if t == "--dport" and i + 1 < len(tok):
            dport = tok[i + 1]; i += 2; continue
        if t == "--dports" and i + 1 < len(tok):   # multiport
            dport = tok[i + 1]; i += 2; continue
        if t == "--ports" and i + 1 < len(tok):
            dport = tok[i + 1]; i += 2; continue
        if t == "--comment" and i + 1 < len(tok):
            comment = tok[i + 1]; i += 2; continue
        if t == "-j" and i + 1 < len(tok):
            target = tok[i + 1]; i += 2; continue
        i += 1

    action = TARGET_ACTION.get(target, target or "?")
    # From column
    if src in ANY:
        frm = "Anywhere (v6)" if v6 else "Anywhere"
    else:
        src = src[:-3] if src.endswith("/32") else src
        src = src[:-4] if src.endswith("/128") else src
        frm = src
    # To column (destination): port/proto, mirroring `ufw status`
    if dport and proto and proto not in ("all", "any"):
        to = f"{dport}/{proto}"
    elif dport:
        to = dport
    elif proto and proto not in ("all", "any"):
        to = f"any on {proto}"
    else:
        to = "Anywhere"
    if v6:
        to += " (v6)"
    return (to, action, frm, comment)


def render_rules(rules, v6):
    txt = read(os.path.join(HOST_ROOT, "etc/ufw", "user6.rules" if v6 else "user.rules"))
    if txt is None:
        return
    in_block = False
    for line in txt.splitlines():
        s = line.strip()
        if s.startswith("### RULES"):
            in_block = True; continue
        if s.startswith("### END RULES"):
            in_block = False; continue
        if not in_block:
            continue
        if s.startswith("-A ufw-user-input") or s.startswith("-A ufw6-user-input"):
            row = parse_rule_line(s, v6)
            if row:
                rules.append(row)


def main():
    en = enabled_state()
    pol = default_policies()

    print("# HOST UFW CONFIGURATION — reconstructed from read-only mount "
          f"{HOST_ROOT} (the scanner's own `ufw status` reflects the container, "
          "not this host)")
    print()
    if en is None:
        print("Status: unavailable (no readable ufw.conf — not a UFW host?)")
    else:
        print("Status: active" if en == "yes" else
              ("Status: inactive" if en == "no" else f"Status: ENABLED={en or '(blank)'}"))
    if pol:
        print("Default: " + ", ".join(
            f"{k.split('_',1)[1].lower()}: {pol.get(k,'?')}"
            for k in ("DEFAULT_INPUT_POLICY", "DEFAULT_OUTPUT_POLICY",
                      "DEFAULT_APPLICATION_POLICY") if k in pol))
    print()

    rules = []
    render_rules(rules, v6=False)
    render_rules(rules, v6=True)

    print("To                         Action      From")
    print("--                         ------      ----")
    if not rules:
        print("(no user rules configured)")
    for to, action, frm, comment in rules:
        line = f"{to:<26} {action:<11} {frm:<26}"
        if comment:
            line += f"  # {comment}"
        print(line)

    print()
    print("## Reconciliation — are these rules actually LOADED right now?")
    # iptables.txt/nftables.txt were captured in the HOST netns (network_mode:
    # host), so they are the host's live ruleset. ufw inserts its own chains only
    # when enabled, so the presence of a ufw chain means the config is enforced.
    def _has_ufw_chain(path):
        txt = read(path) if path else None
        if not txt:
            return False
        return any("ufw" in ln for ln in txt.splitlines()
                   if not ln.lstrip().startswith("#"))
    active = _has_ufw_chain(IPT_TXT) or _has_ufw_chain(NFT_TXT)
    if en != "yes" or not active:
        print("ufw chains ABSENT from the live ruleset — UFW is NOT enforcing; "
              "the rules above are configured but NOT active.")
    else:
        print("ufw chains PRESENT in the live ruleset — UFW config is APPLIED.")

    print()
    print("## Raw rule lines (evidence anchor)")
    for src_rel in ("etc/ufw/user.rules", "etc/ufw/user6.rules"):
        txt = read(os.path.join(HOST_ROOT, src_rel))
        if txt is None:
            continue
        in_block = False
        for line in txt.splitlines():
            s = line.strip()
            if s.startswith("### RULES"):
                in_block = True; continue
            if s.startswith("### END RULES"):
                in_block = False; continue
            if in_block and (s.startswith("### tuple ###") or s.startswith("-A ufw")):
                print(f"  [{src_rel}] {s}")


if __name__ == "__main__":
    main()
