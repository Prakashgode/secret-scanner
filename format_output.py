"""format scan results for console output

basic table-like output with color-coded severity
"""

# ANSI colors for terminal
COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH": "\033[93m",      # yellow
    "MEDIUM": "\033[94m",    # blue
    "LOW": "\033[37m",       # white
}
RESET = "\033[0m"

def format_console(findings):
    if not findings:
        return "No secrets detected."
    
    lines = [
        f"\n{'='*60}",
        f"  Scan Results: {len(findings)} finding(s)",
        f"{'='*60}\n",
    ]
    
    for f in findings:
        color = COLORS.get(f.get('severity', ''), '')
        lines.append(
            f"  {color}[{f.get('severity', '?')}]{RESET} {f.get('type', 'unknown')}\n"
            f"    File: {f['file']}:{f['line']}\n"
        )
    
    lines.append(f"{'='*60}")
    return "\n".join(lines)

# TODO: json output
# TODO: maybe sarif for github code scanning integration?
