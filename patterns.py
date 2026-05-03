PATTERNS = {
    "AWS_KEY": r"AKIA[0-9A-Z]{8,}",  # relaxed (demo-friendly)

    "PRIVATE_KEY": r"-----BEGIN PRIVATE KEY-----",

    "HARDCODED_SECRET": r"(SECRET|KEY|TOKEN|PASSWORD)\s*=\s*['\"][^'\"]+['\"]",

    "GENERIC_TOKEN": r"[A-Za-z0-9_\-]{20,}"  # reduced threshold
}