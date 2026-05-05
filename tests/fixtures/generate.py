# NullBot — Open Source Anti-Botnet | GPL-3.0
# File: tests/fixtures/generate.py
#
# Regenerates all binary test fixtures in this directory.
# Run from the project root: python tests/fixtures/generate.py

import os
import secrets

fixtures_dir = os.path.dirname(os.path.abspath(__file__))

# empty.txt — zero bytes
open(os.path.join(fixtures_dir, "empty.txt"), "wb").close()

# lorem.txt — normal ASCII text (low entropy, ~4 bits/byte)
lorem = (
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
    "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
    "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris "
    "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in "
    "reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla "
    "pariatur. Excepteur sint occaecat cupidatat non proident, sunt in "
    "culpa qui officia deserunt mollit anim id est laborum.\n"
)
with open(os.path.join(fixtures_dir, "lorem.txt"), "w", encoding="ascii") as f:
    f.write(lorem)

# high_entropy.bin — 1 KB of cryptographically random bytes (entropy ≈ 8.0 bits/byte)
with open(os.path.join(fixtures_dir, "high_entropy.bin"), "wb") as f:
    f.write(secrets.token_bytes(1024))

print("Fixtures generated in:", fixtures_dir)
