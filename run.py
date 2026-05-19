#!/usr/bin/env python3
"""Direct launcher for MCP GDB Server — no installation required.

Usage:
    python3 run.py [options]

    # Or make executable:
    chmod +x run.py
    ./run.py [options]
"""

import sys
from pathlib import Path

# Add src/ to Python path so mcp_gdbserver package can be imported
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from mcp_gdbserver.main import main

sys.exit(main())
