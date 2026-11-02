"""Python convenience launcher for the offline Node.js implementation."""
from pathlib import Path
import shutil
import subprocess
import sys

node = shutil.which("node")
if not node:
    raise SystemExit("Node.js 18+ is required. Install Node.js or run `node code/main.js`.")
script = Path(__file__).with_name("main.js")
raise SystemExit(subprocess.call([node, str(script), *sys.argv[1:]], cwd=script.parent.parent))
