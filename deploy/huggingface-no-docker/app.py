"""Aegis public demo on a Hugging Face Space without Docker (Gradio SDK slot; Gradio itself is not used).
Downloads Aegis from GitHub at startup and runs the simulated plant + dashboard on port 7860."""
import os, runpy, subprocess, sys
from pathlib import Path

APP = Path("/tmp/aegis")
if not APP.exists():
    subprocess.run(["git", "clone", "--depth", "1", "https://github.com/YoussefShaaban07/aegis.git", str(APP)], check=True)
os.environ.update(AEGIS_DEMO="1", AEGIS_PUBLIC="1", AEGIS_HTTPS="1", AEGIS_HOST="0.0.0.0", PORT="7860")
os.chdir(APP)
sys.path.insert(0, str(APP))
sys.argv = ["aegis.server"]
runpy.run_module("aegis.server", run_name="__main__")
