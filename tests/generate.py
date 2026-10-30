"""Build instrumented shell scripts only for disposable-root tests."""
import atexit
import importlib.util
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("demudhra_generator", ROOT / "tools/generate.py")
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)
(ROOT / ".build").mkdir(exist_ok=True)
SCRIPTS = Path(tempfile.mkdtemp(prefix="test-scripts-", dir=ROOT / ".build"))
atexit.register(shutil.rmtree, SCRIPTS, ignore_errors=True)
(SCRIPTS / "data").mkdir()
shutil.copyfile(ROOT / "data/fingerprints.tsv", SCRIPTS / "data/fingerprints.tsv")
for platform in ("linux", "macos"):
    script = SCRIPTS / f"demudhra-{platform}.sh"
    script.write_text(generator.platform_script(platform, release=False))
    script.chmod(0o755)
