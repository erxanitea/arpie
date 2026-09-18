import os
import sys

_venv_python = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv", "bin", "python")
if (
    os.path.exists(_venv_python)
    and sys.prefix == sys.base_prefix
    and not os.environ.get("_ARPIE_VENV_EXEC")
):
    os.environ["_ARPIE_VENV_EXEC"] = "1"
    os.execv(_venv_python, [_venv_python] + sys.argv)

from arpie.cli import main


if __name__ == "__main__":
    main()
