import sys
from typing import Union

from __main__ import *


def show_err(s):  # type: (Union[unicode, str]) -> None
    sys.stderr.write(s + "\n")
