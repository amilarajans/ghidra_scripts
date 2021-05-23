import sys
from typing import Optional

from __main__ import *
from ghidra.app.decompiler import (
    DecompileOptions,
    DecompileResults,
    DecompInterface,
)
from ghidra.program.model.address import Address

try:
    from ghidra_builtins import *
except Exception as e:
    pass


def get_decompile_interface():  # type: () -> DecompInterface
    interface = DecompInterface()
    options = DecompileOptions()
    interface.setOptions(options)
    interface.openProgram(currentProgram)
    interface.setSimplificationStyle("decompile")
    return interface


def decompile_at(
    interface, address
):  # type: (DecompInterface, Address) -> Optional[DecompileResults]
    function = getFunctionContaining(address)
    if function is None:
        sys.stderr.write("Function is not defined at " + str(address) + "\n")
        return None
    return interface.decompileFunction(function, 30, monitor)
