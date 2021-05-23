# Search functions referencing specific byte sequences (please change "search_string" in _main function)
# @author Ko Nakagawa
# @category Code Analysis
# @keybinding
# @menupath
# @toolbar

from ghidra.app.tablechooser import (
    AddressableRowObject,
    StringColumnDisplay,
    TableChooserDialog,
)
from ghidra.program.model.address import Address
from utils.console import show_err

try:
    from typing import List, Dict, Any, Union, Optional, cast
    from ghidra_builtins import *
except Exception as e:
    pass


class FunctionReferencingData(AddressableRowObject):
    def __init__(
        self, function_name, from_addr, to_addr
    ):  # type: (FunctionReferencingData, str, Address, Address) -> None
        super(FunctionReferencingData, self).__init__()
        self.function_name = function_name
        self.from_addr = from_addr
        self.to_addr = to_addr

    def getAddress(self):  # type: (FunctionReferencingData) -> Address
        return self.from_addr


class FunctionNameColumn(StringColumnDisplay):
    def getColumnName(self):  # type: (FunctionNameColumn) -> unicode
        return u"Function Name"

    def getColumnValue(
        self, row_object
    ):  # type: (FunctionNameColumn, FunctionReferencingData) -> unicode
        return row_object.function_name


class ToAddrColumn(StringColumnDisplay):
    def getColumnName(self):  # type: (ToAddrColumn) -> unicode
        return u"To Address"

    def getColumnValue(
        self, row_object
    ):  # type: (ToAddrColumn, FunctionReferencingData) -> unicode
        return row_object.to_addr


def configure_table_columns(table_dialog):  # type: (TableChooserDialog) -> None
    table_dialog.addCustomColumn(FunctionNameColumn())
    table_dialog.addCustomColumn(ToAddrColumn())


def _main():  # type: () -> None
    search_string = b"\xc0\x02\x1f\xd6"  # byte sequences to be searched
    base_addr = currentProgram.getImageBase()
    founds = findBytes(base_addr, search_string, 100)  #

    table_dialog = createTableChooserDialog(
        "Found functions referencing "
        + "".join("{0:02x}".format(ord(i)) for i in search_string),
        cast(TableChooserDialog, None),
    )
    configure_table_columns(table_dialog)
    table_dialog.show()

    for found in founds:
        references = getReferencesTo(found)
        for reference in references:
            to_addr = found
            from_addr = reference.getFromAddress()
            if from_addr is None:
                show_err("Cannot get from address")
                continue
            func = getFunctionContaining(from_addr)
            if func is None:
                show_err(from_addr.toString() + " does not contain function")
                continue
            table_dialog.add(
                FunctionReferencingData(str(func.getName()), from_addr, to_addr)
            )


if __name__ == "__main__":
    _main()
