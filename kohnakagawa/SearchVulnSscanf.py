# Insipred by the ZDI blog post
# https://www.thezdi.com/blog/2019/7/16/mindshare-automated-bug-hunting-by-modeling-vulnerable-code
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
from ghidra.program.database.symbol import FunctionSymbol
from ghidra.program.model.address import Address
from ghidra.program.model.pcode import PcodeOp, PcodeOpAST
from ghidra.program.model.symbol import Reference
from utils.console import show_err
from utils.decompiler import decompile_at, get_decompile_interface

try:
    from typing import List, Dict, Any, Union, Optional, cast
    from ghidra_builtins import *
except Exception as e:
    pass


def process_sscanf_call_pattern(
    pcodeop_ast, table_dialog, func_name, address
):  # type: (PcodeOpAST, TableChooserDialog, Union[str, unicode], Address) -> None
    if pcodeop_ast.getOpcode() != PcodeOp.CALL:
        show_err(
            "It seems not to be sscanf function call (address "
            + address.toString()
            + ")"
        )
        return

    if pcodeop_ast.output is None:
        table_dialog.add(
            PotentialVulnSScanfs(
                func_name, address, "sscanf return value is not checked"
            )
        )
        return

    for pcode_using in pcodeop_ast.output.getDescendants():
        # NOTE: In this sample, we only target the INT_EQUAL P-Code. However, in real world, this is not enough.
        # For example, P-Codes such as INT_NOTEQUAL, INT_LESS should be supported to find additional potential
        # vulnerable function call patterns.
        if pcode_using.opcode != PcodeOp.INT_EQUAL:
            continue
        if pcode_using.inputs[0].getDef() == pcodeop_ast:
            varnode_compared = pcode_using.inputs[1]
        elif pcode_using.inputs[1].getDef() == pcodeop_ast:
            varnode_compared = pcode_using.inputs[0]
        else:
            show_err("Should not be reached this line")
            return

        if varnode_compared.isConstant():
            if varnode_compared.getOffset() < pcodeop_ast.getNumInputs() - 3:
                table_dialog.add(
                    PotentialVulnSScanfs(
                        func_name,
                        address,
                        "sscanf return value is checked, but not checked properly.",
                    )
                )


class PotentialVulnSScanfs(AddressableRowObject):
    def __init__(
        self, function_name, location, explanation
    ):  # type: (PotentialVulnSScanfs, str, Address, str) -> None
        super(PotentialVulnSScanfs, self).__init__()
        self.function_name = function_name
        self.location = location
        self.explanation = explanation

    def getAddress(self):  # type: (PotentialVulnSScanfs) -> Address
        return self.location

    def toString(self):  # type: (PotentialVulnSScanfs) -> unicode
        return self.explanation


class FunctionNameColumn(StringColumnDisplay):
    def getColumnName(self):  # type: (FunctionNameColumn) -> unicode
        return u"Function Name"

    def getColumnValue(
        self, row_object
    ):  # type: (FunctionNameColumn, PotentialVulnSScanfs) -> unicode
        return row_object.function_name


class ExplanationColumn(StringColumnDisplay):
    def getColumnName(self):  # type: (ExplanationColumn) -> unicode
        return u"Explanation"

    def getColumnValue(
        self, row_object
    ):  # type: (ExplanationColumn, PotentialVulnSScanfs) -> unicode
        return row_object.explanation


def configure_table_columns(table_dialog):  # type: (TableChooserDialog) -> None
    table_dialog.addCustomColumn(FunctionNameColumn())
    table_dialog.addCustomColumn(ExplanationColumn())


def _main():  # type: () -> None
    table_dialog = createTableChooserDialog(
        "Vulnerable sscanf function call pattern found in " + currentProgram.getName(),
        cast(TableChooserDialog, None),
    )
    configure_table_columns(table_dialog)
    table_dialog.show()

    symbol_table = currentProgram.getSymbolTable()
    sscanf_symbols = list(symbol_table.getSymbols("_sscanf"))
    if len(sscanf_symbols) == 0:
        show_err("sscanf is not found")
        return

    decompiler_ifc = get_decompile_interface()
    for sscanf_symbol in sscanf_symbols:
        if not isinstance(sscanf_symbol, FunctionSymbol):
            continue

        for ref in sscanf_symbol.references:  # type: Reference
            function_calling = getFunctionContaining(ref.getFromAddress())

            if function_calling is None:
                show_err(
                    "Address ("
                    + ref.getFromAddress().toString()
                    + ") does not contain function"
                )
                continue

            decomp_result = decompile_at(
                decompiler_ifc, function_calling.getEntryPoint()
            )
            if decomp_result is None:
                show_err("Cannot decompile at " + function_calling.getEntryPoint())
                continue

            high_function = decomp_result.getHighFunction()
            if high_function is None:
                show_err("Cannot get high function")
                continue

            pcode_ops = high_function.getPcodeOps(ref.getFromAddress())
            process_sscanf_call_pattern(
                next(pcode_ops),
                table_dialog,
                function_calling.getName(),
                ref.getFromAddress(),
            )


if __name__ == "__main__":
    _main()
