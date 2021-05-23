# Search function call pattern
# TODO: More sophisticated search can be done
# c.f. https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/ghidra_scripts/ShowConstantUse.java
# @author Ko Nakagawa
# @category CodeAnalysis
# @keybinding
# @menupath
# @toolbar


import re
import sys
from typing import Any, List, Optional, Tuple, Union, cast

from ghidra.app.tablechooser import (
    AddressableRowObject,
    StringColumnDisplay,
    TableChooserDialog,
)
from ghidra.program.model.address import Address
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.program.model.symbol import Reference, RefType
from utils.decompiler import decompile_at, get_decompile_interface

try:
    from ghidra_builtins import *
except Exception as e:
    pass


def is_target_ref(ref):  # type: (Reference) -> bool
    return ref.getReferenceType() == RefType.UNCONDITIONAL_CALL


def ishexdigit(in_str):  # type: (str) -> bool
    try:
        int(in_str, 16)
    except ValueError as _:
        return False
    return True


# NOTE: float is not supported
def parse_args(args):  # type: (str) -> List[Union[str, int]]
    args_parsed = list()
    for i, arg in enumerate(args.split(",")):
        arg = arg.strip()
        if arg.isdigit():
            args_parsed.append(int(arg))
        elif ishexdigit(arg):
            args_parsed.append(int(arg, 16))
        else:
            args_parsed.append(arg)
    return args_parsed


def check_function_argments(
    pcode_op_ast, parsed_args, call_site, target_func_sig
):  # type: (PcodeOpAST, List[Union[str, int]], Address, str) -> Optional[Address]
    print("Current call site is " + str(call_site))
    if pcode_op_ast.getNumInputs() != len(parsed_args) + 1:
        sys.stderr.write(
            "Number of arguments does not match at " + str(call_site) + "\n"
        )
        sys.stderr.write(
            "Got %d (expected %d)\n"
            % (len(parsed_args) + 1, pcode_op_ast.getNumInputs())
        )
        sys.stderr.write("Signature of target function is " + target_func_sig + "\n")
        return None

    matched_result = list()
    for i, parsed_arg in enumerate(parsed_args):
        input_var_node = pcode_op_ast.getInput(i + 1)
        if parsed_arg == "_":
            continue

        # TODO: to be implemented (for other varnode types)
        if input_var_node.isConstant():
            print("Check the function's argument value")
            print("Got " + str(input_var_node.getOffset()))
            print("Expected " + str(parsed_arg))
            matched_result.append(input_var_node.getOffset() == parsed_arg)

    print("matched result is ", matched_result)
    if matched_result and all(matched_result):
        print("Specified function call pattern is found!")
        return call_site

    return None


class FoundFunctionCallSiteRowObject(AddressableRowObject):
    def __init__(
        self, function_name, location, explanation
    ):  # type: (FoundFunctionCallSiteRowObject, str, Address, str) -> None
        super(FoundFunctionCallSiteRowObject, self).__init__()
        self.function_name = function_name
        self.location = location
        self.explanation = explanation

    def getAddress(self):  # type: (FoundFunctionCallSiteRowObject) -> Address
        return self.location

    def toString(self):  # type: (FoundFunctionCallSiteRowObject) -> unicode
        return self.explanation


class FunctionNameColumn(StringColumnDisplay):
    def getColumnName(self):  # type: (FunctionNameColumn) -> unicode
        return u"Function Name"

    def getColumnValue(
        self, row_object
    ):  # type: (FunctionNameColumn, FoundFunctionCallSiteRowObject) -> unicode
        return row_object.function_name


class ExplanationColumn(StringColumnDisplay):
    def getColumnName(self):  # type: (ExplanationColumn) -> unicode
        return u"Explanation"

    def getColumnValue(
        self, row_object
    ):  # type: (ExplanationColumn, FoundFunctionCallSiteRowObject) -> unicode
        return row_object.explanation


def configure_table_columns(table_dialog):  # type: (TableChooserDialog) -> None
    table_dialog.addCustomColumn(FunctionNameColumn())
    table_dialog.addCustomColumn(ExplanationColumn())


def search_function_call_pattern(
    func_name, args
):  # type: (str, str) -> Optional[List[Any]]
    functions_found = getGlobalFunctions(func_name)
    if len(functions_found) != 1:
        if len(functions_found) == 0:
            sys.stderr.write(func_name + " is not found\n")
            return None
        if len(functions_found) >= 2:
            sys.stderr.write("Multiple " + func_name + " are found\n")
            return None

    table_dialog = createTableChooserDialog(
        "Found function call patterns in " + currentProgram.getName(),
        cast(TableChooserDialog, None),
    )
    configure_table_columns(table_dialog)
    table_dialog.show()

    decompile_ifc = get_decompile_interface()
    parsed_args = parse_args(args)

    target_function_sig = str(functions_found[0].getPrototypeString(True, True))
    target_function_addr = functions_found[0].getEntryPoint()
    refs_to_target = getReferencesTo(target_function_addr)
    for ref in refs_to_target:  # type: Reference
        if not is_target_ref(ref):
            continue

        call_site = ref.getFromAddress()
        decompile_results = decompile_at(decompile_ifc, call_site)
        if decompile_results is None:
            sys.stderr.write(
                "Cannot get decompile result because function is not defined at "
                + str(call_site)
                + "\n"
            )
            continue

        high_function = decompile_results.getHighFunction()
        if high_function is None:
            sys.stderr.write("Cannot get high function\n")
            continue

        pcode_ops = high_function.getPcodeOps(call_site)
        found_call_site = check_function_argments(
            next(pcode_ops), parsed_args, call_site, target_function_sig
        )
        if found_call_site:
            function_containing_call_site = getFunctionContaining(call_site)
            if function_containing_call_site:
                call_site_name = function_containing_call_site.getName()
            else:
                call_site_name = ""
            table_dialog.add(
                FoundFunctionCallSiteRowObject(call_site_name, found_call_site, "Found")
            )


def split_function_name_and_argment(
    func_call_pattern,
):  # type: (str) -> Optional[Tuple[str, str]]
    # NOTE: assuming that parenthesis are not included in function parameters
    # For example, func(a, hoge(b, c)) is not supported now.
    # This feature will be supported in the future.
    matched_obj = re.match(r"(.*)\((.*)\)", func_call_pattern)
    if matched_obj is None or len(matched_obj.groups()) != 2:
        sys.stderr.write(
            "Specified function call patter " + func_call_pattern + " is invalid"
        )
        return None
    return matched_obj.groups()[0], matched_obj.groups()[1]


def _main():  # type: () -> None
    func_name = askString(
        "Function call pattern?", "Type function call pattern (e.g., func(1, _, 3))"
    )
    func_name_and_args = split_function_name_and_argment(str(func_name).strip())
    if func_name_and_args is None:
        return

    search_function_call_pattern(*func_name_and_args)


if __name__ == "__main__":
    _main()
