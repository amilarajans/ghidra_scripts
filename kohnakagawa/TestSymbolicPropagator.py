# Test script for Ghidra SymbolicPropagator (it only works for the analysis of KernelBase.dll)
# @author Ko Nakagawa
# @category CodeAnalysis
# @keybinding
# @menupath
# @toolbar


try:
    from ghidra_builtins import *
except Exception as e:
    pass

import sys
from typing import Any, List, Optional, cast

from ghidra.app.plugin.core.analysis import (
    AutoAnalysisManager,
    ConstantPropagationAnalyzer,
)
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Function, Program
from ghidra.program.model.symbol import Reference
from ghidra.program.util import SymbolicPropogator
from ghidra.util.classfinder import ClassSearcher


# NOTE: this implementation heavily relies on
# https://github.com/astrelsky/ghidra_scripts/blob/ac3caaf7762f59a72bfeef8e24cbc8d1eda00657/PrintfSigOverrider.java#L292-L317
def get_constant_analyzer(
    program,
):  # type: (Program) -> Optional[ConstantPropagationAnalyzer]
    manager = AutoAnalysisManager.getAnalysisManager(currentProgram)
    analyzers = ClassSearcher.getInstances(ConstantPropagationAnalyzer().getClass())
    for analyzer in analyzers:  # type: ConstantPropagationAnalyzer
        if analyzer.canAnalyze(program):
            return cast(
                ConstantPropagationAnalyzer, manager.getAnalyzer(analyzer.getName())
            )
    return None


def analyze_function(
    function, analyzer
):  # type: (Function, ConstantPropagationAnalyzer) -> SymbolicPropogator
    program = function.getProgram()
    sym_eval = SymbolicPropogator(program)
    sym_eval.setParamRefCheck(True)
    sym_eval.setReturnRefCheck(True)
    sym_eval.setStoredRefCheck(True)
    analyzer.flowConstants(
        program, function.getEntryPoint(), function.getBody(), sym_eval, monitor
    )
    return sym_eval


def address_belongs_to_function(address, function):  # type: (Address, Function) -> bool
    for address_range in function.getBody():
        if address in address_range:
            return True
    return False


def get_function_call_sites_in_target_function(
    target_func, calling_func
):  # type: (Function, Function) -> List[Address]
    call_sites_addresses = list()
    references = getReferencesTo(calling_func.getEntryPoint())
    for reference in references:  # type: Reference
        from_addr = reference.getFromAddress()
        if address_belongs_to_function(from_addr, target_func):
            call_sites_addresses.append(from_addr)
    return call_sites_addresses


def _main():  # type: () -> None
    constant_analyzer = get_constant_analyzer(currentProgram)

    create_process_a_found = getGlobalFunctions("CreateProcessA")
    if create_process_a_found is None or len(create_process_a_found) != 1:
        sys.stderr.write("CreateProcessA is not found\n")
        sys.stderr.write("Please use this script for KernelBase.dll analysis\n")
        return
    create_process_a = create_process_a_found[0]

    sym_eval = analyze_function(create_process_a, constant_analyzer)

    create_process_internal_a = getGlobalFunctions("CreateProcessInternalA")[0]

    call_sites = get_function_call_sites_in_target_function(
        create_process_a, create_process_internal_a
    )
    for call_site in call_sites:
        # NOTE: we can get only constants for arguments that are passed via registers.
        val = sym_eval.getRegisterValue(
            call_site, create_process_internal_a.getParameter(0).getRegister()
        )
        if val:
            print(
                "The value of CreateProcessInternalA's first argment is %x"
                % val.getValue()
            )


if __name__ == "__main__":
    _main()
