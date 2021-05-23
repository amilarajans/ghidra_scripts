# Calculate cyclomatic complexities for all functions defined in the current program
# @author Ko Nakagawa
# @category CodeAnalysis
# @keybinding
# @menupath
# @toolbar

try:
    from ghidra_builtins import *
    from typing import List, Dict, Any
except Exception as e:
    pass

from ghidra.program.model.listing import Function, FunctionIterator
from ghidra.program.util import CyclomaticComplexity


def get_complex_functions_list(num):  # type: (int) -> List[Dict[str, Any]]
    functions = currentProgram.getFunctionManager().getFunctions(
        True
    )  # type: FunctionIterator

    func_to_complexity = list()
    cc = CyclomaticComplexity()
    for function in functions:  # type: Function
        complexity = cc.calculateCyclomaticComplexity(function, monitor)
        func_to_complexity.append(
            {
                "function": str(function),
                "address": function.getEntryPoint(),
                "complexity": complexity,
            }
        )

    func_to_complexity_sorted = sorted(
        func_to_complexity, key=lambda elem: elem["complexity"], reverse=True
    )
    return func_to_complexity_sorted[:num]


if __name__ == "__main__":
    print(get_complex_functions_list(10))
