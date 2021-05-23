# Find frequently called functions
# @author Ko Nakagawa
# @category CodeAnalysis
# @keybinding
# @menupath
# @toolbar

try:
    from typing import List, Dict, Any
    from ghidra_builtins import *
except Exception as e:
    pass

from ghidra.program.model.listing import Function, FunctionIterator


def get_frequently_used_functions(num):  # type: (int) -> List[Dict[str, Any]]
    functions = currentProgram.getFunctionManager().getFunctions(
        True
    )  # type: FunctionIterator

    function_to_n_calling = list()
    for function in functions:  # type: Function
        n_calling = len(function.getCallingFunctions(monitor))
        function_to_n_calling.append(
            {
                "n_calling": n_calling,
                "function": function,
                "address": function.getEntryPoint(),
            }
        )

    function_to_n_calling = sorted(
        function_to_n_calling, key=lambda elem: elem["n_calling"], reverse=True
    )
    return function_to_n_calling[:num]


if __name__ == "__main__":
    print(get_frequently_used_functions(10))
