# Ghidra scripts

A collection of some useful Ghidra scripts.
This is a collection created from github repos.

Ghidra scripts to support IOT exploitation. Some of the scripts are a port 
of [devttyS0](https://github.com/devttys0/ida) IDA plugins

## Documentation

Most of scripts has a `.md` file with its documentation.

## Install

Copy the script(s) (you like to use) to your `ghidra_scripts` folder (usually located
at `~/ghidra_scripts`) or any other directory Ghidra is configured to search for
scripts.

In the Ghidra Script Manager click the "Script Directories" icon in the toolbar and add the checked out repository as a path. Scripts from this collection will appear in the respective category.





## [Scripts from - TNS](https://github.com/tacnetsol/ghidra_scripts)

### [ARM ROP Finder](readmes/armrop.md)

Script to find and support finding ARM ROP gadgets. 

- Gadgets
  
  - Find double jumps.
  - Move small value to r0.
  - Get control of more or different registers.
  - Move values between registers.
  - Find strings or shellcode on the stack.
  - Find custom gadgets based on regular expressions.
  - Gadgets to call system with a string argument in r0.

- Support
  
  - Convert entire program to Thumb instructions. 
  - List summary of saved gadgets.

### [Call Chain](readmes/callchain.md)

Find call chains between two user specified functions. Results are displayed in a png.

### [Codatify](readmes/codatify.md)

- Fixup code - defines all undefined data in the .text section as code and creates a function if it can.
- Fixup data - define uninitialized strings and pointers. Searches for function tables and renames functions based on their discovery. 

### [Fluorescence](readmes/fluorescence.md)

Highlight function calls.

### [Function Profiler](readmes/func_profiler.md)

Display cross refs from the current function.

### [Leaf Blower](readmes/leafblower.md)

- Format Strings - Find functions that accept format strings as parameters.
- Leaf Functions - Identify potential leaf functions such as strcpy, strlen, etc.

### [Local Cross References](readmes/local_cross_ref.md)

Find references to items in the current function.

### [MIPS ROP Finder](readmes/mips_rop.md)

Scripts to find and support finding MIPS ROP gadgets.

- Gadgets
  
  - Double Jumps
  - Epilogue
  - Find custom gadgets
  - Indirect Return
  - li a0
  - Prologue
  - System Gadgets

- Chain Builder
  
  - Build ROP chain to call shellcode
  - Build ROP chain to call system with controllable string. 

- Support
  
  - Summary

### [Operator](readmes/operator.md)

Display all calls to a function and identify the source of the parameters it is called with taking variadic arguments into account if they are present.

### [Rename Variables](readmes/rename_variables.md)

Rename saved stack variables. (MIPS only)

### [Rizzo](readmes/rizzo.md)

Create fuzzy function signatures that can be applied to other projects.





## [Scripts from - 0x6d696368](https://github.com/0x6d696368/ghidra_scripts)

### [Google search](readmes/GoogleSearch.md)

Quickly search function names online.

### [RC4 Decrypter](readmes/RC4Decrypter.md)

RC4 decryption

### [Search Simple Stack Strings](readmes/SearchSimpleStackStrings.md)

Searches and reasemble ASCII stack string formed via repeated instructions

### [Simple Stack Strings](readmes/SimpleStackStrings.md)

Reasemble an ASCII stack string formed via repeated instructions

### [Yara Search](readmes/YaraSearch.md)

Provides a YARA search

### [Color Call Graph Calls To](readmes/colorCallGraphCallsTo.md)

Color all calls that are involved (as incoming edges) in the call graph to the current address.

### [Pipe Decoder](readmes/pipeDecoder.md)

Pipe the data from a selection through a shell process and replacing the data with the decoded output piped back from the shell process.





## [Scripts from - ghidraninja](https://github.com/ghidraninja/ghidra_scripts)

### [binwalk](readmes/binwalk.md)

Runs binwalk on the current program and bookmarks the findings

### [yara](readmes/yara.md)

Yara search

### export_gameboy_rom.py

Exports working ROMs from ROMs imported using Gekkio's [GhidraBoy](https://github.com/Gekkio/GhidraBoy).

### [swift demangler](readmes/swift_demangler.md)

Automatically demangle swift function names.

### [go lang renamer](readmes/golang_renamer.md)

Restores function names from a stripped Go binary.





## [Scripts from - Koh M. Nakagawa](https://github.com/kohnakagawa/ghidra_scripts)

### CalcCyclomaticForAllFunctions.py

This script calculates the Cyclomatic complexities for all functions of the current program.
It can be used for finding the complex functions.

### FindFrequentlyUsedFunctions.py

This script shows the frequently-called functions.

### [Search Function Call Pattern](readmes/search_function_call_pattern.md)

This script searches the function call passing a specific value.

### TestSymbolicPropagator.py

This script is for testing Ghidra SymbolicPropagator.
Note that it only works for the analysis of `KernelBase.dll`

### SearchVulnSscanf.py

This scripts finds the potential vulnerable `sscanf` function call patterns via a P-Code analysis.
Insipred by [this ZDI blog post](https://www.thezdi.com/blog/2019/7/16/mindshare-automated-bug-hunting-by-modeling-vulnerable-code).





## [Scripts from - Andrew Strelsky](https://github.com/astrelsky/ghidra_scripts)

### Attach Fids Script

Batch imports FID database files from a user specified directory

### Cleanup Bookmarks Script

Removes the unnecessary "Bad Instruction" bookmarks set during analysis  of ARM binaries. Bookmarks are only removed if data or an instruction are present at the bookmark's address.

### Printf Sig Overrider

Overrides printf calls with the varargs parameter replaced by the format specifiers.This helps the decompiler with type propogation.

### Resolve Fid Script

Displays a table of known FID_conflicts containing an action that allows the user to select the correct label. After the label has been selected all remaining FID_conflict labels are removed from the address and the selected label is demangled and re-applied if necessary.

### Make Constants

Sets the mutability settings for data in read only memory blocks to constant.

### Make Function Table

Creates a function at each address in the selected function table

### Make Strings

Creates null terminated strings in the current selection

### Boost Any

Repairs Boost Any Class DataTypes

### Boost Smart Pointer

Repairs Boost Smart Pointer Class DataTypes

### Boost Tuple

Repairs Boost Tuple Class DataTypes





## [Scripts from - AllsafeCyberSecurity](https://github.com/AllsafeCyberSecurity/ghidra_scripts)

### shellcode_hashes

shellcode_hashs was created inspired by a [script of the same name in flare](https://github.com/fireeye/flare-ida/tree/master/shellcode_hashes).

Find the name that matches the [hash](https://www.fireeye.com/blog/threat-research/2012/11/precalculated-string-hashes-reverse-engineering-shellcode.html) used in the shellcode.

Use the database created by flare script.

### sqlite2json.py

Since Ghidra could not import sqlite, I created a script to convert it to json.

Convert with the following command:

```
python sqlite2json.py
```

### [shellcode hash search](readmes/shellcode_hash_search.md)

Search for shellcode

### [non-zero xor search](non-zero_xor_search.md)

Finds XOR instructions whose source and destination operands are not equivalent.

It is registered in the bookmark.

### [coloring call jmp](readmes/coloring_call_jmp.md)

Coloring of CALL and JMP instructions.

### [stack strings](readmes/stackstrings.md)

Deobfuscate stackstrings used by Godzilla Loader.



## Other

### [FindCrypt (Script)](readmes/FindCrypt.md)

[GitHub - FindCrypt-Ghidra](https://github.com/d3v1l401/FindCrypt-Ghidra)

Find references to Cryptography functions

### Find Banned Functions

This script locates potentially dangerous functions that could introduce a vulnerability if they are used incorrectly.

### Objective-C

Parse Objective C

### kernel svc tables

todo

### Metacast

Fix a metacast output in iOS kernelcache

### sscanf

todo

### rabbithole

Mark functions with their cumulative cyclomatic complexity
