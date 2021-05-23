# Search Function Call Pattern

This script searches the function call passing a specific value.

For example, consider the case where you want to look for the function call of `RtlpImageDirectoryEntryToDataEx()` whose third argument is `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` (`0xd`).

By using this script, you can search such a call site by typing `RtlpImageDirectoryEntryToDataEx(_, _, 0xd, _, _)`

**Input for searching**

![input](./img/type_func_call.png)

**Search results**

![result](./img/search_result.png)