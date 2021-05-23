'''
The MIT License (MIT)

Copyright (c) 2019-2020 Andrew J. Strelsky

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
'''
# Creates null terminated strings in the current selection
#@category Strings
#@author Andrew J. Strelsky

from ghidra.program.model.address import AddressOutOfBoundsException

def getProgress(addr):
    return currentSelection.maxAddress.offset - addr.offset

if __name__ == '__main__':
    mem = currentProgram.getMemory()
    addr = currentSelection.getMinAddress()
    clearListing(addr, currentSelection.getMaxAddress())
    monitor.setMessage('Creating Strings')
    monitor.initialize(currentSelection.numAddresses)
    while currentSelection.contains(addr):
        monitor.checkCanceled()
        d = getDataAt(addr)
        if not d or not d.hasStringValue():
            clearListing(addr)
            if mem.getByte(addr) != 0:
                d = createAsciiString(addr)
                assert d.hasStringValue()
                try:
                    addr = addr.add(d.length)
                except AddressOutOfBoundsException as e:
                    # string ends at the end of the selection or memory block
                    break
            else:
                addr = addr.next()
        elif d.hasStringValue():
            addr = addr.add(d.length)
        else:
            addr = addr.next()
        monitor.progress = getProgress(addr)
