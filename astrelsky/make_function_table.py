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
# Creates a function at each address in the selected function table
#@category Functions
#@author Andrew J. Strelsky

def getProgress(addr):
    return currentSelection.maxAddress.offset - addr.offset

if __name__ == '__main__':
    addr = currentSelection.getMinAddress()
    dtm = currentProgram.getDataTypeManager()
    monitor.setMessage('Creating Functions')
    monitor.initialize(currentSelection.numAddresses)
    while currentSelection.contains(addr):
        monitor.checkCanceled()
        d = getDataAt(addr)
        if not d:
            dt = dtm.getPointer(None, -1)
            d = createData(addr, dt)
        f = getFunctionAt(d.value)
        if not f:
            createFunction(d.value, None)
        addr = addr.add(d.length)
        monitor.progress = getProgress(addr)
