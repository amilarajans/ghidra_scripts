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
# Sets the mutability settings for data in read only memory blocks to constant.
#@category Data
#@author Andrew J. Strelsky
from ghidra.program.model.address import AddressSet

MUT = 'mutability'
CONST = 2

def is_read_only(block):
    return block.read and not (block.write or block.volatile or block.execute)

def get_data(block):
    addr_set = AddressSet(block.start, block.end)
    return [d for d in currentProgram.getListing().getData(addr_set, True)]

def make_read_only(d):
    d.setLong(MUT, CONST)

if __name__ == "__main__":
    for block in [b for b in getMemoryBlocks() if is_read_only(b)]:
        monitor.setMessage('Marking constants in '+block.name)
        data = get_data(block)
        monitor.initialize(len(data))
        for d in data:
            monitor.checkCanceled()
            make_read_only(d)
            monitor.incrementProgress(1)
