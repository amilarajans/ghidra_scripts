# Fix a metacast output in iOS kernelcache 

#@author simo
#@category iOS.kernel
#@keybinding Meta Shift M
#@toolbar logos/m.png

# -*- coding: utf-8 -*-

# This script can be only used in GHIDRA 9.2, so grab the source code and compile it yourself

from ghidra.app.script import GhidraScript,GhidraState
from ghidra.program.model.data import FunctionDefinition
from ghidra.app.util.demangler import Demangler
from ghidra.app.cmd.label import DemanglerCmd
from ghidra.program.model.data import IntegerDataType,VoidDataType,StructureDataType,UnsignedLongLongDataType,PointerDataType,FunctionDefinitionDataType
from ghidra.program.model.data import FunctionDefinitionDataType
from ghidra.program.model.listing import Parameter,ParameterImpl,Program,VariableStorage
from ghidra.program.model.symbol import SourceType,SymbolTable,Namespace,RefType
from ghidra.program.util.GhidraProgramUtilities import getCurrentProgram
from ghidra.app.services import DataTypeManagerService
from ghidra.app.decompiler import DecompileOptions,DecompInterface
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.framework.plugintool.util import OptionsService
from ghidra.program.model.pcode import PcodeOp, VarnodeAST, HighSymbol,HighFunctionDBUtil,HighVariable,HighLocal,HighOther
from ghidra.program.model.pcode import *
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.pcode import LocalSymbolMap 
from ghidra.util.UniversalIdGenerator import nextID

def _decompiler():
    ifc = DecompInterface()
    DecOptions = DecompileOptions()
    service = state.getTool().getService(OptionsService)

    opt = service.getOptions("Decompiler")
    DecOptions.grabFromToolAndProgram(None, opt, currentProgram)
    ifc.setOptions(DecOptions)

    ifc.toggleCCode(True)
    ifc.toggleSyntaxTree(True)
    ifc.setSimplificationStyle("decompile")

    ifc.openProgram(currentProgram)
    return ifc
        
def decompile_func(ifc,func):
    res = ifc.decompileFunction(func,ifc.options.defaultTimeout,monitor)
    if not res.decompileCompleted():
        print res.getErrorMessage()
        raise Exception("Decompilation is not completed")

    hfunc = res.getHighFunction()
    if hfunc == None:
        raise Exception("Cannot get HighFunction")
    return hfunc

def fix_metacast(hfunc):
    print "[+] Fixing metacast ..."
    symIter = hfunc.getLocalSymbolMap().getSymbols()
    idx = 0
    mc_count = 0
    for op in hfunc.pcodeOps:
        addr = op.getSeqnum().getTarget()
        if op.opcode  == PcodeOp.CALL:
            argc = op.getNumInputs()
            caller = op.getInput(0)
            targetFunc = getSymbolAt(toAddr(caller.getOffset())).getName()
            output = op.getOutput()

            if targetFunc != "safeMetaCast":
                continue
            if argc != 3:
                popup("Bogus safeMetaCast() implementation")
                continue
            
            print "[+] Processing ", addr,op
            dt = process_metacast(op,hfunc)
            
            if dt == None:
                continue
            
            dt = PointerDataType(dt)
            if dt == None:
                raise Exception("no pointer data type for %s" %(dt.getName()))

            
            symIter = hfunc.getLocalSymbolMap()
            instr = currentProgram.getListing().getInstructionAt(output.getPCAddress()).getPcode()
            output =  op.getOutput()
            desc = output.getDescendants()
            
            if desc.hasNext() == False:
                raise Exception("No pcode op descandants ")

            if output.isRegister() == True:
                out = output
                high = out.getHigh()
                name = high.getName()
                symbol = high.getSymbol()
                curr_dt = high.getDataType()
                print '[!]', name,symbol,curr_dt
                var = hfunc.splitOutMergeGroup(high,out)
                HighFunctionDBUtil.updateDBVariable(symbol,"my_var"+str(idx),dt,SourceType.USER_DEFINED)
                idx+=1
                continue

            if not output.isUnique():
                raise Exception("What is this ? ")
            
            p = desc.next()
            if p.opcode == PcodeOp.CAST:
                out = p.getOutput()

                high = out.getHigh()
                name = high.getName()
                symbol = high.getSymbol()
                curr_dt = high.getDataType()
                

                print '[!]', name,symbol,curr_dt
                # we need to call newMappedSymbol() in this case
                if symbol == None:
                    continue
                
                var = hfunc.splitOutMergeGroup(high,out)
                
                HighFunctionDBUtil.updateDBVariable(symbol,name,dt,SourceType.USER_DEFINED)
                idx+=1
                
            else:
                if output.isRegister() == True:
                    continue
                raise Exception("Unhandled pcode operation ")
            
            continue
    return mc_count
            
#returns the datatype of the second input of safeMetacast
def process_metacast(op,hfunc):
    arg2 = op.getInput(2)
    
    if arg2.isRegister() == True:
        regDef = arg2.getDef()
        if regDef.opcode == PcodeOp.LOAD:
            if regDef.getNumInputs() != 2 or regDef.getInput(1).isUnique() == False:
                popup("Bogus defintion ")
                raise Exception
                return 
            uniqValDef = regDef.getInput(1).getDef()
            if uniqValDef.opcode == PcodeOp.CAST:
                input = uniqValDef.getInput(0)
                if input.isUnique():
                    return
                else:
                    d = getDataAt(toAddr(input.getOffset())).getValue()
                    sym = getSymbolAt(d).getName(True) # include namespace 
                if "::" in sym:
                    sym = sym.split("::")[0]
                    dt = findDataTypeByName(sym)

                    return dt
                else:

                    return None
    # not implemented
    elif arg2.isUnique():
        adef = arg2.getDef()
        if adef.opcode == PcodeOp.PTRSUB:
            arg = adef.getInput(1)
            if arg.isConstant() :
                sym = getSymbolAt(toAddr(arg.getOffset())).getName(True) # include namespace 
                if "::" in sym:
                    sym = sym.split("::")[0]
                    dt = findDataTypeByName(sym)
                    return dt

def findDataTypeByName(name):
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)
    dataTypeManagers = service.getDataTypeManagers();
    spaces = ["/" , "/Demangler/"]
    for manager in dataTypeManagers:
        for space in spaces:
            dataType = manager.getDataType(space+name)
            if dataType :
                return dataType
        
    return None

if __name__ == "__main__":

    ifc = _decompiler()
    entry = currentAddress 

    func  = getFunctionContaining(entry)

    hfunc = decompile_func(ifc,func)
    symIter = hfunc.getLocalSymbolMap().getSymbols()
    fix_metacast(hfunc)
    
    #HighFunctionDBUtil.commitLocalsToDatabase(hfunc,SourceType.USER_DEFINED)
    