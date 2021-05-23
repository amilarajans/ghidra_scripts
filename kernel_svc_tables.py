#@author: Adubbz
#@category kernal
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.services import DataTypeManagerService
from ghidra.app.util.parser import FunctionSignatureParser
from ghidra.program.model.data import DataType
from ghidra.program.disassemble import Disassembler
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TaskMonitor

SVC_MAPPINGS = {
    0x01 : ("SetHeapSize", "Result  %s(uintptr_t *out_address, size_t size);"),
    0x02 : ("SetMemoryPermission", "Result  %s(uintptr_t address, size_t size, MemoryPermission perm);"),
    0x03 : ("SetMemoryAttribute", "Result  %s(uintptr_t address, size_t size, uint32_t mask, uint32_t attr);"),
    0x04 : ("MapMemory", "Result  %s(uintptr_t dst_address, uintptr_t src_address, size_t size);"),
    0x05 : ("UnmapMemory", "Result  %s(uintptr_t dst_address, uintptr_t src_address, size_t size);"),
    0x06 : ("QueryMemory", "Result  %s(MemoryInfo *out_memory_info, PageInfo *out_page_info, uintptr_t address);"),
    0x07 : ("ExitProcess", "void    %s();"),
    0x08 : ("CreateThread", "Result  %s(Handle *out_handle, ThreadFunc func, uintptr_t arg, uintptr_t stack_bottom, int32_t priority, int32_t core_id);"),
    0x09 : ("StartThread", "Result  %s(Handle thread_handle);"),
    0x0A : ("ExitThread", "void    %s();"),
    0x0B : ("SleepThread", "void    %s(int64_t ns);"),
    0x0C : ("GetThreadPriority", "Result  %s(int32_t *out_priority, Handle thread_handle);"),
    0x0D : ("SetThreadPriority", "Result  %s(Handle thread_handle, int32_t priority);"),
    0x0E : ("GetThreadCoreMask", "Result  %s(int32_t *out_core_id, uint64_t *out_affinity_mask, Handle thread_handle);"),
    0x0F : ("SetThreadCoreMask", "Result  %s(Handle thread_handle, int32_t core_id, uint64_t affinity_mask);"),
    0x10 : ("GetCurrentProcessorNumber", "int32_t %s();"),
    0x11 : ("SignalEvent", "Result  %s(Handle event_handle);"),
    0x12 : ("ClearEvent", "Result  %s(Handle event_handle);"),
    0x13 : ("MapSharedMemory", "Result  %s(Handle shmem_handle, uintptr_t address, size_t size, MemoryPermission map_perm);"),
    0x14 : ("UnmapSharedMemory", "Result  %s(Handle shmem_handle, uintptr_t address, size_t size);"),
    0x15 : ("CreateTransferMemory", "Result  %s(Handle *out_handle, uintptr_t address, size_t size, MemoryPermission map_perm);"),
    0x16 : ("CloseHandle", "Result  %s(Handle handle);"),
    0x17 : ("ResetSignal", "Result  %s(Handle handle);"),
    0x18 : ("WaitSynchronization", "Result  %s(int32_t *out_index, const Handle *handles, int32_t numHandles, int64_t timeout_ns);"),
    0x19 : ("CancelSynchronization", "Result  %s(Handle handle);"),
    0x1A : ("ArbitrateLock", "Result  %s(Handle thread_handle, uintptr_t address, uint32_t tag);"),
    0x1B : ("ArbitrateUnlock", "Result  %s(uintptr_t address);"),
    0x1C : ("WaitProcessWideKeyAtomic", "Result  %s(uintptr_t address, uintptr_t cv_key, uint32_t tag, int64_t timeout_ns);"),
    0x1D : ("SignalProcessWideKey", "void    %s(uintptr_t cv_key, int32_t count);"),
    0x1E : ("GetSystemTick", "int64_t %s();"),
    0x1F : ("ConnectToNamedPort", "Result  %s(Handle *out_handle, const char *name);"),
    0x20 : ("SendSyncRequestLight", "Result  %s(Handle session_handle);"),
    0x21 : ("SendSyncRequest", "Result  %s(Handle session_handle);"),
    0x22 : ("SendSyncRequestWithUserBuffer", "Result  %s(uintptr_t message_buffer, size_t message_buffer_size, Handle session_handle);"),
    0x23 : ("SendAsyncRequestWithUserBuffer", "Result  %s(Handle *out_event_handle, uintptr_t message_buffer, size_t message_buffer_size, Handle session_handle);"),
    0x24 : ("GetProcessId", "Result  %s(uint64_t *out_process_id, Handle process_handle);"),
    0x25 : ("GetThreadId", "Result  %s(uint64_t *out_thread_id, Handle thread_handle);"),
    0x26 : ("Break", "void    %s(BreakReason break_reason, uintptr_t arg, size_t size);"),
    0x27 : ("OutputDebugString", "Result  %s(const char *debug_str, size_t len);"),
    0x28 : ("ReturnFromException", "void    %s(Result result);"),
    0x29 : ("GetInfo", "Result  %s(uint64_t *out, InfoType info_type, Handle handle, uint64_t info_subtype);"),
    0x2A : ("FlushEntireDataCache", "void    %s();"),
    0x2B : ("FlushDataCache", "Result  %s(uintptr_t address, size_t size);"),
    0x2C : ("MapPhysicalMemory", "Result  %s(uintptr_t address, size_t size);"),
    0x2D : ("UnmapPhysicalMemory", "Result  %s(uintptr_t address, size_t size);"),
    0x2E : ("GetDebugFutureThreadInfo", "Result  %s(SvcLastThreadContext|| *out_context, uint64_t *thread_id, Handle debug_handle, int64_t ns);"),
    0x2F : ("GetLastThreadInfo", "Result  %s(SvcLastThreadContext|| *out_context, uintptr_t *out_tls_address, uint32_t *out_flags);"),
    0x30 : ("GetResourceLimitLimitValue", "Result  %s(int64_t *out_limit_value, Handle resource_limit_handle, LimitableResource which);"),
    0x31 : ("GetResourceLimitCurrentValue", "Result  %s(int64_t *out_current_value, Handle resource_limit_handle, LimitableResource which);"),
    0x32 : ("SetThreadActivity", "Result  %s(Handle thread_handle, ThreadActivity thread_activity);"),
    0x33 : ("GetThreadContext3", "Result  %s(ThreadContext *out_context, Handle thread_handle);"),
    0x34 : ("WaitForAddress", "Result  %s(uintptr_t address, ArbitrationType arb_type, int32_t value, int64_t timeout_ns);"),
    0x35 : ("SignalToAddress", "Result  %s(uintptr_t address, SignalType signal_type, int32_t value, int32_t count);"),
    0x36 : ("SynchronizePreemptionState", "void    %s();"),
    0x3C : ("KernelDebug", "void    %s(KernelDebugType kern_debug_type, uint64_t arg0, uint64_t arg1, uint64_t arg2);"),
    0x3D : ("ChangeKernelTraceState", "void    %s(KernelTraceState kern_trace_state);"),
    0x40 : ("CreateSession", "Result  %s(Handle *out_server_session_handle, Handle *out_client_session_handle, bool is_light, uintptr_t name);"),
    0x41 : ("AcceptSession", "Result  %s(Handle *out_handle, Handle port);"),
    0x42 : ("ReplyAndReceiveLight", "Result  %s(Handle handle);"),
    0x43 : ("ReplyAndReceive", "Result  %s(int32_t *out_index, const Handle *handles, int32_t num_handles, Handle reply_target, int64_t timeout_ns);"),
    0x44 : ("ReplyAndReceiveWithUserBuffer", "Result  %s(int32_t *out_index, uintptr_t message_buffer, size_t message_buffer_size, const Handle *handles, int32_t num_handles, Handle reply_target, int64_t timeout_ns);"),
    0x45 : ("CreateEvent", "Result  %s(Handle *out_write_handle, Handle *out_read_handle);"),
    0x48 : ("MapPhysicalMemoryUnsafe", "Result  %s(uintptr_t address, size_t size);"),
    0x49 : ("UnmapPhysicalMemoryUnsafe", "Result  %s(uintptr_t address, size_t size);"),
    0x4A : ("SetUnsafeLimit", "Result  %s(size_t limit);"),
    0x4B : ("CreateCodeMemory", "Result  %s(Handle *out_handle, uintptr_t address, size_t size);"),
    0x4C : ("ControlCodeMemory", "Result  %s(Handle code_memory_handle, CodeMemoryOperation operation, uint64_t address, uint64_t size, MemoryPermission perm);"),
    0x4D : ("SleepSystem", "void    %s();"),
    0x4E : ("ReadWriteRegister", "Result  %s(uint32_t *out_value, PhysicalAddress address, uint32_t mask, uint32_t value);"),
    0x4F : ("SetProcessActivity", "Result  %s(Handle process_handle, ProcessActivity process_activity);"),
    0x50 : ("CreateSharedMemory", "Result  %s(Handle *out_handle, size_t size, MemoryPermission owner_perm, MemoryPermission remote_perm);"),
    0x51 : ("MapTransferMemory", "Result  %s(Handle trmem_handle, uintptr_t address, size_t size, MemoryPermission owner_perm);"),
    0x52 : ("UnmapTransferMemory", "Result  %s(Handle trmem_handle, uintptr_t address, size_t size);"),
    0x53 : ("CreateInterruptEvent", "Result  %s(Handle *out_read_handle, int32_t interrupt_id, InterruptType interrupt_type);"),
    0x54 : ("QueryPhysicalAddress", "Result  %s(SvcPhysicalMemoryInfo|| *out_info, uintptr_t address);"),
    0x55 : ("QueryIoMapping", "Result  %s(uintptr_t *out_address, PhysicalAddress physical_address, size_t size);"),
    0x56 : ("CreateDeviceAddressSpace", "Result  %s(Handle *out_handle, uint64_t das_address, uint64_t das_size);"),
    0x57 : ("AttachDeviceAddressSpace", "Result  %s(DeviceName device_name, Handle das_handle);"),
    0x58 : ("DetachDeviceAddressSpace", "Result  %s(DeviceName device_name, Handle das_handle);"),
    0x59 : ("MapDeviceAddressSpaceByForce", "Result  %s(Handle das_handle, Handle process_handle, uint64_t process_address, size_t size, uint64_t device_address, MemoryPermission device_perm);"),
    0x5A : ("MapDeviceAddressSpaceAligned", "Result  %s(Handle das_handle, Handle process_handle, uint64_t process_address, size_t size, uint64_t device_address, MemoryPermission device_perm);"),
    0x5B : ("MapDeviceAddressSpace", "Result  %s(size_t *out_mapped_size, Handle das_handle, Handle process_handle, uint64_t process_address, size_t size, uint64_t device_address, MemoryPermission device_perm);"),
    0x5C : ("UnmapDeviceAddressSpace", "Result  %s(Handle das_handle, Handle process_handle, uint64_t process_address, size_t size, uint64_t device_address);"),
    0x5D : ("InvalidateProcessDataCache", "Result  %s(Handle process_handle, uint64_t address, uint64_t size);"),
    0x5E : ("StoreProcessDataCache", "Result  %s(Handle process_handle, uint64_t address, uint64_t size);"),
    0x5F : ("FlushProcessDataCache", "Result  %s(Handle process_handle, uint64_t address, uint64_t size);"),
    0x60 : ("DebugActiveProcess", "Result  %s(Handle *out_handle, uint64_t process_id);"),
    0x61 : ("BreakDebugProcess", "Result  %s(Handle debug_handle);"),
    0x62 : ("TerminateDebugProcess", "Result  %s(Handle debug_handle);"),
    0x63 : ("GetDebugEvent", "Result  %s(DebugEventInfo|| *out_info, Handle debug_handle);"),
    0x64 : ("ContinueDebugEvent", "Result  %s(Handle debug_handle, uint32_t flags, const uint64_t *thread_ids, int32_t num_thread_ids);"),
    0x65 : ("GetProcessList", "Result  %s(int32_t *out_num_processes, uint64_t *out_process_ids, int32_t max_out_count);"),
    0x66 : ("GetThreadList", "Result  %s(int32_t *out_num_threads, uint64_t *out_thread_ids, int32_t max_out_count, Handle debug_handle);"),
    0x67 : ("GetDebugThreadContext", "Result  %s(ThreadContext *out_context, Handle debug_handle, uint64_t thread_id, uint32_t context_flags);"),
    0x68 : ("SetDebugThreadContext", "Result  %s(Handle debug_handle, uint64_t thread_id, const ThreadContext *context, uint32_t context_flags);"),
    0x69 : ("QueryDebugProcessMemory", "Result  %s(MemoryInfo *out_memory_info, PageInfo *out_page_info, Handle process_handle, uintptr_t address);"),
    0x6A : ("ReadDebugProcessMemory", "Result  %s(uintptr_t buffer, Handle debug_handle, uintptr_t address, size_t size);"),
    0x6B : ("WriteDebugProcessMemory", "Result  %s(Handle debug_handle, uintptr_t buffer, uintptr_t address, size_t size);"),
    0x6C : ("SetHardwareBreakPoint", "Result  %s(HardwareBreakPointRegisterName name, uint64_t flags, uint64_t value);"),
    0x6D : ("GetDebugThreadParam", "Result  %s(uint64_t *out_64, uint32_t *out_32, Handle debug_handle, uint64_t thread_id, DebugThreadParam param);"),
    0x6F : ("GetSystemInfo", "Result  %s(uint64_t *out, SystemInfoType info_type, Handle handle, uint64_t info_subtype);"),
    0x70 : ("CreatePort", "Result  %s(Handle *out_server_handle, Handle *out_client_handle, int32_t max_sessions, bool is_light, uintptr_t name);"),
    0x71 : ("ManageNamedPort", "Result  %s(Handle *out_server_handle, const char *name, int32_t max_sessions);"),
    0x72 : ("ConnectToPort", "Result  %s(Handle *out_handle, Handle port);"),
    0x73 : ("SetProcessMemoryPermission", "Result  %s(Handle process_handle, uint64_t address, uint64_t size, MemoryPermission perm);"),
    0x74 : ("MapProcessMemory", "Result  %s(uintptr_t dst_address, Handle process_handle, uint64_t src_address, size_t size);"),
    0x75 : ("UnmapProcessMemory", "Result  %s(uintptr_t dst_address, Handle process_handle, uint64_t src_address, size_t size);"),
    0x76 : ("QueryProcessMemory", "Result  %s(MemoryInfo *out_memory_info, PageInfo *out_page_info, Handle process_handle, uint64_t address);"),
    0x77 : ("MapProcessCodeMemory", "Result  %s(Handle process_handle, uint64_t dst_address, uint64_t src_address, uint64_t size);"),
    0x78 : ("UnmapProcessCodeMemory", "Result  %s(Handle process_handle, uint64_t dst_address, uint64_t src_address, uint64_t size);"),
    0x79 : ("CreateProcess", "Result  %s(Handle *out_handle, const CreateProcessParameter *parameters, const uint32_t *caps, int32_t num_caps);"),
    0x7A : ("StartProcess", "Result  %s(Handle process_handle, int32_t priority, int32_t core_id, uint64_t main_thread_stack_size);"),
    0x7B : ("TerminateProcess", "Result  %s(Handle process_handle);"),
    0x7C : ("GetProcessInfo", "Result  %s(int64_t *out_info, Handle process_handle, ProcessInfoType info_type);"),
    0x7D : ("CreateResourceLimit", "Result  %s(Handle *out_handle);"),
    0x7E : ("SetResourceLimitLimitValue", "Result  %s(Handle resource_limit_handle, LimitableResource which, int64_t limit_value);"),
    0x7F : ("CallSecureMonitor", "void    %s(SecureMonitorArguments *args);"),
}

disassembler = Disassembler.getDisassembler(currentProgram, TaskMonitor.DUMMY, None)
seg_mapping = {block.getName(): (block.getStart().getOffset(), block.getEnd().getOffset()) for block in getMemoryBlocks()}

text_start, text_end = seg_mapping['.text']

def IsInText(ea):
    return text_start <= ea and ea < text_end

def Test(ea):
    unknowns = []
    for svc_id in xrange(0x80):
        ea_svc32 = ea + 8 * svc_id
        ea_svc64 = ea_svc32 + 0x80 * 8

        try:
            val32 = getLong(toAddr(ea_svc32))
            val64 = getLong(toAddr(ea_svc64))
        except ghidra.program.model.mem.MemoryAccessException as err:
            return False

        if svc_id in SVC_MAPPINGS.keys():
            if not IsInText(val32):
                return False
            if not IsInText(val64):
                return False
        else:
            if val32 == 0 and val64 == 0:
                continue
            elif val32 == 0 or val64 == 0:
                return False
            else:
                unknowns.append(svc_id)
    for unknown in unknowns:
        print '[!] Possible unknown SVC 0x%02x' % unknown
    return True

rodata_mappings = {x: seg_mapping[x] for x in seg_mapping.keys() if x.startswith('.rodata')}

candidates = []
for (seg_name, (seg_start, seg_end)) in rodata_mappings.items():
    print 'Looking at %s (%08x-%08x)...' % (seg_name, seg_start, seg_end)
    ea = seg_start & ~7
    while ea < seg_end:
        if Test(ea):
            candidates.append(ea)
        ea += 8

assert(len(candidates) == 1)
svc_table32 = candidates[0]
svc_table64 = svc_table32 + 0x80 * 8
print 'Found Svc Tables: %08x %08x' % (svc_table32, svc_table64)

BLS_32   = {}
BLS_64   = {}
BLS_BOTH = {}

def GetBl(func_ea):
    bls = []
    body = getFunctionAt(toAddr(func_ea)).getBody()
    for insn in currentProgram.getListing().getInstructions(body, True):
        disasm = insn.toString().lstrip().rstrip().replace(',',' ')
        if ';' in disasm:
            disasm = disasm[:disasm.index(';')]
        disasm = disasm.split()
        if len(disasm) != 2:
            continue
        if disasm[0].lower() == 'bl':
            bls.append(disasm[1])
    assert(len(bls) in [0, 1])
    if len(bls) == 1:
        # TODO
        target_func = int(bls[0], 0x10)
        assert(IsInText(target_func))
        return target_func
    else:
        return None

def GetMutualBl(func_ea):
    bls = []
    disasms = []
    body = getFunctionAt(toAddr(func_ea)).getBody()
    for insn in currentProgram.getListing().getInstructions(body, True):
        disasm = insn.toString().lstrip().rstrip().replace(',',' ')
        if ';' in disasm:
            disasm = disasm[:disasm.index(';')]
        disasm = disasm.split()
        disasms.append(disasm)
        if len(disasm) != 2:
            continue
        if disasm[0].lower() == 'bl':
            bls.append(disasm[1])
    if len(bls) == 1:
        target_func = int(bls[0], 0x10)
        assert(IsInText(target_func))
        if len(disasms) >= 3:
            if disasms[0][0].lower() != 'stp':
                return None
            if disasms[-1][0].lower() != 'ret':
                if disasms[-1][0].lower() == 'bl':
                    return target_func
                return None
            if disasms[-2][0].lower() != 'ldp':
                return None
            return target_func
        elif len(disasms) >= 2:
            if disasms[0][0].lower() != 'stp':
                return None
            if disasms[-1][0].lower() != 'bl':
                return target_func
            return target_func
        else:
            return None
    else:
        return None

def IsTrampoline(func_ea):
    disasm = getInstructionAt(toAddr(func_ea)).toString().lstrip().rstrip().replace(', ',' ').split()
    return disasm[0].lower() == 'b'

def GetBranch(func_ea):
    disasm = getInstructionAt(toAddr(func_ea)).toString().lstrip().rstrip().replace(', ',' ').split()
    assert disasm[0].lower() == 'b'
    target_func = int(disasm[1], 0x10)
    assert IsInText(target_func)
    return target_func

def GetOrCreateFunction(ea):
    addr = toAddr(ea)
    func = getFunctionAt(addr)
    if not func:
        disassembler.disassemble(addr, None)
        if getSymbolAt(addr) and getInstructionAt(addr):
            func = createFunction(addr, None)
    return func

def SetSignature(ea, sig):
    sig = sig.replace(';', '').replace('const', '')
    orig_func = getFunctionAt(toAddr(ea))
    assert orig_func, 'No function at %x' % ea
    parser = FunctionSignatureParser(currentProgram.getDataTypeManager(), state.getTool().getService(DataTypeManagerService))
    
    try:
        parsed_sig = parser.parse(orig_func.getSignature(), sig)
    except ghidra.app.util.cparser.C.ParseException as err:
        print 'Bad signature %s' % sig
        raise err

    cmd = ApplyFunctionSignatureCmd(orig_func.getEntryPoint(), parsed_sig, SourceType.USER_DEFINED, True, False)
    if not state.getTool().execute(cmd, currentProgram):
        print cmd.getStatusMsg()
        return False
    return True


# Process Tables
for svc_id in SVC_MAPPINGS.keys():
    ea_func32 = getLong(toAddr(svc_table32 + 8 * svc_id))
    ea_func64 = getLong(toAddr(svc_table64 + 8 * svc_id))
    assert(GetOrCreateFunction(ea_func32))
    assert(GetOrCreateFunction(ea_func64))
    bl32 = GetBl(ea_func32)
    bl64 = GetBl(ea_func64)
    if bl32 == bl64 and bl32:
        BLS_BOTH[svc_id] = bl32
    else:
        if bl32:
            BLS_32[svc_id] = bl32
        if bl64:
            BLS_64[svc_id] = bl64

for (svc_id, (svc_name, svc_type)) in SVC_MAPPINGS.items():
    ea_func32 = getLong(toAddr(svc_table32 + 8 * svc_id))
    ea_func64 = getLong(toAddr(svc_table64 + 8 * svc_id))
    func_32 = GetOrCreateFunction(ea_func32)
    func_64 = GetOrCreateFunction(ea_func64)
    svc_name32 = '%s64From32' % svc_name
    svc_name64 = '%s64' % svc_name
    createLabel(toAddr(ea_func32), 'Svc%s' % svc_name32, True)
    SetSignature(ea_func32, 'void %s();' % svc_name)
    createLabel(toAddr(ea_func64), 'Svc%s' % svc_name64, True)
    SetSignature(ea_func64, 'void %s();' % svc_name)
    if svc_id in BLS_BOTH:
        assert('||' not in svc_type)
        GetOrCreateFunction(BLS_BOTH[svc_id])
        createLabel(toAddr(BLS_BOTH[svc_id]), 'Svc%s' % svc_name, True)
        SetSignature(BLS_BOTH[svc_id], svc_type % svc_name)
    else:
        if svc_id in BLS_32:
            createLabel(toAddr(BLS_32[svc_id]), svc_name32, True)
            SetSignature(BLS_32[svc_id], svc_type.replace('||', '32') % svc_name32)
        if svc_id in BLS_64:
            createLabel(toAddr(BLS_64[svc_id]), svc_name64, True)
            SetSignature(BLS_64[svc_id], svc_type.replace('||', '64') % svc_name64)
        if svc_id in BLS_32 and svc_id in BLS_64:
            subbl32 = GetMutualBl(BLS_32[svc_id])
            subbl64 = GetMutualBl(BLS_64[svc_id])
            if subbl32 is not None and subbl64 is not None:
                if subbl32 == subbl64:
                    assert('||' not in svc_type)
                    createLabel(toAddr(subbl64), svc_name, True)
                    SetSignature(subbl64, svc_type % svc_name)
            elif IsTrampoline(BLS_32[svc_id]) and IsTrampoline(BLS_64[svc_id]):
                b32 = GetBranch(BLS_32[svc_id])
                b64 = GetBranch(BLS_64[svc_id])
                if b32 == b64:
                    assert('||' not in svc_type)
                    removeFunctionAt(toAddr(BLS_32[svc_id]))
                    removeFunctionAt(toAddr(BLS_64[svc_id]))
                    removeFunctionAt(toAddr(b32))
                    createFunction(toAddr(b32), None)
                    createFunction(toAddr(BLS_32[svc_id]), None)
                    createFunction(toAddr(BLS_64[svc_id]), None)
                    GetOrCreateFunction(b64)
                    createLabel(toAddr(b64), svc_name, True)
                    SetSignature(b64, svc_type % svc_name)