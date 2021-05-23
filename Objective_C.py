#Parse Objective C
#@author Guy Ishay
#@category iOS
#@keybinding 
#@menupath 
#@toolbar 
import jarray
import ghidra.program.model.data.StringDataType as StringDataType


def test():
	objc_struct = read_objc_metadata(currentProgram.getAddressFactory().getAddress("0x96a020"))
	print(objc_struct)

def main():
	syms = get_syms()
	objc_struct_addr_list = read_objc_exports(syms)
	objc_metadata_addr_list = read_objc_metadata_from_list(objc_struct_addr_list)
	rename_methods(objc_metadata_addr_list)


def get_symbol_at_addr(addr):
	return currentProgram.getSymbolTable().getPrimarySymbol(addr)

def rename_methods(objc_list):
	for objc in objc_list:
		try:
			method_names = objc['method_names']
			method_addrs = objc['method_addrs']
			for i in range(0, len(method_names)):
				method_name = method_names[i]
				method_addr = method_addrs[i]
				s = get_symbol_at_addr(create_addr(method_addr))
				if s:
					new_method_name = objc['class_name'] + '::' + method_name
					print('renaming %s to %s' % (method_addr, new_method_name))
					s.setName(new_method_name, ghidra.program.model.symbol.SourceType.ANALYSIS)
		except KeyError as e:
			print('no method names key in objective c struct')
			continue
		

def get_syms():
	# global objc_structs_sym
	objc_structs_sym = []
	symbols = currentProgram.getSymbolTable().getAllSymbols(False)
	for s in symbols:
		if monitor.isCancelled():
			break
		sym_name = s.getName()
		if not 'OBJC_CLASS' in sym_name:
			continue
		objc_structs_sym.append(s)
	return objc_structs_sym


def addr_is_init(addr):
	return currentProgram.getMemory().getBlock(addr).isInitialized()


def read_objc_exports(objc_structs_sym):
	addr_list = []
	for objc_struct in objc_structs_sym:
		if monitor.isCancelled():
			break
		
		if not addr_is_init(objc_struct.getAddress()):
			continue
		addr = currentProgram.getMemory().getLong(objc_struct.getAddress())
		addr_list.append(addr)
	return addr_list

def read_objc_metadata_from_list(objc_struct_addr_list):
	objc_metadata_list = []
	for objc_struct_addr in objc_struct_addr_list:
		objc_struct_addr = create_addr(objc_struct_addr)
		if monitor.isCancelled():
			break

		if not addr_is_init(objc_struct_addr):
			continue
		try:
			objc_metadata_list.append(read_objc_metadata(objc_struct_addr))
		#not proud of the following catch statements
		except ghidra.program.model.address.AddressOutOfBoundsException as e:
			print(e)
		except AssertionError as e:
			print(e)
		except ghidra.program.model.mem.MemoryAccessException as e:
			print(e)
	print(len(objc_metadata_list))
	return objc_metadata_list

def create_addr(_addr):
	# long conversion didn't work for some reason
	return currentProgram.getAddressFactory().getAddress("0x00").add(_addr)
	
def getStringAtAddr(addr):
    """Get string at an address, if present"""
    data = getDataAt(addr)
    if data is not None:
        dt = data.getDataType()
        if dt.getName() == 'TerminatedCString':
            return str(data)[4:-1]
    return None

# read objective c struct
def read_objc_metadata(addr):
	objc = {}
	mem = currentProgram.getMemory()
	if not addr_is_init(addr):
		raise Exception("addr is not initialized")
	objc['class_t'] = mem.getLong(addr)
	objc['num_methods'] = mem.getInt(addr.add(52)) # offset from base of metadata to num methods
	cur_method_offset = 80
	methods = []
	for i in range(0, objc['num_methods']):
		method_addr = mem.getLong(addr.add(cur_method_offset))
		cur_method_offset += 8
		methods.append(method_addr)
	objc['method_addrs'] = methods

	# print('class_t', objc['class_t'])
	class_data_ptr_addr = create_addr(objc['class_t']).add(32)
	class_data_addr = mem.getLong(class_data_ptr_addr)
	base_protocols_addr = create_addr(mem.getLong(create_addr(class_data_addr).add(40)))

	if base_protocols_addr.equals(create_addr(0x0)):
		return objc

	protocol_count = mem.getLong(base_protocols_addr)
	cur_protocol = base_protocols_addr.add(8)
	protocols = []
	for i in range(0, protocol_count):
		protocols.append(create_addr(mem.getLong(cur_protocol)))
		cur_protocol = cur_protocol.add(8)

	assert len(protocols) == 1

	chosen_protocol = protocols[0]
	objc['class_name'] = getStringAtAddr(create_addr(mem.getLong(chosen_protocol.add(8))))

	assert objc['class_name'] != None

	method_list_addr = create_addr(mem.getLong(chosen_protocol.add(24)))
	methods_size = mem.getInt(method_list_addr.add(4))

	method_names = []
	cur_method = method_list_addr.add(8)
	for i in range(0, methods_size):
		method_name_addr = create_addr(mem.getLong(cur_method))
		method_names.append(getStringAtAddr(method_name_addr))
		cur_method = cur_method.add(24)

	assert methods_size == objc['num_methods']

	objc['method_names'] = method_names
	return objc


# test()
main()