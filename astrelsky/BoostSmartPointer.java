/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2020 Andrew J. Strelsky
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */
// Repairs Boost Smart Pointer Class DataTypes
//@category Boost
//@author Andrew J. Strelsky

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.data.DataTypeParser;
import ghidra.util.exception.InvalidInputException;

import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;
import static ghidra.program.model.symbol.SourceType.USER_DEFINED;

public class BoostSmartPointer extends GhidraScript {

	private static final CategoryPath PATH = new CategoryPath("/boost/detail");
	private static final CategoryPath SP_PATH = new CategoryPath(PATH, "sp_counted_base");

	private static final Pattern T_PATTERN =
		Pattern.compile("sp_counted_base_impl\\<([^,]*),([^,\\>]*)\\>");

	private DataTypeParser parser;

	private DataType getBaseVptr() {
		final DataTypeManager dtm = currentProgram.getDataTypeManager();
		final DataType dt = dtm.getDataType(SP_PATH, "vtable");
		if (dt == null) {
			return dtm.getPointer(DataType.VOID, -1);
		}
		return dtm.getPointer(dt, -1);
	}

	private DataType getBase() {
		final DataTypeManager dtm = currentProgram.getDataTypeManager();
		final DataType longDt = LongDataType.dataType.clone(dtm);
		final DataType vptr = getBaseVptr();
		Structure struct = new StructureDataType(PATH, "sp_counted_base", 0, dtm);
		struct.add(vptr, "_vptr", null);
		struct.add(longDt, "use_count_", null);
		struct.add(longDt, "weak_count_", null);
		struct.setToDefaultAlignment();
		return dtm.resolve(struct, REPLACE_HANDLER);
	}

	private DataType getDeleter(String name) throws InvalidInputException {
		final DataTypeManager dtm = currentProgram.getDataTypeManager();
		Namespace ns = NamespaceUtils.createNamespaceHierarchy(
			name.replaceAll("--", "::"), null, currentProgram, USER_DEFINED);
		if (!(ns instanceof GhidraClass)) {
			ns = NamespaceUtils.convertNamespaceToClass(ns);
		}
		final Structure result = VariableUtilities.findOrCreateClassStruct((GhidraClass) ns, dtm);
		result.pack(-1);
		return result;
	}

	private DataType[] getTemplatedTypes(String name) throws Exception {
		Matcher matcher = T_PATTERN.matcher(name);
		if (matcher.matches()) {
			return new DataType[]{
				parser.parse(matcher.group(1)),
				getDeleter(matcher.group(2))
			};
		}
		return null;
	}

	private void fixDataType(Structure struct) throws Exception {
		final DataTypeManager dtm = currentProgram.getDataTypeManager();
		final DataType[] types = getTemplatedTypes(struct.getName());
		struct.deleteAll();
		struct.setInternallyAligned(false);
		struct.add(getBase(), "super_sp_counted_base", null);
		struct.add(types[0], "ptr", null);
		final int size = struct.getLength() + types[1].getLength();
		if (size < 0x20) {
			((Structure) types[1]).growStructure(0x20 - size);
		}
		struct.add(types[1], "del", null);
		dtm.resolve(struct, REPLACE_HANDLER);
	}

	private static boolean filter(Symbol symbol) {
		final SymbolType type = symbol.getSymbolType();
		if (type == SymbolType.CLASS) {
			return T_PATTERN.matcher(symbol.getName()).matches();
		}
		return false;
	}

	private Structure toDataType(Symbol symbol) {
		final DataTypeManager dtm = currentProgram.getDataTypeManager();
		return VariableUtilities.findOrCreateClassStruct((GhidraClass) symbol.getObject(), dtm);
	}

	private DataTypeParser getDataTypeParser() {
		final PluginTool tool = state.getTool();
		final DataTypeManager dtm = currentProgram.getDataTypeManager();
		final DataTypeQueryService service = tool.getService(DataTypeQueryService.class);
		return new DataTypeParser(dtm, null, service, DataTypeParser.AllowedDataTypes.ALL);
	}

	@Override
	public void run() throws Exception {
		parser = getDataTypeParser();
		final SymbolTable table = currentProgram.getSymbolTable();
		final Namespace detail = NamespaceUtils.createNamespaceHierarchy(
			"boost::detail", null, currentProgram, USER_DEFINED);
		List<Structure> types =
			StreamSupport.stream(table.getChildren(detail.getSymbol()).spliterator(), false)
						 .filter(BoostSmartPointer::filter)
						 .map(this::toDataType)
						 .collect(Collectors.toList());
		monitor.initialize(types.size());
		monitor.setMessage("Repairing Boost Smart Pointers");
		for (Structure type : types) {
			monitor.checkCanceled();
			fixDataType(type);
			monitor.incrementProgress(1);
		}
	}
}
