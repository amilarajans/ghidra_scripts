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
// Repairs Boost Any Class DataTypes
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
import ghidra.app.util.demangler.DemangledDataType;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.data.DataTypeParser;
import ghidra.util.exception.InvalidInputException;

import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;
import static ghidra.program.model.listing.VariableUtilities.findOrCreateClassStruct;
import static ghidra.program.model.symbol.SourceType.USER_DEFINED;

public class BoostAny extends GhidraScript {

	private static final CategoryPath ANY = new CategoryPath("/boost/any");

	private static final String BOOST_PREFIX = "boost--tuples--";
	private static final Pattern TEMPLATE = Pattern.compile("[^\\<]*\\<(.*)\\>");
	private static final Pattern DEREFERENCE = Pattern.compile("([^\\&\\*]*).*");

	private DataTypeParser parser;
	private DataTypeManager dtm;
	private DataType placeholder;
	private SymbolTable table;
	private DataType typeFunction;

	private DataType parse(String token) throws Exception {
		try {
			return parser.parse(token);
		} catch (InvalidDataTypeException e) {
			Matcher matcher = DEREFERENCE.matcher(token);
			matcher.matches();
			DemangledDataType ddt = new DemangledDataType(matcher.group(1));
			dtm.resolve(ddt.getDataType(dtm), REPLACE_HANDLER);
			println(token);
			return parser.parse(token);
		}
	}

	private DataType getPointer(DataType dt) {
		final DataType result = dtm.resolve(dt, REPLACE_HANDLER);
		return dtm.getPointer(result, -1);
	}

	private DataType getTypeFunction() throws InvalidInputException {
		final CategoryPath path = new CategoryPath(ANY, "functions");
		final FunctionDefinition def = new FunctionDefinitionDataType(path, "type");
		final Namespace gc = NamespaceUtils.createNamespaceHierarchy(
			"std::type_info", null, currentProgram, USER_DEFINED);
		final DataType typeInfo = findOrCreateClassStruct((GhidraClass) gc, dtm);
		def.setReturnType(dtm.getPointer(typeInfo, -1));
		def.setGenericCallingConvention(GenericCallingConvention.thiscall);
		return getPointer(def);
	}

	private DataType getHeld(Structure struct) throws Exception {
		Matcher matcher = TEMPLATE.matcher(struct.getName());
		if (matcher.matches()) {
			final String held;
			if (matcher.group(1).startsWith(BOOST_PREFIX)) {
				held = matcher.group(1).substring(BOOST_PREFIX.length());
			} else {
				held = matcher.group(1);
			}
			return parse(held);
		}
		return null;
	}

	private DataType getCloneFunction(final Structure struct) throws Exception {
		final CategoryPath path = new CategoryPath(ANY, struct.getName());
		final FunctionDefinition def = new FunctionDefinitionDataType(
			path, struct.getName());
		final DataType held = getHeld(struct);
		def.setReturnType(dtm.getPointer(held, -1));
		def.setGenericCallingConvention(GenericCallingConvention.thiscall);
		return getPointer(def);
	}

	private DataType getVptr(final Structure struct) throws Exception {
		final CategoryPath path = new CategoryPath(ANY, struct.getName());
		final Structure vtable = new StructureDataType(path, "vtable", 0, dtm);
		final DataType destructor = getDestructor(struct);
		final DataType cloneFunction = getCloneFunction(struct);
		vtable.add(destructor, '~'+struct.getName(), null);
		vtable.add(destructor, '~'+struct.getName(), null);
		vtable.add(typeFunction, "type", null);
		vtable.add(cloneFunction, "clone", null);
		return getPointer(vtable);
	}

	private DataType getPlaceholder() throws Exception {
		final Structure struct = new StructureDataType(ANY, "placeholder", 0, dtm);
		final DataType vptr = getVptr(struct);
		struct.add(vptr, "_vptr", null);
		return dtm.resolve(struct, REPLACE_HANDLER);
	}

	private DataType getDestructor(final Structure struct) {
		final CategoryPath path = new CategoryPath(ANY, struct.getName());
		final FunctionDefinition def = new FunctionDefinitionDataType(path, '~'+struct.getName());
		def.setReturnType(DataType.VOID);
		def.setGenericCallingConvention(GenericCallingConvention.thiscall);
		return getPointer(def);
	}

	private void parseHolder(final Structure struct) throws Exception {
		struct.deleteAll();
		struct.setInternallyAligned(false);
		struct.add(placeholder, "super_placeholder", null);
		struct.add(getHeld(struct), "held", null);
		dtm.resolve(struct, REPLACE_HANDLER);
	}

	private static boolean filter(final Symbol symbol) {
		final SymbolType type = symbol.getSymbolType();
		if (type == SymbolType.CLASS) {
			return symbol.getName().startsWith("holder");
		}
		return false;
	}

	private Structure toDataType(final Symbol symbol) {
		return findOrCreateClassStruct((GhidraClass) symbol.getObject(), dtm);
	}

	private DataTypeParser getDataTypeParser() {
		final PluginTool tool = state.getTool();
		final DataTypeQueryService service = tool.getService(DataTypeQueryService.class);
		return new DataTypeParser(dtm, null, service, DataTypeParser.AllowedDataTypes.ALL);
	}

	@Override
	public void run() throws Exception {
		table = currentProgram.getSymbolTable();
		dtm = currentProgram.getDataTypeManager();
		parser = getDataTypeParser();
		typeFunction = getTypeFunction();
		placeholder = getPlaceholder();
		final Namespace any = NamespaceUtils.createNamespaceHierarchy(
			"boost::any", null, currentProgram, USER_DEFINED);
		List<Structure> types =
			StreamSupport.stream(table.getChildren(any.getSymbol()).spliterator(), false)
						 .filter(BoostAny::filter)
						 .map(this::toDataType)
						 .collect(Collectors.toList());
		monitor.initialize(types.size());
		monitor.setMessage("Repairing Boost Tuples");
		for (Structure type : types) {
			monitor.checkCanceled();
			parseHolder(type);
			monitor.incrementProgress(1);
		}
	}
}
