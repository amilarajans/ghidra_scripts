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
// Repairs Boost Tuple Class DataTypes
//@category Boost
//@author Andrew J. Strelsky

import java.util.ArrayDeque;
import java.util.Deque;
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
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.data.DataTypeParser;

import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;
import static ghidra.program.model.listing.VariableUtilities.findOrCreateClassStruct;
import static ghidra.program.model.symbol.SourceType.USER_DEFINED;

public class BoostTuple extends GhidraScript {

	private static final String NULL_TYPE = "boost--tuples--null_type";

	private static final String BOOST_PREFIX = "boost--tuples--";
	private static final Pattern TEMPLATE = Pattern.compile("[^\\<]*\\<(.*)\\>");
	private static final Pattern DEREFERENCE = Pattern.compile("([^\\&\\*]*).*");
	private static final int MAX_TUPLE_ELEMENTS = 10;

	private DataTypeParser parser;
	private DataTypeManager dtm;

	/*
		TUPLE HIEARCHY
		tuple {
			cons<...> {
				stored_head_type head; // first item
				tail_type tail; // cons of remaining items
			} super_cons<...>
		}
	*/

	private Deque<String> tokenize(String s) {
		final Matcher matcher = TEMPLATE.matcher(s);
		if (matcher.matches()) {
			s = matcher.group(1);
		}
		final Deque<String> result = new ArrayDeque<>(MAX_TUPLE_ELEMENTS);
		int tDepth = 0;
		int pos = 0;
		for (int i = 0; i < s.length(); i++) {
			switch(s.charAt(i)) {
				case ',':
					if (tDepth == 0) {
						result.push(s.substring(pos, i));
						pos = i+1;
					}
					break;
				case '<':
					tDepth++;
					break;
				case '>':
					tDepth--;
					break;
				default:
					break;
			}
		}
		result.push(s.substring(pos));
		return result;
	}

	private DataType parse(String token, CategoryPath path) throws Exception {
		try {
			return parser.parse(token);
		} catch (InvalidDataTypeException e) {
			Matcher matcher = DEREFERENCE.matcher(token);
			matcher.matches();
			DemangledDataType ddt = new DemangledDataType(matcher.group(1));
			dtm.resolve(ddt.getDataType(dtm), REPLACE_HANDLER);
			return parser.parse(token);
		}
	}

	private DataType getTailLessCons(final String token, final CategoryPath path)
		throws Exception {
			final DataType head = parse(token, path);
			final String name = String.format("cons<%s,%s>", token, NULL_TYPE);
			final Structure cons = new StructureDataType(path, name, 0, dtm);
			cons.add(head, "head", null);
			return dtm.resolve(cons, REPLACE_HANDLER);
	}

	private DataType getNextCons(String token, final DataType tail,
		final CategoryPath path) throws Exception {
			final DataType head = parse(token, path);
			final String name = String.format("cons<%s,%s>", token, BOOST_PREFIX+tail.getName());
			final Structure cons = new StructureDataType(path, name, 0, dtm);
			cons.add(head, "head", null);
			cons.add(tail, "tail", null);
			return dtm.resolve(cons, REPLACE_HANDLER);
	}

	private void parseTuple(final Structure struct) throws Exception {
		final CategoryPath path = struct.getCategoryPath();
		final Deque<String> tokens = tokenize(struct.getName());
		DataType superDt;
		if (tokens.size() % 2 == 0) {
			superDt = getTailLessCons(tokens.pop(), path);
		} else {
			superDt = parse(tokens.pop(), path);
		}
		while (!tokens.isEmpty()) {
			superDt = getNextCons(tokens.pop(), superDt, path);
		}
		struct.deleteAll();
		struct.setInternallyAligned(false);
		struct.add(superDt, "super_"+superDt.getName(), null);
		dtm.resolve(struct, REPLACE_HANDLER);
	}

	private static boolean filter(Symbol symbol) {
		final SymbolType type = symbol.getSymbolType();
		if (type == SymbolType.CLASS) {
			return symbol.getName().startsWith("tuple");
		}
		return false;
	}

	private Structure toDataType(Symbol symbol) {
		return findOrCreateClassStruct((GhidraClass) symbol.getObject(), dtm);
	}

	private DataTypeParser getDataTypeParser() {
		final PluginTool tool = state.getTool();
		final DataTypeQueryService service = tool.getService(DataTypeQueryService.class);
		return new DataTypeParser(dtm, null, service, DataTypeParser.AllowedDataTypes.ALL);
	}

	@Override
	public void run() throws Exception {
		dtm = currentProgram.getDataTypeManager();
		parser = getDataTypeParser();
		final SymbolTable table = currentProgram.getSymbolTable();
		final Namespace tuple = NamespaceUtils.createNamespaceHierarchy(
			"boost::tuples", null, currentProgram, USER_DEFINED);
		List<Structure> types =
			StreamSupport.stream(table.getChildren(tuple.getSymbol()).spliterator(), false)
						 .filter(BoostTuple::filter)
						 .map(this::toDataType)
						 .collect(Collectors.toList());
		monitor.initialize(types.size());
		monitor.setMessage("Repairing Boost Tuples");
		for (Structure type : types) {
			monitor.checkCanceled();
			parseTuple(type);
			monitor.incrementProgress(1);
		}
	}
}
