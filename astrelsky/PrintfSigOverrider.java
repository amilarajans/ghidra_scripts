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
// Overrides printf calls with the varargs parameter replaced by the format specifiers.
// This helps the decompiler with type propogation.
//@category Functions
//@author Andrew J. Strelsky

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.*;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PrintfSigOverrider extends GhidraScript {

    private static final String PRINT_F = "printf";
    private static final String UNSUPPORTED_MESSAGE =
		"Currently only processors passing parameters via registers are supported.";
	private static final String TMP_NAME = "tmpname";
	private static final String NAME_ROOT = "prt";
	private static final String AUTO_CAT = "/auto_proto";

    private static final Pattern FORMAT_PATTERN =
        Pattern.compile("%\\d*([lLh]?[cdieEfgGosuxXpn])");

	private static final DataType CHAR_PTR = PointerDataType.getPointer(CharDataType.dataType, -1);

	private SymbolTable table;
	private DataTypeManager dtm;

	private static boolean isFunction(Symbol s) {
		return s.getSymbolType() == SymbolType.FUNCTION;
	}

	private static boolean isCall(Reference r) {
		final RefType type = r.getReferenceType();
		if (type.isCall()) {
			return !(type.isComputed() || type.isIndirect());
		}
		return false;
	}

    @Override
    public void run() throws Exception {
		dtm = currentProgram.getDataTypeManager();
		table = currentProgram.getSymbolTable();
		Optional<Symbol> s = StreamSupport.stream(currentProgram.getSymbolTable()
			.getSymbolIterator(PRINT_F, true)
			.spliterator(), false)
			.filter(PrintfSigOverrider::isFunction)
			.findFirst();
		if (s.isPresent()) {
			Parameter format = ((Function) s.get().getObject()).getParameter(0);
			if (format == null) {
				printerr("Unable to retrieve format parameter");
				return;
			}
			if (!format.isRegisterVariable()) {
				popup(UNSUPPORTED_MESSAGE);
				return;
			}
			final ReferenceManager manager = currentProgram.getReferenceManager();
			List<Address> addresses = Arrays.stream(s.get().getReferences())
				.filter(PrintfSigOverrider::isCall)
				.map(Reference::getFromAddress)
				.filter(Predicate.not(manager::hasReferencesTo))
				.collect(Collectors.toList());
			monitor.initialize(addresses.size());
			monitor.setMessage("Overriding printf calls");
			for (Address address : addresses) {
				monitor.checkCanceled();
				Function function = getFunctionContaining(address);
				if (function == null) {
					monitor.incrementProgress(1);
					continue;
				}
				SymbolicPropogator prop;
				try {
					prop = analyzeFunction(function, monitor);
				} catch (AddressOutOfBoundsException e) {
					monitor.incrementProgress(1);
					continue;
				}
				Address nextAddr = movePastDelaySlot(address);
				SymbolicPropogator.Value value =
					prop.getRegisterValue(nextAddr, format.getRegister());
				if (value != null) {
					Address stringAddress = toAddr(value.getValue());
					if (isValidAddress(stringAddress)) {
						Data data = getDataAt(stringAddress);
						if (data == null || !data.hasStringValue()) {
							clearListing(stringAddress);
							data = DataUtilities.createData(
								currentProgram, stringAddress, StringDataType.dataType, -1, false,
								ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
						}
						String msg = (String) data.getValue();
						overrideFunction(function, address, msg);
					}
				}
				monitor.incrementProgress(1);
			}
        }
	}

	private boolean isValidAddress(Address address) {
		MemoryBlock block = getMemoryBlock(address);
		return block != null && !block.isExecute();
	}

    private Address movePastDelaySlot(Address addr) {
        Instruction inst = getInstructionAt(addr);
        if (inst.getDelaySlotDepth() > 0) {
            do {
                inst = inst.getNext();
            } while (inst.isInDelaySlot());
        }
        return inst.getAddress();
    }

    private void overrideFunction(Function function, Address address, String format)
        throws Exception {
            int transaction = -1;
            if (currentProgram.getCurrentTransaction() == null) {
                transaction = currentProgram.startTransaction("Override Signature");
            }
            boolean commit = false;
            try {
				final FunctionDefinition def = getFunctionSignature(format, function);
				if (def != null) {
					DataTypeSymbol symbol = new DataTypeSymbol(def, NAME_ROOT, AUTO_CAT);
					Namespace space = HighFunction.findCreateOverrideSpace(function);
					if (space != null) {
						symbol.writeSymbol(table, address, space, dtm, true);
						commit = true;
					}
				}
            } catch (Exception e) {
				printerr("Error overriding signature: " + e.getMessage());
            } finally {
                if (transaction != -1) {
                    currentProgram.endTransaction(transaction, commit);
                }
            }
	}

	private static DataType toDataType(CharSequence match) {
		if (match.charAt(0) == 'h') {
			switch(match.charAt(1)) {
				case 'i':
				case 'd':
				case 'o':
					return ShortDataType.dataType;
				case 'u':
				case 'x':
				case 'X':
					return UnsignedShortDataType.dataType;
				default:
					throw new IllegalArgumentException("Unknown specifier "+match);
			}
		} else if (match.charAt(0) == 'l') {
			switch(match.charAt(1)) {
				case 'c':
					return WideCharDataType.dataType;
				case 's':
					return PointerDataType.getPointer(WideCharDataType.dataType, -1);
				case 'i':
				case 'd':
				case 'o':
					return LongDataType.dataType;
				case 'u':
				case 'x':
				case 'X':
					return UnsignedLongDataType.dataType;
				case 'e':
				case 'E':
				case 'f':
				case 'g':
				case 'G':
					return DoubleDataType.dataType;
				default:
					throw new IllegalArgumentException("Unknown specifier "+match);
			}
		} else if (match.charAt(0) == 'L') {
			switch(match.charAt(1)) {
				case 'e':
				case 'E':
				case 'f':
				case 'g':
				case 'G':
					return LongDoubleDataType.dataType;
				default:
					throw new IllegalArgumentException("Unknown specifier "+match);
			}
		} else {
			switch(match.charAt(0)) {
				case 'c':
					return CharDataType.dataType;
				case 's':
					return PointerDataType.getPointer(CharDataType.dataType, -1);
				case 'i':
				case 'd':
				case 'o':
					return IntegerDataType.dataType;
				case 'u':
				case 'x':
				case 'X':
					return UnsignedIntegerDataType.dataType;
				case 'e':
				case 'E':
				case 'f':
				case 'g':
				case 'G':
					return FloatDataType.dataType;
				case 'p':
					return PointerDataType.dataType;
				default:
					throw new IllegalArgumentException("Unknown specifier "+match);
			}
		}
	}

	private static String getSpecifier(MatchResult r) {
		return r.group(1);
	}

	private static ParameterDefinition toParameter(DataType dt) {
		return new ParameterDefinitionImpl(null, dt, null);
	}

	private FunctionDefinition getFunctionSignature(String format, Function function)
		throws Exception {
			FunctionDefinition def = new FunctionDefinitionDataType(TMP_NAME);
			Matcher matcher = FORMAT_PATTERN.matcher(format);
			Stream<DataType> types = matcher.results()
				.map(PrintfSigOverrider::getSpecifier)
				.map(PrintfSigOverrider::toDataType);
			ParameterDefinition[] params = Stream.concat(Stream.of(CHAR_PTR), types)
				.map(PrintfSigOverrider::toParameter)
				.toArray(ParameterDefinition[]::new);
			def.setArguments(params);
			def.setReturnType(IntegerDataType.dataType);
			return def;
    }

    // These should be in a Util class somewhere!

    public static ConstantPropagationAnalyzer getConstantAnalyzer(Program program) {
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        List<ConstantPropagationAnalyzer> analyzers =
            ClassSearcher.getInstances(ConstantPropagationAnalyzer.class);
        for (ConstantPropagationAnalyzer analyzer : analyzers) {
            if (analyzer.canAnalyze(program)) {
                return (ConstantPropagationAnalyzer) mgr.getAnalyzer(analyzer.getName());
            }
        }
        return null;
    }

    public static SymbolicPropogator analyzeFunction(Function function, TaskMonitor monitor)
        throws CancelledException {
            Program program = function.getProgram();
            ConstantPropagationAnalyzer analyzer = getConstantAnalyzer(program);
            SymbolicPropogator symEval = new SymbolicPropogator(program);
            symEval.setParamRefCheck(true);
            symEval.setReturnRefCheck(true);
            symEval.setStoredRefCheck(true);
            analyzer.flowConstants(program, function.getEntryPoint(), function.getBody(),
                                   symEval, monitor);
            return symEval;
	}

}
