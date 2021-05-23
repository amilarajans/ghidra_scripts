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
// Displays a table of known FID_conflicts containing an action that allows the user
// to select the correct label. After the label has been selected all remaining FID_conflict
// labels are removed from the address and the selected label is demangled and re-applied
// if necessary.
//@category FunctionID
//@author Andrew J. Strelsky

import java.awt.Color;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.app.util.query.TableService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressArrayTableModel;
import ghidra.util.table.GhidraTable;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import util.CollectionUtils;

public class ResolveFidScript extends GhidraScript {

	private static final DemanglerOptions OPTIONS = new DemanglerOptions();
	private static final Pattern MANGLED_PATTERN = Pattern.compile("(_Z\\w+)+");

	private AddressArrayTableModel model;

	@Override
	protected void run() throws Exception {
		PluginTool tool = state.getTool();
		if (tool == null) {
			return;
		}

		TableService table = tool.getService(TableService.class);
		SymbolTable symTable = currentProgram.getSymbolTable();
		Address[] conflicts = CollectionUtils.asStream(symTable.getAllSymbols(false))
			.filter(s -> s.getSymbolType() == SymbolType.FUNCTION)
			.filter(s -> s.getName().startsWith("FID_conflict"))
			.map(Symbol::getAddress)
			.distinct()
			.toArray(Address[]::new);

		Runnable runnable = () -> {
			this.model = new AddressArrayTableModel(getScriptName(),
				state.getTool(), currentProgram, conflicts);
			TableComponentProvider<Address> tableProvider =
				table.showTableWithMarkers("Conflicts " + model.getName(), "GhidraScript", model,
					Color.GREEN, null, "Script Results", null);
			tableProvider.installRemoveItemsAction();
			tableProvider.addLocalAction(new OpenSelectionTableAction());
		};
		Swing.runLater(runnable);
	}

	private class FidConflictResolver {

		private final Address address;
		private final List<DemangledObject> demangled;
		private final List<String> conflicts;

		FidConflictResolver(Address address) {
			this.address = address;
			this.demangled = new ArrayList<>();
			String plate = getPlateComment(address);
			Matcher matcher = MANGLED_PATTERN.matcher(plate);
			while (matcher.find()) {
				demangled.add(DemanglerUtil.demangle(currentProgram, matcher.group()));
			}
			SymbolTable table = currentProgram.getSymbolTable();
			this.conflicts = Arrays.stream(table.getSymbols(address))
				.map(s -> s.getName(true))
				.filter(name -> name.startsWith("FID_conflict"))
				.map(name -> name.replace("FID_conflict:", ""))
				.collect(Collectors.toList());
		}

		void resolve() {
			boolean success = false;
			try {
				start();
				String name = askChoice("Resolve Fid Conflict", "Select the correct function",
					conflicts, conflicts.get(0));
				conflicts.forEach(s -> removeSymbol(address, "FID_conflict:" + s));
				DemangledObject d = demangled.stream()
					.filter(o -> o.getName().equals(name))
					.findFirst()
					.orElse(null);
				if (d != null) {
					success = d.applyTo(currentProgram, address, OPTIONS, monitor);
				} else {
					createLabel(address, name, true);
					success = true;
				}
				model.removeObject(address);
			} catch (CancelledException e) {
			} catch (Exception e) {
				Msg.error(this, e);
			} finally {
				end(success);
			}
		}

	}

	private class OpenSelectionTableAction extends DockingAction {

		OpenSelectionTableAction() {
			super("OpenSelectionTableAction", "ResolveFidScript");
			setPopupMenuData(new MenuData(
				new String[] {"Resolve Library Function"}, null, "Show Conflicts"));
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			GhidraTable table = (GhidraTable) context.getContextObject();
			return table.getProgramSelection().getNumAddresses() == 1;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			GhidraTable table = (GhidraTable) context.getContextObject();
			Address address = table.getProgramSelection().getMinAddress();
			FidConflictResolver resolver = new FidConflictResolver(address);
			Swing.runLater(resolver::resolve);
		}

	}
}