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
// Batch imports FID database files from a user specified directory
//@category FunctionID
//@author Andrew J. Strelsky
import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidFileManager;

public class AttachFidsScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		FidFileManager fidManager = FidFileManager.getInstance();
		File path = askDirectory("Select a fidb directory", "OK");
		File[] fidbs = path.listFiles(AttachFidsScript::fidbFilter);
		monitor.setMessage("Importing fidb files");
		monitor.initialize(fidbs.length);
		for (File file : fidbs) {
			monitor.checkCanceled();
			if (fidManager.addUserFidFile(file) == null) {
				printerr(file.getName() + " is not a valid fidb");
			}
			monitor.incrementProgress(1);
		}
	}

	private static boolean fidbFilter(File file, String name) {
		return name.endsWith(".fidb");
	}

}