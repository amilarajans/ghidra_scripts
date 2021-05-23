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
// Removes the unnecessary "Bad Instruction" bookmarks set during analysis
// of ARM binaries. Bookmarks are only removed if data or an instruction
// are present at the bookmark's address.
//@category ARM
//@author Andrew J. Strelsky
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;

import util.CollectionUtils;

public class CleanupBookmarksScript extends GhidraScript {

	private static final String TARGET_CATEGORY = "Bad Instruction";

	@Override
	protected void run() throws Exception {
		BookmarkManager manager = currentProgram.getBookmarkManager();
		BookmarkType errorType = manager.getBookmarkType(BookmarkType.ERROR);
		BookmarkFilter filter = new BookmarkFilter(errorType);
		List<Bookmark> bookmarks = CollectionUtils.asStream(manager.getBookmarksIterator())
			.filter(filter)
			.collect(Collectors.toList());
		monitor.initialize(bookmarks.size());
		monitor.setMessage("Removing unnecessary error bookmarks");
		for (Bookmark bookmark : bookmarks) {
			monitor.checkCanceled();
			manager.removeBookmark(bookmark);
			monitor.incrementProgress(1);
		}
	}

	private class BookmarkFilter implements Predicate<Bookmark> {

		private final BookmarkType errorType;

		BookmarkFilter(BookmarkType errorType) {
			this.errorType = Objects.requireNonNull(errorType);
		}

		@Override
		public boolean test(Bookmark b) {
			if (b.getType().equals(errorType) && b.getCategory().equals(TARGET_CATEGORY)) {
				return getDataAt(b.getAddress()) != null || getInstructionAt(b.getAddress()) != null;
			}
			return false;
		}
	}
	
	
}
