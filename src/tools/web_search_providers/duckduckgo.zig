const std = @import("std");
const common = @import("common.zig");

pub fn execute(
    allocator: std.mem.Allocator,
    query: []const u8,
    count: usize,
    timeout_secs: u64,
) (common.ProviderSearchError || error{OutOfMemory})!common.ToolResult {
    const encoded_query = try common.urlEncode(allocator, query);
    defer allocator.free(encoded_query);

    const url_str = try std.fmt.allocPrint(
        allocator,
        "https://html.duckduckgo.com/html/?q={s}",
        .{encoded_query},
    );
    defer allocator.free(url_str);

    const timeout_str = try common.timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    const headers = [_][]const u8{
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.5",
    };

    const body = common.curlGet(allocator, url_str, &headers, timeout_str) catch |err| {
        common.logRequestError("duckduckgo", query, err);
        return err;
    };
    defer allocator.free(body);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const result_entries = try parseHtml(aa, body, count);
    if (result_entries.len == 0) return common.noWebResults(allocator);

    return common.formatResultEntries(allocator, query, result_entries);
}

/// Legacy entry point for JSON results. No longer used as we scrape HTML.
pub fn formatResults(allocator: std.mem.Allocator, json_body: []const u8, query: []const u8, count: usize) !common.ToolResult {
    _ = allocator;
    _ = json_body;
    _ = query;
    _ = count;
    return common.ToolResult.fail("DuckDuckGo Instant Answer API is no longer supported; results are now fetched via HTML scraping.");
}

fn parseHtml(allocator: std.mem.Allocator, html: []const u8, count: usize) ![]common.ResultEntry {
    var list: std.ArrayListUnmanaged(common.ResultEntry) = .empty;
    defer list.deinit(allocator);
    var search_pos: usize = 0;
    const max_results = @min(count, 10);

    while (list.items.len < max_results) {
        const result_start = std.mem.indexOfPos(u8, html, search_pos, "class=\"result ") orelse break;
        search_pos = result_start + 1;

        // Find title
        const title_class = "class=\"result__a\"";
        const title_pos = std.mem.indexOfPos(u8, html, result_start, title_class) orelse continue;
        const title_end_tag = std.mem.indexOfPos(u8, html, title_pos, ">") orelse continue;
        const title_close_tag = std.mem.indexOfPos(u8, html, title_end_tag, "</a>") orelse continue;
        const title_raw = html[title_end_tag + 1 .. title_close_tag];
        const title = try stripTags(allocator, title_raw);

        // Find url
        const href_start = std.mem.indexOfPos(u8, html, title_pos, "href=\"") orelse continue;
        const href_end = std.mem.indexOfPos(u8, html, href_start + 6, "\"") orelse continue;
        const url_raw = html[href_start + 6 .. href_end];
        const url = try decodeUrl(allocator, url_raw);

        // Find snippet
        const snippet_class = "class=\"result__snippet";
        const snippet_pos = std.mem.indexOfPos(u8, html, result_start, snippet_class) orelse continue;
        const snippet_end_tag = std.mem.indexOfPos(u8, html, snippet_pos, ">") orelse continue;
        const snippet_close_tag = std.mem.indexOfPos(u8, html, snippet_end_tag, "</a>") orelse continue;
        const snippet_raw = html[snippet_end_tag + 1 .. snippet_close_tag];
        const snippet = try stripTags(allocator, snippet_raw);

        try list.append(allocator, .{
            .title = title,
            .url = url,
            .description = snippet,
        });
    }

    return list.toOwnedSlice(allocator);
}

fn stripTags(allocator: std.mem.Allocator, html: []const u8) ![]const u8 {
    return common.stripTags(allocator, html);
}

fn decodeUrl(allocator: std.mem.Allocator, raw_url: []const u8) ![]const u8 {
    if (std.mem.startsWith(u8, raw_url, "//duckduckgo.com/l/?uddg=")) {
        const end_pos = std.mem.indexOfPos(u8, raw_url, 25, "&") orelse raw_url.len;
        const encoded = raw_url[25..end_pos];
        return common.urlDecode(allocator, encoded);
    }
    return allocator.dupe(u8, raw_url);
}

const testing = std.testing;

test "duckduckgo parseHtml" {
    const html =
        \\<div class="result ">
        \\  <h2 class="result__title">
        \\    <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com&rut=1">Example Title</a>
        \\  </h2>
        \\  <a class="result__snippet">Example <b>Snippet</b> with &quot;quotes&quot;</a>
        \\</div>
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const entries = try parseHtml(arena.allocator(), html, 5);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("Example Title", entries[0].title);
    try std.testing.expectEqualStrings("https://example.com", entries[0].url);
    try std.testing.expectEqualStrings("Example Snippet with \"quotes\"", entries[0].description);
}

test "duckduckgo urlDecode" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const raw_url = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2F%3Fq%3D1&rut=1";
    const decoded = try decodeUrl(allocator, raw_url);
    try std.testing.expectEqualStrings("https://example.com/?q=1", decoded);
}
