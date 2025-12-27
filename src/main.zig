//! By convention, main.zig is where your main function lives in the case that
//! you are building an executable. If you are making a library, the convention
//! is to delete this file and start with root.zig instead.

pub fn main() !void {
    // make posix call to get file descriptor
    const fd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    const sockaddr_in = std.posix.sockaddr.in{ .port = std.mem.nativeToBig(u16, 3000), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    const addr_ptr = @as(*const std.posix.sockaddr, @ptrCast(&sockaddr_in));
    const len: std.posix.socklen_t = @intCast(@sizeOf(std.posix.sockaddr.in));
    try std.posix.bind(fd, addr_ptr, len);
    try std.posix.listen(fd, 128);
    std.log.debug("running on localhost:3000\n", .{});

    const run = true;
    while (run) {
        const conn_fd = try std.posix.accept(fd, null, null, 0);
        var buf: [4096]u8 = undefined;
        const n = try std.posix.read(conn_fd, buf[0..]);
        const response =
            "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Content-Length: 21\r\n" ++
            "Connection: close\r\n" ++
            "\r\n" ++
            "hello from the server";
        _ = try std.posix.write(conn_fd, response);

        std.debug.print("\nrequest: {s}\n", .{buf[0..n]});
    }
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // Try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "use other module" {
    try std.testing.expectEqual(@as(i32, 150), lib.add(100, 50));
}

test "fuzz example" {
    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{});
}

const std = @import("std");

/// This imports the separate module containing `root.zig`. Take a look in `build.zig` for details.
const lib = @import("smol_zig_http_lib");
