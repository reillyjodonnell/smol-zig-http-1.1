const builtin = @import("builtin");
const port = 3000;

fn setNonBlocking(fd: std.posix.fd_t) !void {
    const flags_usize = try std.posix.fcntl(fd, std.posix.F.GETFL, 0);

    // fcntl returns an int-ish value; convert to u32 then bitcast to the packed struct type.
    var flags_u32: u32 = @truncate(flags_usize);
    var flags: std.posix.O = @bitCast(flags_u32);

    if (!flags.NONBLOCK) {
        flags.NONBLOCK = true;
        flags_u32 = @bitCast(flags);

        // fcntl wants an integer again
        _ = try std.posix.fcntl(fd, std.posix.F.SETFL, @as(usize, flags_u32));
    }
}

pub fn main() !void {
    // log the zig version
    std.log.info(
        "zig {d}.{d}.{d}",
        .{ builtin.zig_version.major, builtin.zig_version.minor, builtin.zig_version.patch },
    );
    const os = builtin.os.tag;
    switch (os) {
        .macos => std.log.info("running on macOS", .{}),
        .linux => std.log.info("running on Linux", .{}),
        .windows => {
            std.log.err("Windows not supported yet", .{});
            std.os.exit(1);
        },
        else => {
            std.log.err("Unsupported OS: {s}", .{@tagName(os)});
            std.os.exit(1);
        },
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    // allocate an std array list
    var arrayList = try std.ArrayList(u8).initCapacity(alloc, 16);
    defer arrayList.deinit(alloc);

    // make posix call to get file descriptor
    const fd = try std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
        0,
    );
    defer std.posix.close(fd);

    // make sure non blocking
    try setNonBlocking(fd);

    const sockaddr_in = std.posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const addr_ptr: *const std.posix.sockaddr = @ptrCast(&sockaddr_in);
    const len: std.posix.socklen_t = @intCast(@sizeOf(std.posix.sockaddr.in));
    try std.posix.bind(fd, addr_ptr, len);
    try std.posix.listen(fd, 128);
    std.log.info("running on localhost:{d}\n", .{port});

    // starting with mac
    const kq = try std.posix.kqueue();
    defer std.posix.close(kq);

    const change = std.posix.Kevent{
        .ident = @intCast(fd),
        .filter = std.c.EVFILT.READ,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.CLEAR,
        .fflags = 0,
        .data = 0,
        .udata = 0,
    };

    var events: [16]std.posix.Kevent = undefined;
    _ = try std.posix.kevent(kq, &.{change}, &.{}, null);

    const run = true;
    while (run) {
        const n = try std.posix.kevent(kq, &.{}, events[0..], null);

        var i: usize = 0;
        while (i < n) : (i += 1) {
            const ev = events[i];
            if ((ev.flags & std.c.EV.ERROR) != 0) {
                std.log.err("kqueue error: ident={d} errno={d}", .{ ev.ident, ev.data });
                continue;
            }
            if (ev.ident == fd) {
                while (true) {
                    const conn = std.posix.accept(fd, null, null, 0) catch |err| switch (err) {
                        error.WouldBlock => break,
                        else => return err,
                    };
                    defer std.posix.close(conn);
                    try setNonBlocking(conn);

                    var buf: [4096]u8 = undefined;
                    const r = std.posix.read(conn, buf[0..]) catch |err| switch (err) {
                        error.WouldBlock => 0,
                        else => 0,
                    };
                    const resp =
                        "HTTP/1.1 200 OK\r\n" ++ "Content-Length: 5\r\n" ++ "Connection: close\r\n" ++ "\r\n" ++ "hello";
                    _ = std.posix.write(conn, resp) catch {};
                    _ = r;
                }
            }
        }
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
