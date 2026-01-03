const std = @import("std");
const builtin = @import("builtin");
pub fn main() !void {
    switch (comptime builtin.os.tag) {
        .linux => {
            //todo
        },
        .macos => {
            var gpa = std.heap.GeneralPurposeAllocator(.{}){};
            defer _ = gpa.deinit();
            const alloc = gpa.allocator();

            var fd_list = try std.ArrayList(i32).initCapacity(alloc, 0);
            defer {
                for (fd_list.items) |fd| std.posix.close(fd);
                fd_list.deinit(alloc);
            }

            // posix makes this easy conceptually
            const path = "/Users/reilly/programming/experiments/smol-zig-http/src/server";

            // do some for all files recursively in path
            var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });
            defer dir.close();

            var walker = try dir.walk(alloc);
            defer walker.deinit();

            while (try walker.next()) |entry| {
                std.debug.print("{s} ({s}, {any})\n", .{ entry.path, entry.basename, entry.kind });
                // entry.path: full relative path (e.g. "subdir/file.txt")
                // entry.basename: just the file/subdir name
                // entry.kind: .file, .directory, etc.
                const full = try std.fs.path.join(alloc, &.{ path, entry.path });
                defer alloc.free(full);
                const fd = try std.posix.open(full, .{ .EVTONLY = true, .CLOEXEC = true }, 0);
                try fd_list.append(alloc, fd);
            }

            // 2) create kqueue
            const kq = try std.posix.kqueue();
            defer std.posix.close(kq);

            // 3) register vnode watch
            const change = std.posix.Kevent{
                .ident = @as(usize, @intCast(fd)),
                .filter = std.c.EVFILT.VNODE,
                .flags = std.c.EV.ADD | std.c.EV.CLEAR,
                .fflags = std.c.NOTE.WRITE |
                    std.c.NOTE.RENAME |
                    std.c.NOTE.DELETE |
                    std.c.NOTE.ATTRIB,
                .data = 0,
                .udata = 0, // or null depending on Zig version/type
            };

            _ = try std.posix.kevent(kq, &[_]std.posix.Kevent{change}, &[_]std.posix.Kevent{}, null);

            var events: [8]std.posix.Kevent = undefined;

            // 4) next step: block on kevent() to receive events
            while (true) {
                const n = try std.posix.kevent(kq, &[_]std.posix.Kevent{}, // no changes; just waiting
                    events[0..], // writable buffer for returned events
                    null // null timeout = block forever
                );

                // n = how many events were written
                for (events[0..n]) |_| {
                    // ev.fflags will include NOTE_WRITE/RENAME/DELETE/etc.
                    // This is where you'd trigger your debounce + restart.
                    std.debug.print("A file has been updated\n", .{});
                }
            }
        },
        else => {
            std.debug.panic("Unsupported OS: {s}", .{@tagName(builtin.os.tag)});
        },
    }
}
