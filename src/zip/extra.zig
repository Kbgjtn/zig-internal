const std = @import("std");
const zip = @import("zip.zig");

const Context = union(enum) {
    zip64_extended_extra_field: struct {
        uncompressed_size: ?u32,
        compressed_size: ?u32,
        local_file_header_relative_offset: ?u32,
        disk_number_start: ?u16,
    },
    none,
};

pub const Extra = struct {
    id: u16,
    data: []const u8,

    fn asHeaderID(self: Extra) ?zip.HeaderId {
        return std.enums.fromInt(zip.HeaderId, self.id);
    }

    fn parse(self: Extra, ctx: Context) !ExtraFieldMeta {
        const id = self.asHeaderID() orelse return error.BadHeaderId;
        switch (id) {
            .zip64_extended_extra_field => return .{
                .zip64_extended_extra_field = try parseZip64Extended(self.data, ctx),
            },
            else => return error.BadHeaderId,
        }
    }
};

test "extra field header id" {
    {
        const f: Extra = .{ .id = 0x0001, .data = undefined };
        try std.testing.expect(f.asHeaderID() == zip.HeaderId.zip64_extended_extra_field);
    }

    {
        const f: Extra = .{ .id = 0xFFFF, .data = undefined };
        try std.testing.expect(f.asHeaderID() == null);
    }
}

test "extra field parse" {
    // zero fields
    {
        const f: Extra = .{ .id = 0x0001, .data = &[_]u8{0} ** 8 };
        const output = try f.parse(.{
            .zip64_extended_extra_field = .{
                .compressed_size = 0,
                .uncompressed_size = 0,
                .disk_number_start = 0,
                .local_file_header_relative_offset = 0,
            },
        });

        const expected: ExtraFieldMeta = .{
            .zip64_extended_extra_field = .{
                .compressed_size = 0,
                .uncompressed_size = 0,
                .disk_number_start = 0,
                .local_file_header_relative_offset = 0,
            },
        };

        try std.testing.expectEqualDeep(output, expected);
    }

    // null fields
    {
        const f: Extra = .{ .id = 0x0001, .data = &[_]u8{} };
        const output = try f.parse(.{
            .zip64_extended_extra_field = .{
                .compressed_size = null,
                .uncompressed_size = null,
                .disk_number_start = null,
                .local_file_header_relative_offset = null,
            },
        });

        const expected: ExtraFieldMeta = .{
            .zip64_extended_extra_field = .{
                .compressed_size = null,
                .uncompressed_size = null,
                .disk_number_start = null,
                .local_file_header_relative_offset = null,
            },
        };

        try std.testing.expectEqualDeep(output, expected);
    }
}

const ExtraFieldMeta = union(enum) {
    zip64_extended_extra_field: Zip64Extended,
};

const Zip64Extended = struct {
    uncompressed_size: ?u64 = null,
    compressed_size: ?u64 = null,
    local_file_header_relative_offset: ?u64 = null,
    disk_number_start: ?u32 = null,
};

fn parseZip64Extended(
    data: []const u8,
    ctx: Context,
) !Zip64Extended {
    var result: Zip64Extended = .{};
    var reader = std.Io.Reader.fixed(data);

    if (ctx.zip64_extended_extra_field.uncompressed_size) |v| {
        result.uncompressed_size =
            if (v == 0xFFFFFFFF) try reader.takeInt(u64, .little) else @intCast(v);
    }

    if (ctx.zip64_extended_extra_field.compressed_size) |v| {
        result.compressed_size =
            if (v == 0xFFFFFFFF) try reader.takeInt(u64, .little) else @intCast(v);
    }

    if (ctx.zip64_extended_extra_field.local_file_header_relative_offset) |v| {
        result.local_file_header_relative_offset =
            if (v == 0xFFFFFFFF)
                try reader.takeInt(u64, .little)
            else
                @intCast(v);
    }

    if (ctx.zip64_extended_extra_field.disk_number_start) |v| {
        result.disk_number_start =
            if (v == 0xFFFF)
                try reader.takeInt(u32, .little)
            else
                @intCast(v);
    }

    if (reader.end != data.len) return error.Malformed;
    return result;
}

test "parse ZIP64 extended information" {
    const ef: Extra = .{ .data = &[_]u8{ 6, 0, 0, 0, 0, 0, 0, 0 }, .id = 0x1 };
    const parsed = try parseZip64Extended(ef.data, .{
        .zip64_extended_extra_field = .{
            .compressed_size = 6,
            .uncompressed_size = 4294967295,
            .local_file_header_relative_offset = 0,
            .disk_number_start = 0,
        },
    });

    try std.testing.expect(parsed.disk_number_start == 0);
    try std.testing.expect(@TypeOf(parsed.disk_number_start) == ?u32);
    try std.testing.expect(parsed.local_file_header_relative_offset == 0);
    try std.testing.expect(@TypeOf(parsed.local_file_header_relative_offset) == ?u64);
    try std.testing.expect(parsed.uncompressed_size == 6);
    try std.testing.expect(@TypeOf(parsed.uncompressed_size) == ?u64);
    try std.testing.expect(parsed.compressed_size == 6);
    try std.testing.expect(@TypeOf(parsed.compressed_size) == ?u64);
}

pub const Iterator = struct {
    buf: []const u8,
    offset: usize = 0,

    pub fn next(self: *Iterator) !?Extra {
        if (self.offset == self.buf.len) {
            return null;
        }

        if (self.offset + 4 > self.buf.len) {
            return error.BadExtraField;
        }

        const id = std.mem.readInt(u16, self.buf[self.offset..][0..2], .little);
        const size = std.mem.readInt(u16, self.buf[self.offset + 2 ..][0..2], .little);
        self.offset += 4;

        if (self.offset + size > self.buf.len) {
            return error.ZipBadExtraField;
        }

        const data = self.buf[self.offset .. self.offset + size];
        std.debug.print("field_data: {any}\n", .{data[0..]});
        const field = Extra{
            .id = id,
            .data = data,
        };

        self.offset += size;
        return field;
    }
};

test "iterator" {
    var extra = [_]u8{
        85, 84, 5, 0, 3, 4, 210, 153, 105, // 0x5455
        117, 120, 11, 0, 1, 4, 232, 3, 0, 0, 4, 232, 3, 0, 0, //   0x7875
        1, 0, 8, 0, 6, 0, 0, 0, 0, 0, 0, 0, // 0x0001
    };

    var iter: Iterator = .{ .buf = &extra };
    while (try iter.next()) |f| {
        std.debug.print("extra.id 0x{x}\n", .{f.id});

        const id = f.asHeaderID() orelse return error.BadHeaderId;
        switch (id) {
            .zip64_extended_extra_field => {
                const ctx: Context = .{
                    .zip64_extended_extra_field = .{
                        .compressed_size = 6,
                        .disk_number_start = 0,
                        .uncompressed_size = 4294967295,
                        .local_file_header_relative_offset = 0,
                    },
                };
                _ = try f.parse(ctx);
            },
            else => {},
        }
    }
}
