const std = @import("std");
const zip = @import("zip.zig");

pub const ExtraField = struct {
    id: u16,
    data: []const u8,

    fn asHeaderID(self: ExtraField) ?zip.HeaderID {
        return std.enums.fromInt(zip.HeaderID, self.id);
    }
};

test "ExtraField.id" {
    {
        const f: ExtraField = .{
            .id = 0x0001,
            .data = undefined,
        };

        try std.testing.expectEqual(f.asHeaderID(), zip.HeaderID.zip64_extended_extra_field);
    }

    {
        const f: ExtraField = .{
            .id = 0xFFFF,
            .data = undefined,
        };

        try std.testing.expectEqual(f.asHeaderID(), null);
    }
}

const ParsedExtra = union(zip.HeaderID) {
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
    ctx: struct {
        uncompressed: ?u32,
        compressed: ?u32,
        local_file_header_relative_offset: ?u32,
        disk_number_start: ?u16,
    },
) !Zip64Extended {
    var result: Zip64Extended = .{};
    var reader = std.Io.Reader.fixed(data);

    // if (ctx.uncompressed == 0xFFFFFFFF and reader.seek + 8 <= data.len) {
    //     result.uncompressed_size = try reader.takeInt(u64, .little);
    // } else if (ctx.uncompressed) |v| {
    //     result.uncompressed_size = @intCast(v):
    // }

    if (ctx.uncompressed) |v| {
        result.uncompressed_size =
            if (v == 0xFFFFFFFF) try reader.takeInt(u64, .little) else @intCast(v);
    }

    // if (ctx.compressed == 0xFFFFFFFF and reader.seek + 8 <= data.len) {
    //     result.uncompressed_size = try reader.takeInt(u64, .little);
    // } else if (ctx.compressed) |v| {
    //     result.compressed_size = @intCast(v);
    // }

    if (ctx.compressed) |v| {
        result.compressed_size =
            if (v == 0xFFFFFFFF) try reader.takeInt(u64, .little) else @intCast(v);
    }

    if (ctx.local_file_header_relative_offset) |v| {
        result.local_file_header_relative_offset =
            if (v == 0xFFFFFFFF)
                try reader.takeInt(u64, .little)
            else
                @intCast(v);
    }

    // if (ctx.local_file_header_relative_offset == 0xFFFFFFFF and reader.seek + 8 <= data.len) {
    //     result.local_file_header_relative_offset = try reader.takeInt(u64, .little);
    // } else if (ctx.local_file_header_relative_offset) |v| {
    //     result.local_file_header_relative_offset = @intCast(v);
    // }

    if (ctx.disk_number_start) |v| {
        result.disk_number_start =
            if (v == 0xFFFF)
                try reader.takeInt(u32, .little)
            else
                @intCast(v);
    }

    // if (ctx.disk_number_start == 0xFFFF and reader.seek + 4 <= data.len) {
    //     result.local_file_header_relative_offset = try reader.takeInt(u32, .little);
    // } else if (ctx.disk_number_start) |v| {
    //     result.disk_number_start = @intCast(v);
    // }

    if (reader.end != data.len) {
        return error.Malformed;
    }

    return result;
}

test "parseZip64Extended" {
    const ef: ExtraField = .{
        .data = &[_]u8{ 6, 0, 0, 0, 0, 0, 0, 0 },
        .id = 0x1,
    };

    const parsed = try parseZip64Extended(ef.data, .{
        .compressed = 6,
        .uncompressed = 4294967295,
        .local_file_header_relative_offset = 0,
        .disk_number_start = 0,
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

    pub fn next(self: *Iterator) !?ExtraField {
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
        const field = ExtraField{
            .id = id,
            .data = data,
        };

        self.offset += size;
        return field;
    }
};

test "iterator" {
    var extra = [_]u8{
        85, 84, 5, 0, 3, 4, 210, 153, 105, 117, 120, 11, 0, 1, 4, 232, 3, 0, 0, 4, 232, 3, 0, 0, 1, 0, 8, 0, 6, 0, 0, 0, 0, 0, 0, 0,
    };

    var iter: Iterator = .{
        .buf = &extra,
    };

    while (try iter.next()) |f| {
        std.debug.print("extra.id 0x{x}\n", .{f.id});
        // const id = f.asHeaderID() orelse return error.InvalidHeaderID;
        // switch (id) {
        //     .zip64_extended_extra_field => {
        //         _ = try parseZip64Extended(f.data, .{
        //             .compressed = 6,
        //             .uncompressed = 4294967295,
        //             .local_file_header_relative_offset = 0,
        //             .disk_number_start = 0,
        //         });
        //
        //         break;
        //     },
        //     else => {},
        // }
    }
}
