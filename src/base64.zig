const std = @import("std");

// Base64 works in 3-byte blocks. 3 bytes = 24 bits.
// Then it splits that into:
// 4 groups of 6 bits.
// Each 6-bit group maps to a character from a 64-character alphabet.

// Base64 Scale:
// * range 0 to 25 is represented by ASCII uppercase letters [A-Z]
// * range 26 to 51 is represented by ASCII lowercase letters [a-z]
// * range 52 to 61 is represented by one digit numbers [0-9]
// * range 62 to 63 is represented by the characters `+` and `/`, repectively:
// * the character `=` represents the end of meaningful characters in the sequences;

// Encoding Flow:
// Input:
// [ byte1 ][ byte2 ][ byte3 ]
// Binary:
// aaaaaaaa bbbbbbbb cccccccc (24 bits total)
// Split that into:
// aaaaaa aabbbb bbcccc ccdddd
// Each 6-bit chunk becomes Base64 scale above.

// The padding group
// If input length is not divisible by 3:
// * 1 byte left -> output 2 chars + "=="
// * 2 byte left -> output 3 chars + "="
//
// Because:
// * 3 bytes -> 4-chars
// * 2 bytes -> 3-chars + =
// * 1 bytes -> 2-chars + ==
// the padding ensures output length is always multiple of 4.

// Why 3 Bytes become 4 Base64 Characters
// - Understanding the Sizes
// * 1 byte = 8 bits
// * Base64 character represents 6 bits
// Why 6 bits?
// Because Base64 alphabet has 64 symbols. And so is 2^6 = 64
// So each Base64 character encodes exactly 6 bits.
//
// - Find a Clean Bit Grouping
// We need to convert 8-bit bytes into 6-bit chunks.
// We want:
//  * no wasted bits
//  * Clean grouping
//  * No fractional chunks
//  So we can ask:
//  Whats the smallest number of bytes that can be evenly diveded into 6-bit groups?
//  Each byte = 8 bits. We need total bits divisible by 6.
//  So solve: 8(n) % 6 == 0
//  The smallest n that works is 3.
//  Because:
//  3 * 8 = 24 bits
//  24 % 6 == 0
//  24/6 = 4
//  3 bytes (24 bits) becomes 4 Base64 characters (4 x 6 bit).

const Mask6: u8 = 0x3F;
const B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub const Encoder = struct {
    pub fn encode_into(out: []u8, in: []const u8) !usize {
        if (in.len == 0) return 0;

        const required = encodedLength(in.len);
        if (out.len != required) return error.InvalidBufferSize;

        var i: usize = 0;
        var o: usize = 0;

        while (i + 3 <= in.len) {
            const b1 = in[i];
            const b2 = in[i + 1];
            const b3 = in[i + 2];

            const block: u32 =
                (@as(u32, b1) << 16) |
                (@as(u32, b2) << 8) |
                (@as(u32, b3));

            // 24-bit block split into four 6-bit indices
            out[o + 0] = B64_ALPHABET[(block >> 18) & Mask6];
            out[o + 1] = B64_ALPHABET[(block >> 12) & Mask6];
            out[o + 2] = B64_ALPHABET[(block >> 6) & Mask6];
            out[o + 3] = B64_ALPHABET[block & Mask6];

            i += 3;
            o += 4;
        }

        const remaining: usize = in.len - i;

        if (remaining == 1) {
            const b1 = in[i];
            const block: u32 = (@as(u32, b1) << 16);

            out[o] = B64_ALPHABET[(block >> 18) & Mask6];
            out[o + 1] = B64_ALPHABET[(block >> 12) & Mask6];
            out[o + 2] = '=';
            out[o + 3] = '=';
        } else if (remaining == 2) {
            const b1 = in[i];
            const b2 = in[i + 1];
            const block: u32 =
                (@as(u32, b1) << 16) |
                (@as(u32, b2) << 8);

            out[o] = B64_ALPHABET[(block >> 18) & Mask6];
            out[o + 1] = B64_ALPHABET[(block >> 12) & Mask6];
            out[o + 2] = B64_ALPHABET[(block >> 6) & Mask6];
            out[o + 3] = '=';
        }
        return required;
    }

    pub fn encode(
        allocator: std.mem.Allocator,
        in: []const u8,
    ) ![]u8 {
        const size = encodedLength(in.len);
        const out = try allocator.alloc(u8, size);
        const n = try encode_into(out, in);
        errdefer allocator.free(out);
        return out[0..n];
    }
};

pub const DecodeError = error{
    InvalidLength,
    InvalidCharacter,
    InvalidPadding,
    InvalidBufferSize,
};

pub const Decoder = struct {
    const table = build_table();
    const InvalidValue: u8 = 0xFF;

    fn build_table() [256]u8 {
        var t = [_]u8{255} ** 256;
        for (B64_ALPHABET, 0..) |c, i| {
            t[c] = @intCast(i);
        }
        return t;
    }

    pub fn decode_into(
        out: []u8,
        in: []const u8,
    ) DecodeError!usize {
        if (in.len % 4 != 0) return error.InvalidLength;

        const out_length = decodedLength(in);
        if (out_length == 0) return 0;
        if (out.len < out_length) return error.InvalidBufferSize;

        const blocks = in.len / 4;
        if (blocks == 0) return 0;

        const last_block_index = blocks - 1;
        var o: usize = 0;

        // fast path
        for (0..last_block_index) |block_index| {
            const i = block_index * 4;

            const c1 = in[i + 0];
            const c2 = in[i + 1];
            const c3 = in[i + 2];
            const c4 = in[i + 3];

            // No '=' allowed here
            if (c1 == '=' or c2 == '=' or c3 == '=' or c4 == '=') {
                return error.InvalidPadding;
            }

            const v1 = table[c1];
            const v2 = table[c2];
            const v3 = table[c3];
            const v4 = table[c4];

            if (v1 == 255 or v2 == 255 or v3 == 255 or v4 == 255) {
                return error.InvalidCharacter;
            }

            const block: u32 =
                (@as(u32, v1) << 18) |
                (@as(u32, v2) << 12) |
                (@as(u32, v3) << 6) |
                (@as(u32, v4));

            out[o + 0] = @intCast((block >> 16) & 0xFF);
            out[o + 1] = @intCast((block >> 8) & 0xFF);
            out[o + 2] = @intCast(block & 0xFF);

            o += 3;
        }

        // slow path: last block
        {
            const i = last_block_index * 4;
            const c1 = in[i + 0];
            const c2 = in[i + 1];
            const c3 = in[i + 2];
            const c4 = in[i + 3];

            if (c1 == '=' or c2 == '=')
                return error.InvalidPadding;

            const v1 = table[c1];
            const v2 = table[c2];

            if (v1 == 255 or v2 == 255)
                return error.InvalidCharacter;

            var v3: u8 = 0;
            var v4: u8 = 0;
            const is_c3_padded = c3 == '=';
            const is_c4_padded = c4 == '=';

            if (is_c3_padded and !is_c4_padded) {
                return error.InvalidPadding;
            }

            // Padding cases
            const bytes_to_write: usize = if (is_c3_padded) 1 else if (is_c4_padded) 2 else 3;

            // Decode non-padding characters
            if (!is_c3_padded) {
                v3 = table[c3];
                if (v3 == 255) return error.InvalidCharacter;
            }

            if (!is_c4_padded) {
                v4 = table[c4];
                if (v4 == 255) return error.InvalidCharacter;
            }

            const block: u32 =
                (@as(u32, v1) << 18) |
                (@as(u32, v2) << 12) |
                (@as(u32, v3) << 6) |
                (@as(u32, v4));

            if (bytes_to_write >= 1) {
                out[o] = @intCast((block >> 16) & 255);
            }

            if (bytes_to_write >= 2) {
                out[o + 1] = @intCast((block >> 8) & 255);
            }

            if (bytes_to_write == 3) {
                out[o + 2] = @intCast(block & 255);
            }

            o += bytes_to_write;
        }

        return o;
    }

    pub fn decode(allocator: std.mem.Allocator, in: []const u8) ![]u8 {
        const size = decodedLength(in);
        const out = try allocator.alloc(u8, size);
        const n = try decode_into(out, in);
        errdefer allocator.free(out);
        return out[0..n];
    }
};

pub fn encodedLength(input_len: usize) usize {
    return ((input_len + 2) / 3) * 4;
}

pub fn decodedLength(input: []const u8) usize {
    var padding: usize = 0;
    if (input.len >= 2 and input[input.len - 1] == '=') padding += 1;
    if (input.len >= 2 and input[input.len - 2] == '=') padding += 1;

    return (input.len / 4) * 3 - padding;
}

test "Base64 decode" {
    var prng = std.Random.DefaultPrng.init(0xdeadbeef);
    const random = prng.random();

    const allocator = std.testing.allocator;

    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        const size = random.intRangeAtMost(usize, 0, 4096);
        const input = try allocator.alloc(u8, size);
        defer allocator.free(input);

        random.bytes(input);

        // Calculate encoded size
        const encoded_len = encodedLength(size);
        const encoded = try allocator.alloc(u8, encoded_len);
        // std.debug.print("encoded len = {}\n", .{encoded.len});
        defer allocator.free(encoded);

        _ = try Encoder.encode_into(encoded, input);

        // Calculate decoded size
        const decoded_len = decodedLength(encoded);
        const decoded = try allocator.alloc(u8, decoded_len);
        defer allocator.free(decoded);

        const written = try Decoder.decode_into(decoded, encoded);
        try std.testing.expectEqual(input.len, written);
        try std.testing.expectEqualSlices(u8, input, decoded);

        const decoded2 = try Decoder.decode(allocator, encoded);
        defer allocator.free(decoded2);
        try std.testing.expectEqual(input.len, decoded2.len);
        try std.testing.expectEqualSlices(u8, input, decoded2);
    }
}

fn expectEncode(
    allocator: std.mem.Allocator,
    in: []const u8,
    expected: []const u8,
) !void {
    const out = try Encoder.encode(allocator, in);
    defer allocator.free(out);
    try std.testing.expectEqualStrings(expected, out);
}

test "Base64 encode" {
    const allocator = std.testing.allocator;
    try expectEncode(allocator, "", "");
    try expectEncode(allocator, "0", "MA==");
    try expectEncode(allocator, "foo", "Zm9v");
}

test "Base64 encode binary data compare to std.base64" {
    const allocator = std.testing.allocator;

    const data = [_]u8{
        0x66,
        0x6F,
        0x6F,
    };
    const result = try Encoder.encode(allocator, &data);
    defer allocator.free(result);

    // verify using std.base64
    var buf: [8]u8 = undefined;
    const expected = std.base64.standard.Encoder.encode(&buf, &data);

    try std.testing.expectEqualStrings(expected, result);
}

fn skipTest() error.SkipTest!void {
    return error.SkipTest;
}

test "fuzz: Base64 encoder" {
    if (true) return error.SkipZigTest; // Skip this test

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    var input_buffer: [1024]u8 = undefined;

    var i: usize = 0;
    const random = prng.random();

    while (i < 100_000) : (i += 1) {
        const len = random.intRangeLessThan(usize, 0, input_buffer.len);
        random.bytes(input_buffer[0..len]);

        const encoded = try Encoder.encode(allocator, input_buffer[0..len]);
        defer allocator.free(encoded);

        const decoded_buffer = try allocator.alloc(u8, len);
        try std.base64.standard.Decoder.decode(decoded_buffer, encoded);
        defer allocator.free(decoded_buffer);

        try std.testing.expectEqualSlices(u8, input_buffer[0..len], decoded_buffer);
    }
}
