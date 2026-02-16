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

const BASE64_MAX_BIT_SIZE: u8 = 0x3F;

pub const Encoder = struct {
    _table: *const [64]u8,

    pub fn init() Encoder {
        return Encoder{
            ._table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        };
    }

    // Validate:
    // * input length % 4 == 0 (decoder)
    // * only valid Base64 characters
    // * padding only at end
    // * no more than 2 "="
    // * "=" only allowed in last 2 positions
    pub fn encode_into(self: *const Encoder, out: []u8, in: []const u8) !usize {
        if (in.len == 0) return 0;

        const required = _calculate_encode_length(in);
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

            out[o] = self._table[(block >> 18) & BASE64_MAX_BIT_SIZE];
            out[o + 1] = self._table[(block >> 12) & BASE64_MAX_BIT_SIZE];
            out[o + 2] = self._table[(block >> 6) & BASE64_MAX_BIT_SIZE];
            out[o + 3] = self._table[block & BASE64_MAX_BIT_SIZE];

            i += 3;
            o += 4;
        }

        const remaining: usize = in.len - i;

        if (remaining == 1) {
            const b1 = in[i];
            const block: u32 = (@as(u32, b1) << 16);

            out[o] = self._table[(block >> 18) & BASE64_MAX_BIT_SIZE];
            out[o + 1] = self._table[(block >> 12) & BASE64_MAX_BIT_SIZE];
            out[o + 2] = '=';
            out[o + 3] = '=';
        } else if (remaining == 2) {
            const b1 = in[i];
            const b2 = in[i + 1];
            const block: u32 =
                (@as(u32, b1) << 16) |
                (@as(u32, b2) << 8);

            out[o] = self._table[(block >> 18) & BASE64_MAX_BIT_SIZE];
            out[o + 1] = self._table[(block >> 12) & BASE64_MAX_BIT_SIZE];
            out[o + 2] = self._table[(block >> 6) & BASE64_MAX_BIT_SIZE];
            out[o + 3] = '=';
        }
        return required;
    }

    pub fn encode(
        self: Encoder,
        allocator: std.mem.Allocator,
        in: []const u8,
    ) ![]u8 {
        const size = _calculate_encode_length(in);
        const out = try allocator.alloc(u8, size);
        errdefer allocator.free(out);

        const n = try self.encode_into(out, in);
        return out[0..n];
    }

    fn _calculate_encode_length(in: []const u8) usize {
        if (in.len == 0) return 0;
        return ((in.len + 2) / 3) * 4;
    }

    pub fn _char_at(self: Encoder, index: usize) u8 {
        return self._table[index];
    }
};

fn expectEncode(
    allocator: std.mem.Allocator,
    b64: *const Encoder,
    input: []const u8,
    expected: []const u8,
) !void {
    const encoded = try b64.encode(allocator, input);
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings(expected, encoded);
}

test "Base64 encode" {
    const allocator = std.testing.allocator;
    const base64 = Encoder.init();

    try expectEncode(allocator, &base64, "", "");
    try expectEncode(allocator, &base64, "foo", "Zm9v");
}

test "encode binary data" {
    const allocator = std.testing.allocator;
    const base64 = Encoder.init();

    const data = [_]u8{
        0x66,
        0x6F,
        0x6F,
    };
    const result = try base64.encode(allocator, &data);
    defer allocator.free(result);

    // verify using std.base64
    var buf: [8]u8 = undefined;
    const expected = std.base64.standard.Encoder.encode(&buf, &data);

    try std.testing.expectEqualStrings(expected, result);
}

test "fuzz base64 encoder" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    var input_buffer: [1024]u8 = undefined;

    var i: usize = 0;
    const random = prng.random();
    const base64 = Encoder.init();

    while (i < 100_000) : (i += 1) {
        const len = random.intRangeLessThan(usize, 0, input_buffer.len);
        random.bytes(input_buffer[0..len]);

        const encoded = try base64.encode(allocator, input_buffer[0..len]);
        defer allocator.free(encoded);

        const decoded_buffer = try allocator.alloc(u8, len);
        try std.base64.standard.Decoder.decode(decoded_buffer, encoded);
        defer allocator.free(decoded_buffer);

        try std.testing.expectEqualSlices(u8, input_buffer[0..len], decoded_buffer);
    }
}
