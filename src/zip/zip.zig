/// refs:
/// - https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
/// -
const std = @import("std");
const time = @import("time.zig");
const Extra = @import("extra.zig");

// A ZIP file is correctly identified by the presence of an EOCDR (`END OF
// CENTRAL DIRECTORY RECORD`) which is located at the end of the archive
// structure in order to allow the easy appending of new files.

// If the EOCDR (`END OF CENTRAL DIRECTORY RECORD`) record indicates a non empty archive,
// the name of each file or directory of within the archive should be specified
// in a EOCDR entry, along with other metdata about the entry, and
// an offset into the ZIP file, pointing to the actual entry data.

// Requirement:
// - Parse the EOCD
// - Locate the Central Directory
// - Find the file entry you want
// - Jump to its Local File Header
// - Decompress (w/e COMPRESSION alg)

// ZIP file format uses 32-bit CRC algorithm for archiving purpose. In order
// to render the compressed files, a ZIP archive holds a directory at its end
// that keeps the entry of the contained files and their location in the archive file.
// It, thus, plays the role of encoding for encapsulation information necessary to render
// the compressed files. ZIP readers use the directory to load the list of files without
// reading the entire ZIP archive. The format keeps dual copies of the directory structure
// to provide greater protection against loss of data.

/// General purpose bit flag with size 2-bytes.
/// Bit 00: encrypted file
/// Bit 01: compression option
/// Bit 02: compression option
/// Bit 03: data descriptor
/// Bit 04: enhanced deflation
/// Bit 05: compressed patched data
/// Bit 06: strong encryption
/// Bit 07-10: unused
/// Bit 11: language encoding
/// Bit 12: reserved
/// Bit 13: mask header values
/// Bit 14-15: reserved
pub const GeneralPurposeFlags = packed struct(u16) {
    encrypted: bool, // bit 0
    compression_option1: bool, // bit 1
    compression_option2: bool, // bit 2
    data_descriptor: bool, // bit 3
    enhanced_deflation: bool, // bit 4
    compressed_patched_data: bool, // bit 5
    strong_encryption: bool, // bit 6
    _unused1: u4, // bits 7-10
    language_encoding: bool, // bit 11
    _reserved1: bool, // bit 12
    mask_header_values: bool, // bit 13
    _reserved2: u2, // bits 14-15
};

/// Compression method
/// 00: no compression
/// 01: shrunk
/// 02: reduced with compression factor 1
/// 03: reduced with compression factor 2
/// 04: reduced with compression factor 3
/// 05: reduced with compression factor 4
/// 06: imploded
/// 07: reserved
/// 08: deflated
/// 09: enhanced deflated
/// 10: PKWare DCL imploded
/// 11: reserved
/// 12: compressed using BZIP2
/// 13: reserved
/// 14: LZMA
/// 15-17: reserved
/// 18: compressed using IBM TERSE
/// 19: IBM LZ77 z
/// 98: PPMd version I, Rev 1
pub const CompressionMethod = enum(u16) {
    stored = 0x0,
    deflate = 0x8,
    _,
};

// File Headers

/// The Local File Header of each entry represents information
/// about the file such as comment, file size and file name.
/// The extra data fields (optional) can accommodate information
/// for extensibility options of the ZIP format. The Local File
/// Header has specific field structure consisting of multi-byte
/// values.
///
/// All the values are stored in little-endian byte order
/// where the field lenght counts the length in bytes. All the
/// structures ZIP file use 4-byte signatures for each file entry.
/// So basically, need to store the metadata in a way that
/// produces a byte-exact layout which matches the binary format.
pub const LocalFileHeader = extern struct {
    signature: u32 align(1),
    version_needed_to_extract: u16 align(1),
    flags: GeneralPurposeFlags align(1),
    compression_method: CompressionMethod align(1),
    last_modification_time: u16 align(1),
    last_modification_date: u16 align(1),
    crc32: u32 align(1),
    compressed_size: u32 align(1),
    uncompressed_size: u32 align(1),
    filename_len: u16 align(1),
    extra_len: u16 align(1),
    // ...
    // File name (variable size)
    // Extra field (variable size)

    const signature_marker: u32 = 0x04034b50;

    // TODO should this returned the parsed extra if any?
    // (dapa) NOPE
    pub fn read(
        r: *std.fs.File.Reader,
        offset: u64,
    ) !LocalFileHeader {
        try r.seekTo(offset);
        const header = try r.interface.takeStruct(LocalFileHeader, .little);
        if (header.signature != signature_marker) return error.ZipBadSignature;
        if (header.flags.encrypted) {
            return error.ZipUnsupportedEncryption;
        }

        // r.interface.toss(header.filename_len);
        // std.debug.print("seek after reading lfh.filename {}\n", .{r.logicalPos()});
        //
        // var extra_buf: [max_u16]u8 = undefined;
        // const extra = extra_buf[0..header.extra_len];
        // try r.interface.readSliceAll(extra);
        //
        // std.debug.print("seek after reading lfh.filename {}\n", .{r.logicalPos()});
        // std.debug.print("extra ok: {}\n", .{extra.len == header.extra_len});
        //
        // var zip64_extended_extra: Extra.Zip64Extended = .{
        //     .compressed_size = header.compressed_size,
        //     .uncompressed_size = header.uncompressed_size,
        // };
        //
        // if (header.requires_zip64()) {
        //     var iter: Extra.Iterator = .{ .buf = extra };
        //     while (try iter.next()) |field| {
        //         const id = field.asHeaderID() orelse return error.BadHeaderID;
        //         if (id == HeaderId.zip64_extended_extra_field) {
        //             const ctx: Extra.Context = .{
        //                 .zip64_extended_extra_field = .{
        //                     .uncompressed_size = header.uncompressed_size,
        //                     .compressed_size = header.compressed_size,
        //                     .disk_number_start = null,
        //                     .local_file_header_relative_offset = null,
        //                 },
        //             };
        //
        //             const out = try field.parse(ctx);
        //             zip64_extended_extra = out.zip64_extended_extra_field;
        //         }
        //     }
        // }
        //
        // std.debug.print("extra metadata [lfh]: {}\n", .{zip64_extended_extra});
        // header.print();
        // std.debug.print("seek after reading lfh.extra {}\n", .{r.logicalPos()});
        //
        // if (header.compression_method == CompressionMethod.deflate) {
        //     var flate_buf: [std.compress.flate.max_window_len]u8 = undefined;
        //     var decompress: std.compress.flate.Decompress = .init(&r.interface, .raw, &flate_buf);
        //     std.debug.print("data decompressed:\n", .{});
        //
        //     while (true) {
        //         const byte = decompress.reader.takeByte() catch |err| switch (err) {
        //             error.EndOfStream => break,
        //             else => return err,
        //         };
        //
        //         std.debug.print("{c}", .{byte});
        //     }
        // } else if (header.compression_method == CompressionMethod.stored) {
        //     var data_buf: [4096]u8 = undefined; // output buffer
        //     // try r.seekTo(zip64_extended_extra.compressed_size);
        //     const data = data_buf[0..zip64_extended_extra.compressed_size];
        //     try r.interface.readSliceAll(data);
        //     std.debug.print("data (0): {s}\n", .{data});
        // }

        return header;
    }

    pub fn requires_zip64(s: LocalFileHeader) bool {
        return s.compressed_size == 0xFFFFFFFF or
            s.uncompressed_size == 0xFFFFFFFF;
    }

    pub fn print(self: LocalFileHeader) void {
        std.debug.print("Local File Header\n", .{});
        std.debug.print("-------------------------------\n", .{});
        std.debug.print("    signature                            0x{x}\n", .{self.signature});
        std.debug.print("    version_needed_to_extract            {d:.2}\n", .{@as(f32, @floatFromInt(self.version_needed_to_extract)) / 10.0});
        std.debug.print("    flags                                {}\n", .{self.flags});
        std.debug.print("    compression_method                   {any}\n", .{self.compression_method});
        std.debug.print("    last_modification_time               {}\n", .{time.decodeDOSTime(self.last_modification_time)});
        std.debug.print("    last_modification_date               {}\n", .{time.decodeDosDate(self.last_modification_date)});
        std.debug.print("    crc-32 checksum                      {x}\n", .{self.crc32});
        std.debug.print("    compressed_size                      {d}\n", .{self.compressed_size});
        std.debug.print("    uncompressed_size                    {d}\n", .{self.uncompressed_size});
        std.debug.print("    filename_len                         {d}\n", .{self.filename_len});
        std.debug.print("    extra_len                            {d}\n\n", .{self.extra_len});
    }
};

/// 4-bytes (0x04034b50 as little-endian order)
const local_file_header_signature: u32 = 0x50_4B_03_04;
const local_file_header_size: u32 = 30;

test "local file header structure" {
    try std.testing.expectEqual(
        @sizeOf(LocalFileHeader),
        local_file_header_size,
    );

    try std.testing.expectEqual(
        @bitSizeOf(LocalFileHeader),
        local_file_header_size * 8,
    );

    try std.testing.expectEqual(
        std.mem.readInt(u32, &[_]u8{ 'P', 'K', 3, 4 }, .little),
        0x04_03_4B_50,
    );
}

const Version = packed struct(u16) {
    spec_version: u8, // lower byte
    os: u8, // upper byte
};

const FileData = struct {
    compressed_size: u64,
    header: LocalFileHeader,
    offset: u64,

    // pub fn parseExtra(extra: []const u8) !ExtraMetadata {
    //     var meta = ExtraMetadata{};
    //     var offset: usize = 0;
    //
    //     while (offset < extra.len) {
    //         if (offset + 4 > extra.len) {
    //             return error.ZipExtraInvalid;
    //         }
    //
    //         const header_id: HeaderId = @enumFromInt(std.mem.readInt(u16, extra[offset..][0..2], .little));
    //         const size = std.mem.readInt(u16, extra[offset + 2 ..][0..2], .little);
    //
    //         offset += 4;
    //
    //         if (offset + size > extra.len) {
    //             return error.ZipExtraInvalid;
    //         }
    //
    //         const data = extra[offset .. offset + size];
    //         switch (header_id) {
    //             .zip64_extended_extra_field => try meta.parseZip64Extended(data),
    //             .extended_timestamp => try meta.parseExtendedTimestamp(data),
    //             // 0x7875 => try meta.parseUnixExtra(data),
    //             else => {},
    //         }
    //
    //         offset += size;
    //     }
    //
    //     std.debug.print("meta {}\n", .{meta});
    //     return meta;
    // }

    pub fn read(
        self: FileData,
        stream: *std.fs.File.Reader,
        buf: []u8,
    ) ![]u8 {
        if (buf.len < self.header.filename_len) {
            return error.ZipInsufficientBuffer;
        }

        try stream.seekTo(self.offset + local_file_header_size);

        const filename = buf[0..self.header.filename_len];
        {
            try stream.interface.readSliceAll(filename);
        }

        {
            var extra_buf: [1024]u8 = undefined;
            const extra = extra_buf[0..self.header.extra_len];
            try stream.interface.readSliceAll(extra);

            // const extra_meta = try parseExtra(extra);
            // std.debug.print("extra: {}\n", .{extra_meta});
        }

        switch (self.header.compression_method) {
            .stored, .deflate => {},
            else => return error.UnsupportedCompressionMethod,
        }

        return filename;
    }

    pub fn extract() !void {}
};

/// Central directory structure:
/// [ file header 1 ]
/// [ file header 2 ]
/// ...
/// [ file header n ]
/// [digital signature]
/// [ Zip64 end of central directory record ]
/// [ Zip64 end of central directory locator ]
/// [ End of central directory record ]
///
/// The file header are similar to the local file headers,
/// but contain some extra information. The Zip64 entries
/// handle the case of a 64-bit Zip arhive, and the end
/// central directory record contains information about the
/// archive itself.
pub const CentralDirectoryFileHeader = extern struct {
    signature: u32 align(1),
    version_made_by: Version align(1),
    version_needed_to_extract: u16 align(1),
    flags: GeneralPurposeFlags align(1),
    compression_method: CompressionMethod align(1),
    last_modification_time: u16 align(1),
    last_modification_date: u16 align(1),
    crc32: u32 align(1),
    compressed_size: u32 align(1),
    uncompressed_size: u32 align(1),
    filename_len: u16 align(1),
    extra_len: u16 align(1),
    comment_len: u16 align(1),
    disk_number_start: u16 align(1),
    internal_file_attributes: u16 align(1),
    external_file_attributes: u32 align(1),
    local_file_header_relative_offset: u32 align(1),
    // ...
    // filename (variable size)
    // extra field (variable size)
    // file comment (variable size)

    const signature_mask: u32 = 0x02_01_4B_50;
    const size: u64 = 46;

    fn read(
        reader: *std.fs.File.Reader,
        offset: u64,
    ) !CentralDirectoryFileHeader {
        try reader.seekTo(offset);
        const cdfh = try reader.interface.takeStruct(CentralDirectoryFileHeader, .little);

        if (cdfh.signature != signature_mask) return error.ZipBadSignature;
        if (cdfh.disk_number_start != 0) return error.ZipUnsupportedMultiDisk;

        // If any of these are 0xFFFFFFFF:
        // - cdfh.compressed_size
        // - cdfh.uncompressed_size
        // - cdfh.local_file_header_relative_offset
        // Then the real values are stored in extra field 0x0001
        // TODO (dapa)
        // Requirement:
        // - parse extra field
        // - extract zip64 extended information
        // - override values
        // Validation:
        // - ZIP64 extra field actually exists
        // - It contains expected fields
        // - Its length mathces

        // If sentinel is present but extra field missing -> error.ZipMalformed

        //  try parseExtra();

        return cdfh;
        // @panic("no implemented!");
    }

    fn computeEntrySize(self: CentralDirectoryFileHeader) !u64 {
        const filename_offset = std.math.add(
            u64,
            size,
            self.filename_len,
        ) catch return error.ZipSizeOverflow;

        const extra_field_offset: u64 = std.math.add(
            u64,
            filename_offset,
            self.extra_len,
        ) catch return error.ZipSizeOverflow;

        return std.math.add(u64, extra_field_offset, self.comment_len) catch return error.Zip64SizeOverflow;
    }

    pub fn requires_zip64(self: CentralDirectoryFileHeader) bool {
        return @as(u64, self.local_file_header_relative_offset) == 0xFFFFFFFF or
            @as(u64, self.compressed_size) == 0xFFFFFFFF or
            @as(u64, self.uncompressed_size) == 0xFFFFFFFF or
            @as(u32, self.disk_number_start) == 0xFFF;
    }

    pub fn print(self: CentralDirectoryFileHeader) void {
        std.debug.print("Central Directory File Header\n", .{});
        std.debug.print("-------------------------------\n", .{});
        std.debug.print("    signature:                             0x{x}\n", .{self.signature});
        std.debug.print("    version_made_by:                       {}\n", .{self.version_made_by});
        std.debug.print("    version_needed_to_extract:             {d:.1}\n", .{@as(f64, @floatFromInt(self.version_needed_to_extract)) / 10.0});
        std.debug.print("    flags:                                 {}\n", .{self.flags});
        std.debug.print("    compression_method:                    {any}\n", .{self.compression_method});
        std.debug.print("    last_modification_time:                {}\n", .{time.decodeDOSTime(self.last_modification_time)});
        std.debug.print("    last_modification_date:                {}\n", .{time.decodeDosDate(self.last_modification_date)});
        std.debug.print("    crc32:                                 {x}\n", .{self.crc32});
        std.debug.print("    compressed_size:                       {d}\n", .{self.compressed_size});
        std.debug.print("    uncompressed_size:                     {d}\n", .{self.uncompressed_size});
        std.debug.print("    filename_len:                          {d}\n", .{self.filename_len});
        std.debug.print("    extra_len:                             {d}\n", .{self.extra_len});
        std.debug.print("    comment_len:                           {d}\n", .{self.comment_len});
        std.debug.print("    disk_number_start:                     {d}\n", .{self.disk_number_start});
        std.debug.print("    internal_file_attributes:              {d}\n", .{self.internal_file_attributes});
        std.debug.print("    external_file_attributes:              0x{x}\n", .{self.external_file_attributes});
        std.debug.print("    local_file_header_offset:              {d}\n\n", .{self.local_file_header_relative_offset});
    }
};

const cdfh_signature: u32 = 0x50_4B_01_02;
const cdfh_size: u32 = 46;

// Digital Signature
pub const DigitalSignature = struct {
    signature: u32, // 0x05_05_4b_50 (little)
    size_of_data: u16,
    // ...
    // signature_data (variable size)
};

test "central directory file header structure" {
    try std.testing.expectEqual(
        @sizeOf(CentralDirectoryFileHeader),
        cdfh_size,
    );

    try std.testing.expectEqual(
        @bitSizeOf(CentralDirectoryFileHeader),
        cdfh_size * 8,
    );

    try std.testing.expectEqual(
        std.mem.readInt(u32, &[_]u8{ 'P', 'K', 1, 2 }, .little),
        0x02_01_4B_50,
    );
}

/// End of central directory record (EOCD)
const eocd_signature: u32 = 0x50_4B_05_06;
const eocd_signature_bytes = [_]u8{ 0x50, 0x4B, 5, 6 };
const eocd_size: usize = 22;
const max_u16: u32 = std.math.maxInt(u16);

// simple ZIP Layout
// [file entries...]
// [Central Directory...]
// [EOCD]
// The classic EOCD Record uses 16-bit and 32-bit fields.
// `u16` for record counts and `u32` for central directory
// size and offset. The limits is max entries only up to (65_535),
// max central directory size 4 GiB, and max offset 4 GiB.
//
// When any of those values exceed those limits, the specs says:
// `Set the field to 0xFFFF or 0xFFFFFFFF and create the ZIP64
// EOCD record.`
//
// TODO (dapa)
// Flows for ZIP64:
// - Parse the ZIP64 End of Central Directory Locator
// - Use it to find the ZIP64 End of Central Directory Record
// - Read the real 64-bit values from there

// Overall .ZIP file format
// [local file header 1]
// [encryption header 1]
// [file data 1]
// [data descriptor 1]
// .
// .
// .
// [local file header n]
// [encryption header n]
// [file data n]
// [data descriptor n]
// [archive decryption header]
// [archive extra data record]
// [central directory header 1]
// .
// .
// .
// [central directory header n]
// [zip64 end of central directory record]
// [zip64 end of central directory locator]
// [end of central directory record]
const EndRecord64Locator = extern struct {
    signature: u32 align(1),
    central_directory_disk: u32 align(1),
    central_directory_offset: u64 align(1),
    total_disks: u32 align(1),

    pub const signature_mask: u32 = 0x07064B50;
    pub const size: u32 = 20;

    pub fn read(reader: *std.fs.File.Reader, file_size: u64, offset: u64) !EndRecord64Locator {
        if (offset < size) {
            return error.Zip64Malformed;
        }

        const locator_offset: u64 = offset - eocd64_locator_size;
        try reader.seekTo(locator_offset);
        const locator = try reader.interface.takeStruct(EndRecord64Locator, .little);
        if (locator.signature != signature_mask) {
            return error.Zip64InvalidSignature;
        }

        try locator.validateStructure(file_size, locator_offset, offset);
        return locator;
    }

    fn validateStructure(
        self: EndRecord64Locator,
        file_size: u64,
        locator_offset: u64,
        eocd_offset: u64,
    ) error{ ZipUnsupportedMultiDisk, ZipMalformed }!void {
        // TODO (dapa)
        // must be a single disk
        if (self.central_directory_disk != 0 or self.total_disks != 1) {
            return error.ZipUnsupportedMultiDisk;
        }

        // must be adjacent to EOCD
        if (locator_offset + size != eocd_offset) {
            return error.ZipMalformed;
        }

        if (self.central_directory_offset >= file_size) {
            return error.ZipMalformed;
        }
    }

    pub fn print(self: EndRecord64Locator) void {
        std.debug.print("End Of Central Directory Record ZIP64 Locator\n", .{});
        std.debug.print("signature 0x{x}\n", .{self.signature});
        std.debug.print("central_directory_disk {}\n", .{self.central_directory_disk});
        std.debug.print("central_directory_offset {}\n", .{self.central_directory_offset});
        std.debug.print("total_disks {}\n", .{self.total_disks});
    }
};

const eocd64_locator_signature: u32 = 0x50_4B_06_07;
const eocd64_locator_size: usize = 20;

test "eocd64_locator_structure" {
    try std.testing.expectEqual(@sizeOf(EndRecord64Locator), eocd64_locator_size);
    try std.testing.expectEqual(@bitSizeOf(EndRecord64Locator), eocd64_locator_size * 8);
}

// The value store into the "size of zip64 eocd record"
// SHOULD be the size of the remaining record and SHOULD
// NOT include the leading 12 bytes.
// Size = SizeOfFixedFields + SizeOfVariableData - 12.
const EndOfCentralDirectoryRecord64 = extern struct {
    version_made_by: Version align(1),
    version_needed_to_extract: u16 align(1),
    disk_number: u32 align(1),
    central_directory_disk_number: u32 align(1),
    record_count_disk: u64 align(1),
    record_count_total: u64 align(1),
    central_directory_size: u64 align(1),
    central_directory_offset: u64 align(1),
    // ...
    // Data sector (variable size) [optional]

    /// 4.3.14.1 The value stored into the "size of zip64 end of central
    ///          directory record" SHOULD be the size of the remaining
    ///          record and SHOULD NOT include the leading 12 bytes.
    ///
    ///          Size = SizeOfFixedFields + SizeOfVariableData - 12.
    const header64 = extern struct {
        signature: u32 align(1),
        record_size: u64 align(1),
    };

    const signature_marker: u32 = 0x06_06_4b_50;
    const size: u64 = 44;

    pub fn read(reader: *std.fs.File.Reader, file_size: u64, offset: u64) !EndOfCentralDirectoryRecord64 {
        try reader.seekTo(offset);

        const header = try reader.interface.takeStruct(
            header64,
            .little,
        );

        if (header.signature != signature_marker) {
            return error.Zip64InvalidSignature;
        }

        if (header.record_size < size) {
            return error.Zip64Malformed;
        }

        const total_size: u64 = std.math.add(u64, 12, header.record_size) catch return error.Zip64SizeOverflow;
        if (offset + total_size > file_size) {
            return error.Zip64SizeOverflow;
        }

        const record = try reader.interface.takeStruct(EndOfCentralDirectoryRecord64, .little);

        // check if there's extensible data record remaining
        if (header.record_size > size) {
            // TODO (dapa)
            // Parse The Extensible Data?
            // unimplemented supported:
            // Central directory encryption
            // Strong encryption (spec 6.2+)
            // PKWARE proprietary extensions

            const remaining = header.record_size - size;
            // try reader.seekBy(@as(i64, @intCast(remaining)));
            reader.interface.toss(remaining);
        }

        try record.validateStructure(offset);
        return record;
    }

    fn validateStructure(
        self: EndOfCentralDirectoryRecord64,
        offset: u64,
    ) error{ Zip64UnsupportedMultiDisk, Zip64SizeOverflow, Zip64Malformed }!void {
        if (self.disk_number != 0 or
            self.central_directory_disk_number != 0 or
            self.record_count_disk != self.record_count_total)
        {
            return error.Zip64UnsupportedMultiDisk;
        }

        const end = std.math.add(u64, self.central_directory_offset, self.central_directory_size) catch return error.Zip64SizeOverflow;
        if (end > offset) {
            return error.Zip64SizeOverflow;
        }
    }

    pub fn print(self: EndOfCentralDirectoryRecord64) void {
        std.debug.print("End Of Central Directory Record ZIP64\n", .{});
        std.debug.print("version_made_by {}\n", .{self.version_made_by});
        std.debug.print("version_needed_to_extract {}\n", .{self.version_needed_to_extract});
        std.debug.print("disk_number {}\n", .{self.disk_number});
        std.debug.print("central_directory_disk_number {}\n", .{self.central_directory_disk_number});
        std.debug.print("record_count_disk {}\n", .{self.record_count_disk});
        std.debug.print("record_count_total {}\n", .{self.record_count_total});
        std.debug.print("central_directory_size {}\n", .{self.central_directory_size});
        std.debug.print("central_directory_offset {}\n", .{self.central_directory_offset});
    }
};

test "End of Central Directory Record ZIP64" {
    try std.testing.expectEqual(@sizeOf(EndOfCentralDirectoryRecord64.header64), 12);
    try std.testing.expectEqual(@bitSizeOf(EndOfCentralDirectoryRecord64.header64), 12 * 8);

    // signature
    try std.testing.expectEqual(EndOfCentralDirectoryRecord64.signature_marker, 0x06_06_4b_50);
    try std.testing.expectEqual(EndOfCentralDirectoryRecord64.size, 44);

    try std.testing.expectEqual(@sizeOf(EndOfCentralDirectoryRecord64), EndOfCentralDirectoryRecord64.size);
    try std.testing.expectEqual(@bitSizeOf(EndOfCentralDirectoryRecord64), EndOfCentralDirectoryRecord64.size * 8);
}

const EndOfCentralDirectoryRecord = extern struct {
    signature: u32 align(1),
    disk_number: u16 align(1),
    central_directory_disk_number: u16 align(1),
    record_count_disk: u16 align(1),
    record_count_total: u16 align(1),
    central_directory_size: u32 align(1),
    central_directory_offset: u32 align(1),
    comment_len: u16 align(1),

    const size: u64 = 22;

    /// [4.4.1 General notes on fields] (https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
    /// 4.4.1.4  If one of the fields in the end of central directory
    /// record is too small to hold required data, the field SHOULD be
    /// set to -1 (0xFFFF or 0xFFFFFFFF) and the ZIP64 format record
    /// SHOULD be created.
    ///
    /// 4.4.1.5  The end of central directory record and the Zip64 end
    /// of central directory locator record MUST reside on the same
    /// disk when splitting or spanning an archive.
    pub fn requiresZip64(self: EndOfCentralDirectoryRecord) bool {
        return self.record_count_total == 0xFFFF or
            self.record_count_disk == 0xFFFF or
            self.central_directory_size == 0xFFFFFFFF or
            self.central_directory_offset == 0xFFFFFFFF;
    }

    pub fn read(f: *std.fs.File.Reader) !struct {
        offset: u64,
        record: EndOfCentralDirectoryRecord,
    } {
        const file_size: u64 = try f.getSize();
        if (file_size < eocd_size) {
            return error.ZipNoEndRecord;
        }

        const max_record_len = eocd_size + max_u16;
        var buffer: [max_record_len]u8 = undefined;
        const search_limit = @min(file_size, buffer.len);

        var loaded_len: usize = 0;
        var comment_len: u16 = 0;

        const base_file_offset = file_size - search_limit;

        while (comment_len <= max_u16) {
            const record_len = @as(usize, comment_len) + eocd_size;
            if (record_len > search_limit) {
                return error.ZipNoEndRecord;
            }

            try ensureLoaded(f, file_size, buffer[buffer.len - search_limit ..], &loaded_len, record_len);

            // [file data .............][ EOCD header ][ comment ]
            //                             ^ start
            const record_offset = search_limit - record_len;
            const window_start = buffer.len - search_limit;
            const record_start = window_start + record_offset;
            const record_bytes = buffer[record_start..][0..eocd_size];

            if (isValidEndRecord(record_bytes, comment_len)) {
                return .{
                    .record = parse(record_bytes),
                    .offset = base_file_offset + record_offset,
                };
            }

            comment_len += 1;
        }
    }

    fn validateStructure(
        self: EndOfCentralDirectoryRecord,
        file_size: u64,
        offset: u64,
    ) error{ ZipMalformed, ZipUnsupportedMultiDisk }!void {
        // no multi-disk support
        if (self.disk_number != 0 or
            self.central_directory_disk_number != 0 or
            self.record_count_disk != self.record_count_total)
        {
            return error.ZipUnsupportedMultiDisk;
        }

        // validate comment lenght consistency
        const expected_end = std.math.add(u64, offset, size) catch return error.ZipMalformed;
        const actual_end = std.math.add(u64, expected_end, self.comment_len) catch return error.ZipMalformed;
        if (actual_end != file_size) {
            return error.ZipMalformed;
        }
    }

    fn validateSizeFields(self: EndOfCentralDirectoryRecord, file_size: u64) error{
        ZipSizeOverflow,
        ZipEmptyArchive,
        ZipUnsupportedMultiDisk,
    }!void {
        if (self.central_directory_offset >= file_size) {
            return error.ZipSizeOverflow;
        }

        if (self.record_count_total == 0) {
            return error.ZipEmptyArchive;
        }

        const end = std.math.add(
            u64,
            self.central_directory_offset,
            self.central_directory_size,
        ) catch return error.ZipSizeOverflow;

        if (end > file_size) return error.ZipSizeOverflow;
    }

    pub fn getOffset(self: EndOfCentralDirectoryRecord) usize {
        return self.central_directory_size + self.central_directory_offset;
    }

    pub fn readComment(
        reader: *std.fs.File.Reader,
        file_size: u64,
        offset: u64,
        comment_len: u64,
        buf: []u8,
    ) ![]u8 {
        if (comment_len == 0) return buf[0..0];

        if (buf.len < comment_len) {
            return error.InsufficientBufferSize;
        }

        const comment_offset = offset + eocd_size;
        const comment_end = try std.math.add(u64, comment_offset, comment_len);

        if (comment_end != file_size) {
            return error.InvalidZipStructure;
        }

        try reader.seekTo(comment_offset);

        const out = buf[0..comment_len];
        try reader.interface.readSliceAll(out);
        return out;
    }

    fn parse(bytes: []const u8) EndOfCentralDirectoryRecord {
        return EndOfCentralDirectoryRecord{
            .signature = std.mem.readInt(u32, bytes[0..4], .little),
            .disk_number = std.mem.readInt(u16, bytes[4..6], .little),
            .central_directory_disk_number = std.mem.readInt(u16, bytes[6..8], .little),
            .record_count_disk = std.mem.readInt(u16, bytes[8..10], .little),
            .record_count_total = std.mem.readInt(u16, bytes[10..12], .little),
            .central_directory_size = std.mem.readInt(u32, bytes[12..16], .little),
            .central_directory_offset = std.mem.readInt(u32, bytes[16..20], .little),
            .comment_len = std.mem.readInt(u16, bytes[20..22], .little),
        };
    }

    fn isValidEndRecord(record_bytes: []const u8, expected_comment_len: u16) bool {
        if (!std.mem.eql(u8, record_bytes[0..4], &eocd_signature_bytes)) {
            return false;
        }
        const actual_comment_len = std.mem.readInt(u16, record_bytes[20..22], .little);
        return actual_comment_len == expected_comment_len;
    }

    fn ensureLoaded(
        file_reader: *std.fs.File.Reader,
        file_size: u64,
        buf: []u8,
        loaded_len: *usize,
        required_len: usize,
    ) !void {
        const step: u16 = 512;
        while (required_len > loaded_len.*) {
            const new_loaded = @min(loaded_len.* + step, buf.len);
            const n = new_loaded - loaded_len.*;

            try file_reader.seekTo(file_size - new_loaded);
            const target = buf[buf.len - new_loaded ..][0..n];
            try file_reader.interface.readSliceAll(target);

            loaded_len.* = new_loaded;
        }
    }

    pub fn print(self: EndOfCentralDirectoryRecord) void {
        std.debug.print("End-of-central-directory record\n", .{});
        std.debug.print("-------------------------------\n", .{});
        std.debug.print("    signature                             0x{X}\n", .{self.signature});
        std.debug.print("    disk_number                           {d}\n", .{self.disk_number});
        std.debug.print("    central_directory_disk_number         {d}\n", .{self.central_directory_disk_number});
        std.debug.print("    record_count_disk                     {d}\n", .{self.record_count_disk});
        std.debug.print("    record_count_total                    {d}\n", .{self.record_count_total});
        std.debug.print("    central_directory_size                {d}\n", .{self.central_directory_size});
        std.debug.print("    central_directory_offset              {d}\n", .{self.central_directory_offset});
        std.debug.print("    comment_len                           {d}\n\n", .{self.comment_len});
    }
};

/// File data
/// Immediately following the local header for a file
/// SHOULD be placed the compressed or stored data for the file.
/// If the file is encrypted, the encryption header for the file
/// SHOULD be placed after the local header and before the file
/// data. The series of [local file header][encryption header]
/// [file data][data descriptor] repeats for each file in the
/// .ZIP archive.
///
/// Zero-byte files, directories, and other file types that
/// contain no content MUST NOT include file data.
/// Data Descriptor (Optional)
/// Although not originally assigned a signature, the value
/// 0x08074b50 has commonly been adopted as a signature value
/// for the data descriptor record.
/// When the Central Directory Encryption method is used,
/// the data descriptor record is not required, but MAY be used.
/// If present, and bit 3 of the general purpose bit field is set to
/// indicate its presence, the values in fields of the data descriptor
/// record MUST be set to binary zeros.
const data_descriptor_signature: u32 = 0x50_4B_07_08;

// Archive decryption header
// The Archive Decryption Header is introduced in version 6.2
// of the ZIP format specification. This record exists in support
// of the Central Directory Encryption Feature implemented as part
// of the Strong Encryption Specification.
// When the Central Directory Structure is encrypted, this decryption
// header MUST precede the encrypted data segment.

/// Extensible Data Fields
/// Extra fields are documented in PKWARE's appnote.txt and are
/// intended to allow for backward- and forward-compatible extensions
/// to the zipfile format. Multiple extra-field data is less then 66KB.
/// (In fact, PKWARE requires that the total length of the entire file
/// header, including timestamp, file attributes, file name, comment,
/// extra field, etc., be no more than 64KB).
///
/// Each extra-field type must contain a for byte header consisting of a
/// two-byte Header ID and a two-byte length in least significant order
/// byte (little-endian) for the remaining data in the subblock. If there
/// are extra additional subblocks within the extra field, the header for
/// each one will appear immediately following the data for the previous
/// subblock (i.e., with no padding or allignment).
///
/// All integer fields in the description below are in little-endian
/// format unless otherwise specifed. Note that "Short" means two bytes,
/// "Long" means four bytes, and "Long-Long" means eight bytes, regardless
/// of their native sizes. Unless specifically noted, all integer fields
/// should be interpreted as unsigned (non-negative) numbers.
///
/// refs:
/// - [4.5 Extensible Data Fields](https://pkwaredownloads.blob.core.windows.net/pem/APPNOTE.txt)
/// - [Extra Fields](https://libzip.org/specifications/extrafld.txt)
pub const HeaderId = enum(u16) {
    // The current Header ID mappings defined by PKWARE are:
    /// Zip64 extended information extra field
    zip64_extended_extra_field = 0x0001,
    /// AV Info
    av_info = 0x0007,
    /// https://en.wikipedia.org/wiki/OS/2
    os2_extended_attributes = 0x0009, // also Info-ZIP
    /// Win9x/WinNT FileTimes
    ntfs = 0x000a,
    /// OpenVMS
    open_vms = 0x000c, // also Info-ZIP
    /// Unix
    unix = 0x000d,
    /// Patch Descrptor
    patch_descriptor = 0x000f,
    /// PKCS#7 Store for X.509 Certificates
    pkcs7_certs = 0x0014,
    /// X.509 Certificate ID and Signature for individual file
    x509_certificate_id_and_signature = 0x0015,
    // X.509 Certificate ID for Central Directory
    x509_certificate_id_for_central_directory = 0x0016,

    // The Header ID mappings defined by Info-ZIP and third parties are:
    /// IBM S/390 attributes - uncompressed
    ibm_s390_attributes_uncompressed = 0x0065,
    /// IBM S/390 attributes - compressed
    ibm_s390_attributes_compressed = 0x0066,
    /// Info-ZIP Macintosh (old, J. Lee)
    info_zip_macintosh = 0x07c8,
    /// ZipIt Macintosh (first version)
    zipit_macintosh = 0x2605,
    /// 0x2705        ZipIt Macintosh v 1.3.5 and newer (w//o full filename)
    zipit_macintosh_v1_3_5 = 0x2705,
    /// Info-ZIP Macintosh (new, D. Haase's 'Mac3' field)
    info_zip_macintosh_mac3 = 0x334d,
    /// 0x4154        Tandem NSK
    tandem_nsk = 0x4154,
    /// 0x4341        Acorn//SparkFS (David Pilling)
    acorn_sparkfs = 0x4341,
    /// 0x4453        Windows NT security descriptor (binary ACL)
    windows_nt_security_descriptor = 0x4453,
    /// 0x4704        VM//CMS
    vm_cms = 0x4704,
    /// 0x470f        MVS
    mvs = 0x470f,
    /// 0x4854        Theos, old inofficial port
    theos_old = 0x4854,
    /// 0x4b46        FWKCS MD5 (see below)
    fwkcs_md5 = 0x4b46,
    /// 0x4c41        OS//2 access control list (text ACL)
    os2_acl = 0x4c41,
    /// 0x4d49        Info-ZIP OpenVMS (obsolete)
    info_zip_openvms_obsolete = 0x4d49,
    /// 0x4d63        Macintosh SmartZIP, by Macro Bambini
    macintosh_smartzip = 0x4d63,
    /// 0x4f4c        Xceed original location extra field
    xceed_orginal_location = 0x4f4c,
    /// 0x5356        AOS//VS (binary ACL)
    aos_vs = 0x5356,
    /// 0x5455        extended timestamp
    extended_timestamp = 0x5455,
    /// 0x5855        Info-ZIP Unix (original; also OS//2, NT, etc.)
    info_zip_unix = 0x5855,
    /// 0x554e        Xceed unicode extra field
    xceed_unicode_field = 0x554e,
    /// 0x6375        Info-ZIP Unicode Comment
    info_zip_unicode_comment = 0x6375,
    /// 0x6542        BeOS (BeBox, PowerMac, etc.)
    beos = 0x6542,
    /// 0x6854        Theos
    theos = 0x6854,
    /// 0x7075        Info-ZIP Unicode Path
    info_zip_unicode_path = 0x7075,
    /// 0x756e        ASi Unix
    asi_unix = 0x756e,
    /// 0x7855        Info-ZIP Unix (previous new)
    info_zip_unix_previous = 0x7855,
    /// 0x7875        Info-ZIP Unix (new)
    info_zip_unix_new = 0x7875,
    /// 0xfb4a        SMS//QDOS
    sms_qdos = 0xfb4a,
};

pub const ExtraMetadata = struct {
    // ZIP64
    zip64_uncompressed_size: ?u64 = null,
    zip64_compressed_size: ?u64 = null,
    zip64_local_header_offset: ?u64 = null,
    zip64_disk_number_start: ?u32 = null,

    // Extended timestamp (0x5455)
    mod_time_unix: ?u32 = null,
    access_time_unix: ?u32 = null,
    creation_time_unix: ?u32 = null,

    // Info-ZIP Unix (0x7875)
    uid: ?u32 = null,
    gid: ?u32 = null,

    /// Parse ZIP64 Extended Information Data Fields
    /// Note: all fields stored in Intel low-byte/high-byte order.
    ///
    ///         Value      Size       Description
    ///         -----      ----       -----------
    /// (ZIP64) 0x0001     2 bytes    Tag for this "extra" block type
    ///
    ///         Size       2 bytes    Size of this "extra" block
    ///         Original
    ///
    ///         Size       8 bytes    Original uncompresseed file size
    ///         Compressed
    ///
    ///         Size       8 bytes    Size of compressed data
    ///         Relative Header
    ///
    ///         Offset     8 bytes    Offset of local header record
    ///
    ///         Disk Start
    ///         Number     4 bytes    Number of the disk on which
    ///                               this file starts
    ///
    /// This entry in the Local header must include BOTH original
    /// and compressed file sizes.
    pub fn parseZip64Extended(self: *ExtraMetadata, data: []const u8) !void {
        var offset: usize = 0;
        if (offset + 8 <= data.len) {
            self.zip64_uncompressed_size =
                std.mem.readInt(u64, data[offset..][0..8], .little);
            offset += 8;
        }

        if (offset + 8 <= data.len) {
            self.zip64_compressed_size =
                std.mem.readInt(u64, data[offset..][0..8], .little);
            offset += 8;
        }

        if (offset + 8 <= data.len) {
            self.zip64_local_header_offset =
                std.mem.readInt(u64, data[offset..][0..8], .little);
            offset += 8;
        }

        if (offset + 4 <= data.len) {
            self.zip64_disk_number_start =
                std.mem.readInt(u32, data[offset..][0..4], .little);
            offset += 4;
        }

        if (offset != data.len) return error.Zip64Malformed;
    }

    /// Extended Timestamps
    /// format: 1 byte flags + optional 4-byte mod/access/creation timestamps
    /// The following is the layout of the extended-timestamp extra block.
    ///
    /// (Last Revision 19970118)
    ///
    ///         Local-header version:
    ///
    ///         Value         Size        Description
    ///         -----         ----        -----------
    /// (time)  0x5455        Short       tag for this extra block type ("UT")
    ///         TSize         Short       total data size for this block
    ///         Flags         Byte        info bits
    ///         (ModTime)     Long        time of last modification (UTC/GMT)
    ///         (AcTime)      Long        time of last access (UTC/GMT)
    ///         (CrTime)      Long        time of original creation (UTC/GMT)
    ///
    ///         Central-header version:
    ///
    ///         Value         Size        Description
    ///         -----         ----        -----------
    /// (time)  0x5455        Short       tag for this extra block type ("UT")
    ///         TSize         Short       total data size for this block
    ///         Flags         Byte        info bits (refers to local header!)
    ///         (ModTime)     Long        time of last modification (UTC/GMT)
    ///
    /// The central-header extra field contains the modification time only,
    /// or no timestamp at all.  TSize is used to flag its presence or
    /// absence.
    ///
    /// The lower three bits of Flags in both headers indicate which time-
    /// stamps are present in the LOCAL extra field:
    /// bit 0       if set, modification time is present
    /// bit 1       if set, access time is present
    /// bit 2       if set, creation time is present
    /// bits 3-7    reserved for additional timestamps; not set
    ///
    /// Those times that are present will appear in the order indicated, but
    /// any combination of times may be omitted. (Creation time may be present
    /// without access time, for example.)  TSize should equal
    /// (1 + 4*(number of set bits in Flags)), as the block is currently defined.
    /// Other timestamps may be added in the future.
    fn parseExtendedTimestamp(self: *ExtraMetadata, data: []const u8) !void {
        if (data.len < 1) return error.InvalidExtraField;

        const flags = data[0];
        var offset: usize = 1;

        if ((flags & 0x01) != 0 and offset + 4 <= data.len) {
            self.mod_time_unix = std.mem.readInt(u32, data[offset..][0..4], .little);
            offset += 4;
        }

        if ((flags & 0x02) != 0 and offset + 4 <= data.len) {
            self.access_time_unix = std.mem.readInt(u32, data[offset..][0..4], .little);
            offset += 4;
        }

        if ((flags & 0x04) != 0 and offset + 4 <= data.len) {
            self.creation_time_unix = std.mem.readInt(u32, data[offset..][0..4], .little);
        }
    }

    fn parseUnixExtra(meta: *ExtraMetadata, data: []const u8) !void {
        if (data.len < 3)
            return error.InvalidExtraField;

        var offset: usize = 0;

        const version = data[offset];
        _ = version; // currently unused
        offset += 1;

        const uid_size = data[offset];
        offset += 1;

        if (offset + uid_size > data.len)
            return error.InvalidExtraField;

        meta.uid = std.mem.readInt(
            u32,
            @ptrCast(data[offset .. offset + 4].ptr),
            .little,
        );
        offset += uid_size;

        if (offset >= data.len)
            return;

        const gid_size = data[offset];
        offset += 1;

        if (offset + gid_size > data.len)
            return error.InvalidExtraField;

        meta.gid = std.mem.readInt(
            u32,
            // data[offset .. offset + gid_size],
            @ptrCast(data[offset .. offset + 4].ptr),
            .little,
        );
    }
};

/// Iterator
const Iterator = struct {
    reader: *std.fs.File.Reader,
    cd_index: u64 = 0,
    cd_offset: u64 = 0,
    cd_size: u64 = 0,
    total_entries: u64 = 0,
    cd_end: u64 = 0,
    cd_start: u64 = 0,
    file_size: u64,

    /// entries count DoS guard
    const max_reasonable_entries = 10_000_000;

    pub fn init(reader: *std.fs.File.Reader) !Iterator {
        const file_size = try reader.getSize();
        std.debug.print("file_size: {}\n", .{file_size});

        // Read EOCD record
        const eocd = try EndOfCentralDirectoryRecord.read(reader);
        try eocd.record.validateStructure(file_size, eocd.offset);

        var iterator: Iterator = .{ .reader = reader, .file_size = file_size };

        const requires_zip64 = eocd.record.requiresZip64();
        if (!requires_zip64) {
            try eocd.record.validateSizeFields(file_size);
            iterator.cd_size = eocd.record.central_directory_size;
            iterator.cd_offset = eocd.record.central_directory_offset;
            iterator.total_entries = eocd.record.record_count_total;
        } else {
            // the archive is zip64 structure path
            // eocd zip64 allocator check
            const locator = try EndRecord64Locator.read(reader, file_size, eocd.offset);
            if (locator.central_directory_offset >= file_size) {
                return error.Zip64SizeOverflow;
            }

            const record64 = try EndOfCentralDirectoryRecord64.read(
                reader,
                file_size,
                locator.central_directory_offset,
            );

            iterator.cd_offset = record64.central_directory_offset;
            iterator.cd_size = record64.central_directory_size;
            iterator.total_entries = record64.record_count_total;
        }

        iterator.cd_start = iterator.cd_offset;
        iterator.cd_end = iterator.cd_offset + iterator.cd_size;

        try iterator.validateSizeFields(file_size);
        return iterator;
    }

    pub fn next(
        self: *Iterator,
    ) !?FileData {
        if (self.cd_index == self.total_entries) return null;
        if (self.cd_offset >= self.cd_end) return error.ZipMalformed;

        const cdfh = try CentralDirectoryFileHeader.read(
            self.reader,
            self.cd_offset,
        );

        if (cdfh.flags.encrypted) return error.ZipUnsupportedEncryption;

        const entry_size = try cdfh.computeEntrySize();
        const entry_end = std.math.add(u64, self.cd_offset, entry_size) catch return error.ZipSizeOverflow;
        if (entry_end > self.cd_end) return error.ZipMalformed;

        // std.debug.print("entry_size {}\n", .{entry_size});
        // std.debug.print("entry_end {}\n", .{entry_end});

        defer {
            self.cd_index += 1;
            self.cd_offset += entry_size;
        }

        var file_name_buf: [256]u8 = undefined;
        const file_name = file_name_buf[0..cdfh.filename_len];
        try self.reader.interface.readSliceAll(file_name);

        std.debug.print("Entry #{d} [{d}] - {s}\n", .{ self.cd_index + 1, self.cd_offset, file_name });
        cdfh.print();

        var extra_buf: [max_u16]u8 = undefined;
        const extra = extra_buf[0..cdfh.extra_len];
        try self.reader.interface.readSliceAll(extra);

        if (cdfh.comment_len > 0) {
            try self.reader.seekBy(cdfh.comment_len);
        }

        var zip64_extra: Extra.Zip64Extended = .{
            .compressed_size = @intCast(cdfh.compressed_size),
            .uncompressed_size = @intCast(cdfh.uncompressed_size),
            .local_file_header_relative_offset = @intCast(cdfh.local_file_header_relative_offset),
            .disk_number_start = @intCast(cdfh.disk_number_start),
        };

        if (cdfh.requires_zip64()) {
            const extra_iterator: Extra.Iterator = .{ .buf = extra };
            const field = extra_iterator.find(HeaderId.zip64_extended_extra_field) orelse return error.Zip64Malformed;
            const ctx: Extra.Context = .{
                .zip64_extended_extra_field = .{
                    .uncompressed_size = cdfh.uncompressed_size,
                    .compressed_size = cdfh.compressed_size,
                    .disk_number_start = cdfh.disk_number_start,
                    .local_file_header_relative_offset = cdfh.local_file_header_relative_offset,
                },
            };
            const out = try field.parse(ctx);
            zip64_extra = out.zip64_extended_extra_field;
        }

        const file_header = try LocalFileHeader.read(self.reader, zip64_extra.local_file_header_relative_offset);
        file_header.print();

        std.debug.print("zip64_extra {}\n", .{zip64_extra});

        // TODO (dapa) should i re-check on local file header too?
        // which one should be the trusted canonical sources?

        // zip64_extra = .{
        //     .compressed_size = @intCast(file_header.compressed_size),
        //     .uncompressed_size = @intCast(file_header.uncompressed_size),
        //     .disk_number_start = null,
        //     .local_file_header_relative_offset = null,
        // };
        // if (file_header.requires_zip64()) {
        //     const extra_iterator: Extra.Iterator = .{ .buf = extra };
        //     const field = extra_iterator.find(HeaderId.zip64_extended_extra_field) orelse return error.Zip64Malformed;
        //     const ctx: Extra.Context = .{
        //         .zip64_extended_extra_field = .{
        //             .uncompressed_size = file_header.uncompressed_size,
        //             .compressed_size = file_header.compressed_size,
        //             .local_file_header_relative_offset = null,
        //             .disk_number_start = null,
        //         },
        //     };
        //     const out = try field.parse(ctx);
        //     zip64_extra = out.zip64_extended_extra_field;
        // }
        //
        // file_header.print();

        // validate compressed_size and uncompressed_size cdfh and lfh

        return FileData{
            .header = file_header,
            .compressed_size = zip64_extra.compressed_size,
            .offset = zip64_extra.local_file_header_relative_offset,
        };
    }

    fn validateSizeFields(self: Iterator, file_size: u64) error{ EntryCountExceedsLimit, Zip64SizeOverflow, Zip64EmptyArchive }!void {
        // validate unified central directory bounds
        if (self.total_entries == 0) return error.Zip64EmptyArchive;
        if (self.total_entries > max_reasonable_entries) return error.EntryCountExceedsLimit;

        if (self.cd_offset >= file_size) return error.Zip64SizeOverflow;
        const end = std.math.add(u64, self.cd_offset, self.cd_size) catch return error.Zip64SizeOverflow;
        if (end > file_size) return error.Zip64SizeOverflow;
    }
};

test "eocd_structure" {
    // const with_comment_zip = "sample/with_comment.zip";
    // const my_epub = "sample/accessible_epub_3.epub";
    const as_zip64 = "sample/as_zip64.zip";

    var file = try std.fs.cwd().openFile(as_zip64, .{ .mode = .read_only });
    defer file.close();

    var buf: [1024]u8 = undefined;
    var freader = file.reader(&buf);

    var iter = try Iterator.init(&freader);

    while (try iter.next()) |fd| {
        _ = fd;
        // var filename_buffer: [128]u8 = undefined;
        // const fname = try fd.read(&freader, &filename_buffer);
        // std.debug.print("filename: {s}\n", .{fname});
    }
}

test {
    const myepub = "sample/accessible_epub_3.epub";
    var file = try std.fs.cwd().openFile(myepub, .{ .mode = .read_only });
    defer file.close();

    var buffer: [1024]u8 = undefined;
    var reader = file.reader(&buffer);

    var zip_iter: std.zip.Iterator = try .init(&reader);

    var filename_buf: [128]u8 = undefined;
    var count: usize = 0;

    while (try zip_iter.next()) |entry| {
        // std.debug.print("entry: {}\n", .{entry});
        const filename = filename_buf[0..entry.filename_len];
        try reader.seekTo(entry.header_zip_offset + @sizeOf(CentralDirectoryFileHeader));
        try reader.interface.readSliceAll(filename);

        // std.debug.print("filename: {s}\n", .{filename});
        // std.debug.print("size of CentralDirectoryFileHeader: {d}\n", .{@sizeOf(CentralDirectoryFileHeader)});
        count += 1;
    }
}
