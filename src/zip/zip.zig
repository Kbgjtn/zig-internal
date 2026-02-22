/// refs:
/// - https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
/// -
const std = @import("std");

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
    store = 0x0,
    deflate = 0x8,
    _,
};

pub const DosTime = struct {
    hour: u8,
    minute: u8,
    second: u8,
};

pub const DosDate = struct {
    year: u16,
    month: u8,
    day: u8,
};

pub fn decodeDOSTime(raw: u16) DosTime {
    return .{
        .hour = @as(u8, @truncate((raw & 0b00000_000000_11111) * 2)),
        .minute = @as(u8, @truncate((raw >> 5) & 0b111111)),
        .second = @as(u8, @truncate((raw >> 11) & 0b11111)),
    };
}

pub fn decodeDosDate(raw: u16) DosDate {
    return DosDate{
        .day = @as(u8, @truncate(raw & 0b11111)),
        .month = @as(u8, @truncate((raw >> 5) & 0b1111)),
        .year = 1980 + ((raw >> 9) & 0b1111111),
    };
}

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
    version: u16 align(1),
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

    pub fn print(self: LocalFileHeader) void {
        std.debug.print("Local File Header\n", .{});
        std.debug.print("  signature 0x{x}\n", .{self.signature});
        std.debug.print("  version {d:.2}\n", .{@as(f32, @floatFromInt(self.version)) / 10.0});
        std.debug.print("  flags {}\n", .{self.flags});
        std.debug.print("  last_modification_time {}\n", .{decodeDOSTime(self.last_modification_time)});
        std.debug.print("  last_modification_date {}\n", .{decodeDosDate(self.last_modification_date)});
        std.debug.print("  crc-32 checksum {d}\n", .{self.crc32});
        std.debug.print("  compressed_size {d}\n", .{self.compressed_size});
        std.debug.print("  uncompressed_size {d}\n", .{self.uncompressed_size});
        std.debug.print("  filename_len {d}\n", .{self.filename_len});
        std.debug.print("  extra_len {d}\n", .{self.extra_len});
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

    pub fn print(self: CentralDirectoryFileHeader) void {

        // TODO apply the print all attrs
        std.debug.print("CentralDirectoryFileHeader\n", .{});
        std.debug.print("  signature:                 0x{x}\n", .{self.signature});
        std.debug.print("  version_made_by:           {}\n", .{self.version_made_by});
        std.debug.print("  version_needed_to_extract: {d:.1}\n", .{@as(f64, @floatFromInt(self.version_needed_to_extract)) / 10.0});
        std.debug.print("  flags:                     {}\n", .{self.flags});
        std.debug.print("  compression_method:        {d}\n", .{@intFromEnum(self.compression_method)});
        std.debug.print("  last_modification_time:    {d}\n", .{self.last_modification_time});
        std.debug.print("  last_modification_date:    {d}\n", .{self.last_modification_date});
        std.debug.print("  crc32:                     0x{x}\n", .{self.crc32});
        std.debug.print("  compressed_size:           {d}\n", .{self.compressed_size});
        std.debug.print("  uncompressed_size:         {d}\n", .{self.uncompressed_size});
        std.debug.print("  filename_len:              {d}\n", .{self.filename_len});
        std.debug.print("  extra_len:                 {d}\n", .{self.extra_len});
        std.debug.print("  comment_len:               {d}\n", .{self.comment_len});
        std.debug.print("  disk_number:               {d}\n", .{self.disk_number_start});
        std.debug.print("  internal_file_attributes:  {d}\n", .{self.internal_file_attributes});
        std.debug.print("  external_file_attributes:  0x{x}\n", .{self.external_file_attributes});
        std.debug.print("  local_file_header_offset:  {d}\n", .{self.local_file_header_relative_offset});
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
const max_comment_len: u32 = std.math.maxInt(u16);

// simple ZIP Layout
// [file entries...]
// [Central Directory...]
// [EOCD]

const EndOfCentralDirectoryRecord = extern struct {
    signature: u32 align(1),
    disk_number: u16 align(1),
    central_directory_disk_number: u16 align(1),
    record_count_disk: u16 align(1),
    record_count_total: u16 align(1),
    central_directory_size: u32 align(1),
    central_directory_offset: u32 align(1),
    comment_len: u16 align(1),

    /// [4.4.1 General notes on fields](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
    /// 4.4.1.4  If one of the fields in the end of central directory
    /// record is too small to hold required data, the field SHOULD be
    /// set to -1 (0xFFFF or 0xFFFFFFFF) and the ZIP64 format record
    /// SHOULD be created.
    ///
    /// 4.4.1.5  The end of central directory record and the Zip64 end
    /// of central directory locator record MUST reside on the same
    /// disk when splitting or spanning an archive.
    pub fn isOverflowSentinels(self: EndOfCentralDirectoryRecord) bool {
        return self.record_count_total == 0xFFFF or
            self.central_directory_size == 0xFFFFFFFF or
            self.central_directory_offset == 0xFFFFFFFF;
    }

    pub fn print(self: EndOfCentralDirectoryRecord) void {
        std.debug.print("EndOfCentralDirectoryRecord\n", .{});
        std.debug.print(".signature 0x{X}\n", .{self.signature});
        std.debug.print(".disk_number {d}\n", .{self.disk_number});
        std.debug.print(".central_directory_disk_number {d}\n", .{self.central_directory_disk_number});
        std.debug.print(".record_count_disk {d}\n", .{self.record_count_disk});
        std.debug.print(".record_count_total {d}\n", .{self.record_count_total});
        std.debug.print(".central_directory_size {d}\n", .{self.central_directory_size});
        std.debug.print(".central_directory_offset {d}\n", .{self.central_directory_offset});
        std.debug.print(".comment_len {d}\n", .{self.comment_len});
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

    pub fn Read(f: *std.fs.File.Reader) !EndOfCentralDirectoryRecord {
        const file_size: u64 = try f.getSize();
        if (file_size < eocd_size) {
            return error.ZipNoEndRecord;
        }

        const max_record_len = eocd_size + max_comment_len;
        var buffer: [max_record_len]u8 = undefined;
        const search_limit = @min(file_size, buffer.len);

        var loaded_len: usize = 0;
        var comment_len: u16 = 0;

        std.debug.print("file_size {}\n", .{file_size});
        std.debug.print("search_limit {}\n", .{search_limit});
        std.debug.print("max_record_len {}\n", .{max_record_len});

        while (comment_len <= max_comment_len) {
            const record_len = @as(usize, comment_len) + eocd_size;
            std.debug.print("record_len: {}\n", .{record_len});
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
                std.debug.print("comment_len {}\n", .{comment_len});
                return parse(record_bytes);
            }

            comment_len += 1;
        }
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
        if (!std.mem.eql(u8, record_bytes[0..4], &eocd_signature_bytes))
            return false;

        const actual_comment_len =
            std.mem.readInt(u16, record_bytes[20..22], .little);

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

pub const ExtraMetadata = struct {
    // ZIP64
    zip64_uncompressed_size: ?u664 = null,
    zip64_compressed_size: ?u664 = null,
    zip64_local_header_offset: ?u664 = null,

    // Extended timestamp (0x5455)

    mod_time_unix: ?u32 = null,
    access_time_unix: ?u32 = null,
    creation_time_unix: ?u32 = null,

    // Info-ZIP Unix (0x7875)
    uid: ?u32 = null,
    gid: ?u32 = null,

    fn parseZip64(self: *ExtraMetadata, data: []const u8) !void {
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
    }

    fn parseExtendedTimestamp(self: *ExtraMetadata, data: []const u8) !void {
        if (data.len < 1)
            return error.InvalidExtraField;

        const flags = data[0];
        var offset: usize = 1;

        if ((flags & 0x01) != 0) {
            if (offset + 4 > data.len)
                return error.InvalidExtraField;

            self.mod_time_unix =
                std.mem.readInt(u32, data[offset..][0..4], .little);
            offset += 4;
        }

        if ((flags & 0x02) != 0) {
            if (offset + 4 > data.len)
                return error.InvalidExtraField;

            self.access_time_unix =
                std.mem.readInt(u32, data[offset..][0..4], .little);
            offset += 4;
        }

        if ((flags & 0x04) != 0) {
            if (offset + 4 > data.len)
                return error.InvalidExtraField;

            self.creation_time_unix =
                std.mem.readInt(u32, data[offset..][0..4], .little);
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

const FileData = struct {
    header: LocalFileHeader,
    offset: u64,

    pub fn parseExtra(extra: []const u8) !ExtraMetadata {
        var meta = ExtraMetadata{};
        var offset: usize = 0;

        while (offset < extra.len) {
            if (offset + 4 > extra.len) {
                return error.ZipExtraInvalid;
            }

            const id = std.mem.readInt(u16, extra[offset..][0..2], .little);
            const size = std.mem.readInt(u16, extra[offset + 2 ..][0..2], .little);

            offset += 4;

            if (offset + size > extra.len) {
                return error.ZipExtraInvalid;
            }

            meta = meta;
            // const data = extra[offset .. offset + size];
            switch (id) {
                // 0x0001 => try meta.parseZip64(data),
                // 0x5455 => try meta.parseExtendedTimestamp(data),
                // 0x7875 => try meta.parseUnixExtra(data),
                else => {},
            }

            offset += size;
        }

        return meta;
    }

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

            const extra_meta = try parseExtra(extra);
            std.debug.print("extra: {}\n", .{extra_meta});
        }

        switch (self.header.compression_method) {
            .store, .deflate => {},
            else => return error.UnsupportedCompressionMethod,
        }

        return filename;
    }

    pub fn extract() !void {}
};

pub const EndOfCentralDirectoryRecord64_Locator = extern struct {};

/// Iterator
const Iterator = struct {
    reader: *std.fs.File.Reader,
    eocdr: EndOfCentralDirectoryRecord,

    cd_index: u64 = 0,
    cd_offset: u64 = 0,

    pub fn init(reader: *std.fs.File.Reader) !Iterator {
        const record = try EndOfCentralDirectoryRecord.Read(reader);

        record.print();

        if (record.isOverflowSentinels()) {
            // Check 20 bytes before EOCD for ZIP64 Locator
            // Signature: 0x07064b50
            // if found:
            // - Read the data locator
            // - Seek to ZIP64 EOCD record
            // - Override values
            // if not found:
            // - Either malformed ZIP
            // - Or legal edge-case where value is exactly max

            // NOTE (dapa):
            // Also Important: Per-File ZIP64 Is Separate
            // Even if archive is NOT ZIP64 at top-level,
            // Individual files may still use ZIP64 extra (0x0001)
            // if file size > 4GB.
            // That is independent of EOCD.
            // So you need two detection layers:
            //
            // Archive-level ZIP64 (EOCD overflow)
            // Per-entry ZIP64 (CDFH size == 0xFFFFFFFF)
            return error.Zip64_NotImplementedYet;
        }

        return Iterator{
            .eocdr = record,
            .reader = reader,
            .cd_offset = record.central_directory_offset,
        };
    }

    pub fn next(self: *Iterator) !?FileData {
        if (self.cd_index == self.eocdr.record_count_total) {
            return null;
        }

        std.debug.print("current_cd_offset: {}\n", .{self.cd_offset});

        try self.reader.seekTo(self.cd_offset);

        const cdfh = self.reader.interface.takeStruct(CentralDirectoryFileHeader, .little) catch |err| switch (err) {
            error.ReadFailed => return self.reader.err.?,
            error.EndOfStream => return error.EndOfStream,
        };

        // cdfh.print();

        const entry_size =
            cdfh_size +
            cdfh.filename_len +
            cdfh.extra_len +
            cdfh.comment_len;

        defer {
            self.cd_index += 1;
            self.cd_offset += entry_size;
        }

        // TODO Access the Local File Header
        try self.reader.seekTo(cdfh.local_file_header_relative_offset);

        const lfh = try self.reader.interface.takeStruct(LocalFileHeader, .little);
        if (lfh.signature != std.mem.readInt(u32, &[_]u8{ 0x50, 0x4B, 3, 4 }, .little)) {
            return error.ZipBadSignature;
        }

        std.debug.print("cd_index {}\n", .{self.cd_index});
        std.debug.print("cd_offset {}\n", .{self.cd_offset});

        return FileData{
            .header = lfh,
            .offset = cdfh.local_file_header_relative_offset,
        };
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
    // const file_size: u64 = try freader.getSize();

    var iter = try Iterator.init(&freader);
    var total_files: usize = 0;
    while (try iter.next()) |fd| {
        var filename_buffer: [128]u8 = undefined;
        const fname = try fd.read(&freader, &filename_buffer);
        std.debug.print("filename: {s}\n", .{fname});
        total_files += 1;
    }

    std.debug.print("total_files: {d}\n", .{total_files});

    // var comment_buffer: [256]u8 = undefined;
    // const out = try EndOfCentralDirectoryRecord.readComment(
    //     file_reader,
    //     try file_reader.getSize(),
    //     eocdr.getOffset(),
    //     eocdr.comment_len,
    //     &comment_buffer,
    // );

    // std.debug.print("comment: {s}\n", .{out});

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
