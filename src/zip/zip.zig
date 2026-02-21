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

const GeneralPurposeFlags = packed struct {
    raw: u16,

    pub fn init(raw: u16) GeneralPurposeFlags {
        return .{ .raw = raw };
    }

    pub fn has(self: GeneralPurposeFlags, mask: u16) bool {
        return (self.raw & mask) != 0;
    }

    pub fn unknown(
        self: GeneralPurposeFlags,
    ) u16 {
        return self.raw & ~GPFlags.known_mask;
    }
};

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
const GPFlags = struct {
    pub const encrypted: u16 = 1 << 0;
    pub const compression_option1: u16 = 1 << 1;
    pub const compression_option2: u16 = 1 << 2;
    pub const data_descriptor: u16 = 1 << 3;
    pub const enhanced_deflation: u16 = 1 << 4;
    pub const compressed_patched: u16 = 1 << 5;
    pub const strong_encryption: u16 = 1 << 6;
    pub const language_encoding_utf8: u16 = 1 << 11;
    pub const mask_header_values: u16 = 1 << 13;

    pub const known_mask: u16 =
        encrypted |
        compression_option1 |
        compression_option2 |
        data_descriptor |
        enhanced_deflation |
        compressed_patched |
        strong_encryption |
        language_encoding_utf8 |
        mask_header_values;
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
pub const FileHeader = extern struct {
    signature: u32 align(1),
    version_made_by: u16 align(1),
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
    file_comment_len: u16 align(1),
    disk_number_start: u16 align(1),
    internal_file_attributes: u16 align(1),
    external_file_attributes: u32 align(1),
    local_file_header_relative_offset: u32 align(1),
    // ...
    // filename (variable size)
    // extra field (variable size)
    // file comment (variable size)
};

const file_header_signature: u32 = 0x50_4B_01_02;
const file_header_size: u32 = 46;

// Digital Signature
pub const DigitalSignature = struct {
    signature: u32, // 0x05_05_4b_50 (little)
    size_of_data: u16,
    // ...
    // signature_data (variable size)
};

test "central directory file header structure" {
    try std.testing.expectEqual(
        @sizeOf(FileHeader),
        file_header_size,
    );

    try std.testing.expectEqual(
        @bitSizeOf(FileHeader),
        file_header_size * 8,
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

const EndOfCentralDirectoryRecord = extern struct {
    signature: u32 align(1),
    disk_number: u16 align(1),
    central_directory_disk_number: u16 align(1),
    record_count_disk: u16 align(1),
    record_count_total: u16 align(1),
    central_directory_size: u32 align(1),
    central_directory_offset: u32 align(1),
    comment_len: u16 align(1),

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

    pub fn FindFile(f: *std.fs.File.Reader) !EndOfCentralDirectoryRecord {
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
        std.debug.print("max_comment_len {}\n", .{max_comment_len});
        std.debug.print("max_record_len {}\n", .{max_record_len});
        std.debug.print("buffer.len {}\n", .{buffer.len});
        std.debug.print("search_limit {}\n", .{search_limit});

        std.debug.print("=== while ===\n", .{});

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

test "eocd_structure" {
    const with_comment_zip = "sample/with_comment.zip";
    var file = try std.fs.cwd().openFile(with_comment_zip, .{ .mode = .read_only });
    defer file.close();

    var buf: [1024]u8 = undefined;
    var freader = file.reader(&buf);

    const eocd_record = try EndOfCentralDirectoryRecord.FindFile(&freader);
    eocd_record.print();
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
        try reader.seekTo(entry.header_zip_offset + @sizeOf(FileHeader));
        try reader.interface.readSliceAll(filename);
        std.debug.print("filename: {s}\n", .{filename});
        // std.debug.print("size of CentralDirectoryFileHeader: {d}\n", .{@sizeOf(CentralDirectoryFileHeader)});
        count += 1;
    }
}
