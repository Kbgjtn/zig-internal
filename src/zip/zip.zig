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
const GeneralPurposeFlags = packed struct(u16) {
    encrypted: bool,
    _: u15,
};

/// The Compression Method:
/// - Store (No Compression)
/// - Shrink (LZW)
/// - Reduce (levels 1-4; LZ77 + probabilistic)
/// - Implode
/// - Deflate
/// - Deflate64
/// - bzip2
/// - LZMA
/// - Zstandard
/// - WavPack
/// - etc.
/// The most commonly used compression method is `DEFLATE`, which is described in IETF RFC 1951.
pub const CompressionMethod = enum(u16) {
    store = 0,
    deflate = 8,
    _,
};

// File Headers

/// The Local File Header has specific field structure consisting
/// of multi-byte values. All the values are stored in little-endian byte order
/// where the field lenght counts the length in bytes. All the structures ZIP file
/// use 4-byte signatures for each file entry. So basically, need to store the metadata
/// in a way that produces a byte-exact layout which matches the binary format.
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

test "local file header structure" {
    try std.testing.expect(@sizeOf(LocalFileHeader) == 30);
}

/// 4-bytes (0x04034b50 as little-endian order)
const local_file_header_signature: u32 = 0x50_4B_03_04;
const local_file_header_size: u8 = 30;

const data_descriptor_signature: u32 = 0x50_4B_07_08;

/// Central directory file header (CDFH)
const cdfh_signature: u32 = 0x50_4B_01_02;
/// End of central directory record (EOCD)
const eocd_signature: u32 = 0x50_4B_05_06;

const Method = enum(u8) {
    Store = 0x0,
    Deflate = 0x8,
};

const EOCD = packed struct {
    signature: u32,
    disk: u16,
    cd_disk: u16,
    disk_entries: u16,
    total_entries: u16,
    cd_size: u64,
    cd_offset: u32,
    comment_len: u16,
};

pub const CentralDirectoryFileHeader = extern struct {
    signature: [4]u8 align(1),
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
    comment_len: u16 align(1),
    disk_number: u16 align(1),
    internal_file_attributes: u16 align(1),
    external_file_attributes: u32 align(1),
    local_file_header_offset: u32 align(1),
};

test {
    const myepub = "sample/accessible_epub_3.epub";
    var file = try std.fs.cwd().openFile(myepub, .{ .mode = .read_only });
    defer file.close();

    var buffer: [1024]u8 = undefined;
    var reader = file.reader(&buffer);

    var zip_iter: std.zip.Iterator = try .init(&reader);

    var filename_buf: [128]u8 = undefined;

    while (try zip_iter.next()) |entry| {
        std.debug.print("entry: {}\n", .{entry});
        const filename = filename_buf[0..entry.filename_len];
        try reader.seekTo(entry.header_zip_offset + @sizeOf(CentralDirectoryFileHeader));
        try reader.interface.readSliceAll(filename);
        std.debug.print("filename: {s}\n", .{filename});
        std.debug.print("size of CentralDirectoryFileHeader: {d}\n", .{@sizeOf(CentralDirectoryFileHeader)});
    }
}
