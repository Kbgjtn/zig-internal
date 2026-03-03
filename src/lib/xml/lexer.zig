const std = @import("std");

// Byte Order Marker (BOM)

// Byte Stream Layer
// responsibillities:
// - Handle UTF-8 (required)
// - Optionally detect UTF-16 via BOM
// - Normalize line endings to `\n`

// Logical Structures
// Each XML Document contains one or more elements, the boundaries of
// which are either delimited by `start-tags` and `end-tags`, or for `empty`
// elements, by an `empty-element-tag`. Each element has a type, identified
// by name, sometimes called its "generic identifier" (GI), and may have a
// set of attribute specifications. Each attribute specification has a name
// and a value.

pub const Token = enum {
    /// <
    lt,
    /// >
    gt,
    /// /
    slash,
    /// =
    equals,
    /// element or attribute names
    name,
    /// the "value"
    string_literal,
    text,
    comment,
    cdata,
    pi,
    doctype,
    entity_ref,
    eof,
};

pub const XMLError = error{
    UnexpectedEOF,
    UnexpectedToken,
    MismatchedTag,
    MultipleRootElements,
};

pub const Event = union(enum) {
    StartDocument,
    EndDocument,
    /// Start of Element
    STag: []const u8,
    /// End of Element
    ETag: []const u8,
    Characters: []const u8,
    Comment: []const u8,
    // Processing Instruction(s)
    PI: []const u8,
};

// An element:
// element ::= EmptyElementTag
//           | STag content ETag
//
// Content:
// content ::= (element | CharData | Reference | CDSect | PI | Comment)*

const state = enum {
    Start, // before first element
    Prolog,
    Content, // inside root
    Epilog, // after root closed
    End,
};

/// Stage 1: minimal scratch engine structure XML Document parser
pub const Parser = struct {
    allocator: std.mem.Allocator,
    input: []const u8,

    state: state = .Start,
    pos: usize = 0,
    element_stack: std.ArrayList([]const u8),

    pub fn init(
        allocator: std.mem.Allocator,
        v: []const u8,
    ) Parser {
        return .{
            .input = v,
            .allocator = allocator,
            .element_stack = std.ArrayList([]const u8).initCapacity(allocator, v.len),
        };
    }

    pub fn deinit(self: *Parser) void {
        self.element_stack.deinit();
    }

    fn peekByte(self: *Parser) ?u8 {
        if (self.pos >= self.input.len) return null;
        return self.input[self.pos];
    }

    fn takeByte(self: *Parser) ?u8 {
        if (self.pos >= self.input.len) return null;
        const byte = self.input[self.pos];
        self.pos += 1;
        return byte;
    }

    /// **White Space**
    /// S (white space) consists of one or more space (#x20) characters, carriage returns, line feeds, or tabs.
    fn skipS(self: *Parser) void {
        while (self.peekByte()) |c| {
            if (!std.ascii.isWhitespace(c)) break;
            _ = self.takeByte();
        }
    }
};
