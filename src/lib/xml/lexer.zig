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
        input: []const u8,
    ) !Parser {
        return .{
            .input = input,
            .allocator = allocator,
            .element_stack = try std.ArrayList([]const u8).initCapacity(allocator, input.len),
        };
    }

    pub fn deinit(self: *Parser) void {
        self.element_stack.deinit(self.allocator);
    }

    pub fn next(self: *Parser) !?Event {
        switch (self.state) {
            .Start => {
                self.state = .Content;
                return Event.StartDocument;
            },
            .Epilog => {
                self.skipS();
                if (self.peekByte() == null) {
                    self.state = .End;
                    return Event.EndDocument;
                }
            },
            .Content => {
                self.skipS();
                const byte = self.peekByte() orelse {
                    if (self.element_stack.items.len != 0) return XMLError.UnexpectedEOF;
                    self.state = .End;
                    return Event.EndDocument;
                };
                if (byte == '<') {
                    return try self.parseMarkup();
                } else {
                    return try self.parseText();
                }
            },
            .End => return null,
        }

        return XMLError.UnexpectedToken;
    }

    fn parseMisc(self: *Parser) !Event {
        const next_byte = self.reader.peekByte() catch return error.UnexpectedEOF;
        switch (next_byte) {
            '!' => {
                // Could be comment, CDATA or doctype
                _ = try self.reader.takeByte(); // consume '!'
                const byte = try self.reader.peekByte();
                if (byte == '-') {
                    return try self.parseComment();
                }

                if (byte == '[') {
                    const cd_start = try self.reader.take(6);
                    if (std.mem.eql(u8, cd_start, "[CDATA")) {
                        return try self.parseProcessingInstruction();
                    }
                }

                return error.UnexpectedToken;
            },
            '?' => {
                _ = try self.reader.takeByte(); // consume '?'
                return try self.parseProcessingInstruction();
            },
            else => {
                return XMLError.UnexpectedToken;
            },
        }
    }

    fn parseProcessingInstruction(self: *Parser) !Event {
        const target_start = self.reader.seek;

        while (true) {
            const c = self.reader.takeByte() catch return XMLError.UnexpectedEOF;
            if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != ':') break;
            _ = try self.reader.takeByte();
        }

        const target = self.input[target_start..self.reader.seek];
        if (target.len == 0) return XMLError.UnexpectedToken;

        self.skipS();

        // Parse data until '?>'
        const data_start = self.reader.seek;
        while (true) {
            const c = self.reader.takeByte() catch return error.UnexpectedEOF;
            if (c == '?') {
                const next_byte = self.reader.takeByte() catch return error.UnexpectedEOF;
                if (next_byte == '>') break;
            }
        }

        const data = self.input[data_start .. self.reader.seek - 2]; // Exclude '?>'
        return .{
            .ProcessingInstruction = .{
                .target = target,
                .data = data,
            },
        };
    }

    fn parseComment(self: *Parser) !Event {
        // expect '--'
        const dash1 = self.reader.takeByte() catch return error.UnexpectedToken;
        const dash2 = self.reader.takeByte() catch return error.UnexpectedToken;

        if (dash1 != '-' or dash2 != '-') return error.UnexpectedToken;
        const start = self.reader.seek;

        while (true) {
            const c = self.reader.takeByte() catch return error.UnexpectedEOF;
            if (c == '-') {

                // Check for '-->'
                const next1 = self.reader.peekByte() catch return XMLError.UnexpectedEOF;
                if (next1 == '-') {
                    _ = try self.reader.takeByte(); // consume second '-'
                    const next2 = self.reader.takeByte() catch return XMLError.UnexpectedEOF;
                    if (next2 != '>') return error.UnexpectedToken;
                    break;
                }
            }
        }

        const comment_text = self.input[start .. self.reader.seek - 3]; // Exclude '-->'
        return .{ .Comment = comment_text };
    }

    fn parseMarkup(self: *Parser) !Event {
        _ = self.takeByte(); // consume '<'
        const byte = self.peekByte() orelse return XMLError.UnexpectedEOF;
        switch (byte) {
            '/' => return try self.parseEndTag(),
            else => return try self.parseStartTag(),
        }
    }

    fn parseStartTag(self: *Parser) !Event {
        const name = try self.parseName();
        try self.element_stack.append(self.allocator, name);
        self.skipS();
        const byte = self.takeByte() orelse return XMLError.UnexpectedToken;
        if (byte != '>') return XMLError.UnexpectedToken;
        return .{ .STag = name };
    }

    fn parseEndTag(self: *Parser) !Event {
        _ = self.takeByte(); // consume '/'
        const name = try self.parseName();
        const top = self.element_stack.pop() orelse return XMLError.MismatchedTag;

        if (!std.mem.eql(u8, top, name)) {
            return XMLError.MismatchedTag;
        }

        const byte = self.takeByte() orelse return XMLError.UnexpectedEOF;
        if (byte != '>') return XMLError.UnexpectedToken;

        if (self.element_stack.items.len == 0) {
            self.state = .Epilog;
        }
        return .{ .ETag = name };
    }

    fn parseText(self: *Parser) !Event {
        const start = self.pos;
        while (self.peekByte()) |c| {
            if (c == '<') break;
            _ = self.takeByte();
        }

        const slice = self.input[start..self.pos];
        return .{ .Characters = slice };
    }

    fn parseName(self: *Parser) ![]const u8 {
        const start = self.pos;
        while (self.peekByte()) |c| {
            if (!std.ascii.isAlphanumeric(c)) break;
            _ = self.takeByte();
        }

        if (self.pos == start) {
            return XMLError.UnexpectedToken;
        }
        return self.input[start..self.pos];
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
