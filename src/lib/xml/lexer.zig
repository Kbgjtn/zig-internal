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
    xml_decl,
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
    /// End Of File
    eof,
};

pub const XMLError = error{
    UnexpectedEOF,
    UnexpectedToken,
    MismatchedTag,
    MultipleRootElements,
};

pub const Event = union(enum) {
    XMLDecl: XMLDecl,
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
    ProcessingInstruction: struct {
        target: []const u8,
        data: []const u8,
    },
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

const Attribute = struct {
    name: []const u8,
    value: []const u8,
};
const XMLDecl = struct {
    signature: []const u8,
    // version info
    version: []const u8,
    encoding: []const u8,
    // standalone document declaration
    sdd: []const u8,

    pub fn print(self: XMLDecl) void {
        std.debug.print("XML Declaration\n", .{});
        std.debug.print("-----------------------------\n", .{});
        std.debug.print("   signature \t{s}\n", .{self.signature});
        std.debug.print("   version \t{s}\n", .{self.version});
        std.debug.print("   encoding \t{s}\n", .{self.encoding});
        std.debug.print("   standalone \t{s}\n", .{self.sdd});
    }
};

/// Stage 1: minimal scratch engine structure XML Document parser
pub const Parser = struct {
    const XMLDeclStart = "<?xml";

    allocator: std.mem.Allocator,
    input: []const u8,
    reader: std.Io.Reader,
    state: state = .Start,
    element_stack: std.ArrayList([]const u8),
    attribute_list: std.ArrayList(Attribute),

    pub fn init(allocator: std.mem.Allocator, input: []const u8) !Parser {
        for (0..input.len) |i| {
            std.debug.print("i-{d}:{c}\n", .{ i, input[i] });
        }

        return .{
            .input = input,
            .reader = std.Io.Reader.fixed(input),
            .allocator = allocator,
            .element_stack = try std.ArrayList([]const u8).initCapacity(allocator, input.len),
            .attribute_list = try std.ArrayList(Attribute).initCapacity(allocator, 0),
        };
    }

    pub fn deinit(self: *Parser) void {
        self.element_stack.deinit(self.allocator);
        self.attribute_list.deinit(self.allocator);
    }

    pub fn next(self: *Parser) !?Event {
        self.skipS();
        switch (self.state) {
            .Epilog => {
                _ = self.reader.peekByte() catch {
                    self.state = .End;
                    return Event.EndDocument;
                };
                return try self.parseMisc();
            },
            .Start => {
                // Check Prolog
                // XMLDecl? Misc* (doctypedecl Misc*)?
                const xml_decl_start = try self.reader.peek(5);
                if (!std.mem.eql(u8, xml_decl_start, XMLDeclStart)) {
                    self.state = .Content;
                } else {
                    self.state = .Prolog;
                }

                return Event.StartDocument;
            },
            .Prolog => {
                // Prolog
                // [22] prolog       ::=    XMLDecl? Misc* (doctypedecl Misc*)?
                // [23] XMLDecl      ::=    '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
                // [24] VersionInfo  ::=    S 'version' Eq ("'" VersionNum "'" | '"' VersionNum '"')
                // [25] Eq           ::=    S? '=' S?
                // [26] VersionNum   ::=    '1.' [0-9]+
                // [27] Misc         ::=    Comment | PI | S

                const signature = try self.reader.take(5); // consume xml_decl signature
                var xml_decl: XMLDecl = .{
                    .signature = signature,
                    .encoding = "UTF-8",
                    .version = "1.0",
                    .sdd = "no",
                };

                while (true) {
                    self.skipS();

                    const byte = try self.reader.peekByte();
                    if (byte == '?') {
                        _ = try self.reader.takeByte(); // consume '?'
                        _ = try self.reader.takeByte(); // consume '>'
                        break;
                    }

                    const attr = try self.parseAttribute();
                    if (std.mem.eql(u8, attr.name, "version")) {
                        xml_decl.version = attr.value;
                    } else if (std.mem.eql(u8, attr.name, "encoding")) {
                        xml_decl.encoding = attr.value;
                    } else if (std.mem.eql(u8, attr.name, "standalone")) {
                        xml_decl.sdd = attr.value;
                    }
                }

                self.state = .Content;
                return .{ .XMLDecl = xml_decl };
            },
            .Content => {
                self.skipS();
                const byte = self.reader.peekByte() catch {
                    if (self.element_stack.items.len != 0) return XMLError.UnexpectedEOF;

                    // Stack is empty, so we're at end of root element
                    self.state = .Epilog;
                    return Event.EndDocument;
                };

                // std.debug.print("content.state {any}\n", .{self.state});
                // std.debug.print("content byte {c}\n", .{byte});

                if (byte == '<') {
                    return try self.parseMarkup();
                }

                return try self.parseText();
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
        _ = try self.reader.takeByte(); // consume '<'
        const byte = self.reader.peekByte() catch return XMLError.UnexpectedEOF;
        switch (byte) {
            '/' => return try self.parseEndTag(),
            '!' => return try self.parseMisc(),
            else => return try self.parseStartTag(),
        }
    }

    fn parseStartTag(self: *Parser) !Event {
        const name = try self.parseName();
        try self.element_stack.append(self.allocator, name);

        self.attribute_list.clearAndFree(self.allocator);
        self.skipS();

        // Parse attributes
        while (true) {
            const byte = self.reader.peekByte() catch return XMLError.UnexpectedEOF;
            if (byte == '>') {
                _ = try self.reader.takeByte(); // consume '>'
                return .{ .STag = name };
            }

            if (byte == '/') {
                // self-closing tag
                _ = try self.reader.takeByte(); // consume '/'
                const closing = self.reader.takeByte() catch return XMLError.UnexpectedEOF;
                if (closing != '>') return XMLError.UnexpectedToken;

                // pop the element since it's self-closing
                _ = self.element_stack.pop();
                return .{ .STag = name };
            }

            const attr = try self.parseAttribute();
            try self.attribute_list.append(self.allocator, attr);
            self.skipS();
        }
    }

    fn parseAttribute(self: *Parser) !Attribute {
        const name_start = self.reader.seek;
        std.debug.print("name_start: {}\n", .{name_start});
        while (self.reader.peekByte() catch null) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != ':') break;
            _ = try self.reader.takeByte();
        }

        const name = self.input[name_start..self.reader.seek];
        if (name.len == 0) return XMLError.UnexpectedToken;
        std.debug.print("attribute.name: {s}\n", .{name});

        self.skipS();

        // Expect '='
        const eq = try self.reader.takeByte();
        if (eq != '=') return XMLError.UnexpectedToken;

        self.skipS();

        // Parse attribute value (quoted)

        const quote = self.reader.takeByte() catch return XMLError.UnexpectedToken;
        if (quote != '"' and quote != '\'') return XMLError.UnexpectedToken;

        const value_start = self.reader.seek;
        while (true) {
            const c = self.reader.takeByte() catch return XMLError.UnexpectedEOF;
            if (c == quote) break;
        }

        const value = self.input[value_start .. self.reader.seek - 1];
        std.debug.print("attribute.value: {s}\n", .{value});
        return .{
            .name = name,
            .value = value,
        };
    }

    fn parseEndTag(self: *Parser) !Event {
        _ = try self.reader.takeByte(); // consume '/' or '?'
        // std.debug.print("prefix delim {c}\n", .{prefix_delim});

        const name = try self.parseName();
        const top = self.element_stack.pop() orelse return XMLError.MismatchedTag;

        if (!std.mem.eql(u8, top, name)) {
            return XMLError.MismatchedTag;
        }

        const byte = self.reader.takeByte() catch return XMLError.UnexpectedEOF;
        if (byte != '>') return XMLError.UnexpectedToken;

        if (self.element_stack.items.len == 0) {
            self.state = .Epilog;
        }
        return .{ .ETag = name };
    }

    fn parseText(self: *Parser) !Event {
        const start = self.reader.seek;
        while (self.reader.peekByte() catch null) |c| {
            if (c == '<') break;
            _ = try self.reader.takeByte();
        }

        const slice = self.input[start..self.reader.seek];
        return .{ .Characters = slice };
    }

    fn parseName(self: *Parser) ![]const u8 {
        const start = self.reader.seek;
        while (self.reader.peekByte() catch null) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') break;
            _ = try self.reader.takeByte();
        }

        // std.debug.print("reader.seek {}\n", .{self.reader.seek});
        // std.debug.print("self.pos {}\n", .{self.pos});

        if (self.reader.seek == start) {
            return XMLError.UnexpectedToken;
        }
        return self.input[start..self.reader.seek];
    }

    /// **White Space**
    /// S (white space) consists of one or more space (#x20) characters, carriage returns, line feeds, or tabs.
    fn skipS(self: *Parser) void {
        while (true) {
            const c = self.reader.peekByte() catch break;
            if (!std.ascii.isWhitespace(c)) break;
            _ = self.reader.takeByte() catch break;
        }
    }
};
