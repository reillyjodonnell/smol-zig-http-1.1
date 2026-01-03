const std = @import("std");
const Allocator = std.mem.Allocator;

/// HTTP Methods as defined in HTTP/1.1 (RFC 7231)
pub const Method = enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,

    pub fn fromString(str: []const u8) ?Method {
        const map = std.StaticStringMap(Method).initComptime(.{
            .{ "GET", .GET },
            .{ "HEAD", .HEAD },
            .{ "POST", .POST },
            .{ "PUT", .PUT },
            .{ "DELETE", .DELETE },
            .{ "CONNECT", .CONNECT },
            .{ "OPTIONS", .OPTIONS },
            .{ "TRACE", .TRACE },
            .{ "PATCH", .PATCH },
        });
        return map.get(str);
    }

    pub fn toString(self: Method) []const u8 {
        return @tagName(self);
    }
};

/// HTTP Version
pub const Version = enum {
    HTTP_1_0,
    HTTP_1_1,

    pub fn fromString(str: []const u8) ?Version {
        if (std.mem.eql(u8, str, "HTTP/1.0")) return .HTTP_1_0;
        if (std.mem.eql(u8, str, "HTTP/1.1")) return .HTTP_1_1;
        return null;
    }

    pub fn toString(self: Version) []const u8 {
        return switch (self) {
            .HTTP_1_0 => "HTTP/1.0",
            .HTTP_1_1 => "HTTP/1.1",
        };
    }
};

/// Common HTTP Status Codes
pub const StatusCode = enum(u16) {
    // 1xx Informational
    Continue = 100,
    SwitchingProtocols = 101,

    // 2xx Success
    OK = 200,
    Created = 201,
    Accepted = 202,
    NoContent = 204,
    ResetContent = 205,
    PartialContent = 206,

    // 3xx Redirection
    MultipleChoices = 300,
    MovedPermanently = 301,
    Found = 302,
    SeeOther = 303,
    NotModified = 304,
    TemporaryRedirect = 307,
    PermanentRedirect = 308,

    // 4xx Client Errors
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    NotAcceptable = 406,
    RequestTimeout = 408,
    Conflict = 409,
    Gone = 410,
    LengthRequired = 411,
    PreconditionFailed = 412,
    PayloadTooLarge = 413,
    URITooLong = 414,
    UnsupportedMediaType = 415,
    RangeNotSatisfiable = 416,
    ExpectationFailed = 417,
    ImATeapot = 418,
    UnprocessableEntity = 422,
    TooManyRequests = 429,

    // 5xx Server Errors
    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
    HTTPVersionNotSupported = 505,

    pub fn reasonPhrase(self: StatusCode) []const u8 {
        return switch (self) {
            .Continue => "Continue",
            .SwitchingProtocols => "Switching Protocols",
            .OK => "OK",
            .Created => "Created",
            .Accepted => "Accepted",
            .NoContent => "No Content",
            .ResetContent => "Reset Content",
            .PartialContent => "Partial Content",
            .MultipleChoices => "Multiple Choices",
            .MovedPermanently => "Moved Permanently",
            .Found => "Found",
            .SeeOther => "See Other",
            .NotModified => "Not Modified",
            .TemporaryRedirect => "Temporary Redirect",
            .PermanentRedirect => "Permanent Redirect",
            .BadRequest => "Bad Request",
            .Unauthorized => "Unauthorized",
            .Forbidden => "Forbidden",
            .NotFound => "Not Found",
            .MethodNotAllowed => "Method Not Allowed",
            .NotAcceptable => "Not Acceptable",
            .RequestTimeout => "Request Timeout",
            .Conflict => "Conflict",
            .Gone => "Gone",
            .LengthRequired => "Length Required",
            .PreconditionFailed => "Precondition Failed",
            .PayloadTooLarge => "Payload Too Large",
            .URITooLong => "URI Too Long",
            .UnsupportedMediaType => "Unsupported Media Type",
            .RangeNotSatisfiable => "Range Not Satisfiable",
            .ExpectationFailed => "Expectation Failed",
            .ImATeapot => "I'm a teapot",
            .UnprocessableEntity => "Unprocessable Entity",
            .TooManyRequests => "Too Many Requests",
            .InternalServerError => "Internal Server Error",
            .NotImplemented => "Not Implemented",
            .BadGateway => "Bad Gateway",
            .ServiceUnavailable => "Service Unavailable",
            .GatewayTimeout => "Gateway Timeout",
            .HTTPVersionNotSupported => "HTTP Version Not Supported",
        };
    }
};

/// HTTP Header - a key-value pair
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Query parameter from URL
pub const QueryParam = struct {
    key: []const u8,
    value: []const u8,
};

/// Parsed URI components
pub const Uri = struct {
    raw: []const u8,
    path: []const u8,
    query: ?[]const u8,
    fragment: ?[]const u8,
};

/// HTTP Request structure
pub const Request = struct {
    method: Method,
    uri: Uri,
    version: Version,
    headers: []Header,
    body: ?[]const u8,

    // Convenience accessors for common headers
    pub fn getHeader(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }

    pub fn getContentLength(self: *const Request) ?usize {
        const value = self.getHeader("Content-Length") orelse return null;
        return std.fmt.parseInt(usize, value, 10) catch null;
    }

    pub fn getContentType(self: *const Request) ?[]const u8 {
        return self.getHeader("Content-Type");
    }

    pub fn getHost(self: *const Request) ?[]const u8 {
        return self.getHeader("Host");
    }

    pub fn getUserAgent(self: *const Request) ?[]const u8 {
        return self.getHeader("User-Agent");
    }

    pub fn getConnection(self: *const Request) ?[]const u8 {
        return self.getHeader("Connection");
    }

    pub fn isKeepAlive(self: *const Request) bool {
        const conn = self.getConnection() orelse {
            // HTTP/1.1 defaults to keep-alive
            return self.version == .HTTP_1_1;
        };
        return std.ascii.eqlIgnoreCase(conn, "keep-alive");
    }
};

/// HTTP Response structure
pub const Response = struct {
    version: Version,
    status: StatusCode,
    reason: []const u8,
    headers: []Header,
    body: ?[]const u8,

    pub fn getHeader(self: *const Response, name: []const u8) ?[]const u8 {
        for (self.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }

    pub fn getContentLength(self: *const Response) ?usize {
        const value = self.getHeader("Content-Length") orelse return null;
        return std.fmt.parseInt(usize, value, 10) catch null;
    }
};

/// Parser errors
pub const ParseError = error{
    InvalidMethod,
    InvalidVersion,
    InvalidStatusCode,
    InvalidHeader,
    InvalidUri,
    InvalidRequestLine,
    InvalidStatusLine,
    IncompleteRequest,
    IncompleteResponse,
    HeaderTooLong,
    TooManyHeaders,
    InvalidContentLength,
    BodyTooLarge,
    OutOfMemory,
};

/// Maximum limits for safety
pub const Limits = struct {
    max_header_size: usize = 8192,
    max_headers: usize = 100,
    max_uri_length: usize = 8192,
    max_body_size: usize = 10 * 1024 * 1024, // 10MB default
};

/// HTTP Parser
pub const Parser = struct {
    allocator: Allocator,
    limits: Limits,

    pub fn init(allocator: Allocator) Parser {
        return .{
            .allocator = allocator,
            .limits = .{},
        };
    }

    pub fn initWithLimits(allocator: Allocator, limits: Limits) Parser {
        return .{
            .allocator = allocator,
            .limits = limits,
        };
    }

    /// Parse an HTTP request from raw bytes
    /// Returns the parsed request and the number of bytes consumed
    pub fn parseRequest(self: *const Parser, data: []const u8) ParseError!struct { request: Request, bytes_consumed: usize } {
        var pos: usize = 0;

        // Parse request line: METHOD SP URI SP VERSION CRLF
        const request_line_end = findCRLF(data[pos..]) orelse return ParseError.IncompleteRequest;
        const request_line = data[pos .. pos + request_line_end];

        const parsed_request_line = try parseRequestLine(request_line, self.limits.max_uri_length);
        pos += request_line_end + 2; // +2 for CRLF

        // Parse headers
        var headers: std.ArrayListUnmanaged(Header) = .empty;
        errdefer headers.deinit(self.allocator);

        while (pos < data.len) {
            // Check for end of headers (empty line)
            if (data.len >= pos + 2 and data[pos] == '\r' and data[pos + 1] == '\n') {
                pos += 2;
                break;
            }

            const header_end = findCRLF(data[pos..]) orelse return ParseError.IncompleteRequest;

            if (header_end > self.limits.max_header_size) {
                return ParseError.HeaderTooLong;
            }

            const header_line = data[pos .. pos + header_end];
            const header = try parseHeaderLine(header_line);

            if (headers.items.len >= self.limits.max_headers) {
                return ParseError.TooManyHeaders;
            }

            headers.append(self.allocator, header) catch return ParseError.OutOfMemory;
            pos += header_end + 2;
        }

        // Parse body if Content-Length is present
        var body: ?[]const u8 = null;
        const headers_slice = headers.toOwnedSlice(self.allocator) catch return ParseError.OutOfMemory;

        // Look for Content-Length in parsed headers
        for (headers_slice) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "Content-Length")) {
                const content_length = std.fmt.parseInt(usize, header.value, 10) catch return ParseError.InvalidContentLength;

                if (content_length > self.limits.max_body_size) {
                    return ParseError.BodyTooLarge;
                }

                if (pos + content_length > data.len) {
                    return ParseError.IncompleteRequest;
                }

                body = data[pos .. pos + content_length];
                pos += content_length;
                break;
            }
        }

        return .{
            .request = .{
                .method = parsed_request_line.method,
                .uri = parsed_request_line.uri,
                .version = parsed_request_line.version,
                .headers = headers_slice,
                .body = body,
            },
            .bytes_consumed = pos,
        };
    }

    /// Parse an HTTP response from raw bytes
    pub fn parseResponse(self: *const Parser, data: []const u8) ParseError!struct { response: Response, bytes_consumed: usize } {
        var pos: usize = 0;

        // Parse status line: VERSION SP STATUS SP REASON CRLF
        const status_line_end = findCRLF(data[pos..]) orelse return ParseError.IncompleteResponse;
        const status_line = data[pos .. pos + status_line_end];

        const parsed_status_line = try parseStatusLine(status_line);
        pos += status_line_end + 2;

        // Parse headers
        var headers: std.ArrayListUnmanaged(Header) = .empty;
        errdefer headers.deinit(self.allocator);

        while (pos < data.len) {
            if (data.len >= pos + 2 and data[pos] == '\r' and data[pos + 1] == '\n') {
                pos += 2;
                break;
            }

            const header_end = findCRLF(data[pos..]) orelse return ParseError.IncompleteResponse;

            if (header_end > self.limits.max_header_size) {
                return ParseError.HeaderTooLong;
            }

            const header_line = data[pos .. pos + header_end];
            const header = try parseHeaderLine(header_line);

            if (headers.items.len >= self.limits.max_headers) {
                return ParseError.TooManyHeaders;
            }

            headers.append(self.allocator, header) catch return ParseError.OutOfMemory;
            pos += header_end + 2;
        }

        var body: ?[]const u8 = null;
        const headers_slice = headers.toOwnedSlice(self.allocator) catch return ParseError.OutOfMemory;

        for (headers_slice) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "Content-Length")) {
                const content_length = std.fmt.parseInt(usize, header.value, 10) catch return ParseError.InvalidContentLength;

                if (content_length > self.limits.max_body_size) {
                    return ParseError.BodyTooLarge;
                }

                if (pos + content_length > data.len) {
                    return ParseError.IncompleteResponse;
                }

                body = data[pos .. pos + content_length];
                pos += content_length;
                break;
            }
        }

        return .{
            .response = .{
                .version = parsed_status_line.version,
                .status = parsed_status_line.status,
                .reason = parsed_status_line.reason,
                .headers = headers_slice,
                .body = body,
            },
            .bytes_consumed = pos,
        };
    }

    /// Free resources allocated during parsing
    pub fn freeRequest(self: *const Parser, request: *Request) void {
        self.allocator.free(request.headers);
    }

    pub fn freeResponse(self: *const Parser, response: *Response) void {
        self.allocator.free(response.headers);
    }
};

// ============================================================================
// Internal parsing helpers
// ============================================================================

fn findCRLF(data: []const u8) ?usize {
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 1) {
        if (data[i] == '\r' and data[i + 1] == '\n') {
            return i;
        }
    }
    return null;
}

fn parseRequestLine(line: []const u8, max_uri_length: usize) ParseError!struct { method: Method, uri: Uri, version: Version } {
    // METHOD SP URI SP VERSION
    var parts = std.mem.splitScalar(u8, line, ' ');

    const method_str = parts.next() orelse return ParseError.InvalidRequestLine;
    const uri_str = parts.next() orelse return ParseError.InvalidRequestLine;
    const version_str = parts.next() orelse return ParseError.InvalidRequestLine;

    // Ensure no extra parts (URI can have spaces if encoded, but raw spaces are invalid)
    if (parts.next() != null) {
        // Could be a URI with spaces - rejoin everything between method and version
        // For simplicity, we'll reject this as invalid per HTTP/1.1 spec
        return ParseError.InvalidRequestLine;
    }

    const method = Method.fromString(method_str) orelse return ParseError.InvalidMethod;

    if (uri_str.len > max_uri_length) {
        return ParseError.InvalidUri;
    }

    const uri = parseUri(uri_str);
    const version = Version.fromString(version_str) orelse return ParseError.InvalidVersion;

    return .{
        .method = method,
        .uri = uri,
        .version = version,
    };
}

fn parseStatusLine(line: []const u8) ParseError!struct { version: Version, status: StatusCode, reason: []const u8 } {
    // VERSION SP STATUS SP REASON
    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse return ParseError.InvalidStatusLine;
    const version_str = line[0..first_space];

    const rest = line[first_space + 1 ..];
    const second_space = std.mem.indexOfScalar(u8, rest, ' ') orelse return ParseError.InvalidStatusLine;
    const status_str = rest[0..second_space];
    const reason = rest[second_space + 1 ..];

    const version = Version.fromString(version_str) orelse return ParseError.InvalidVersion;
    const status_code = std.fmt.parseInt(u16, status_str, 10) catch return ParseError.InvalidStatusCode;
    const status = std.meta.intToEnum(StatusCode, status_code) catch return ParseError.InvalidStatusCode;

    return .{
        .version = version,
        .status = status,
        .reason = reason,
    };
}

fn parseHeaderLine(line: []const u8) ParseError!Header {
    // Header: value (with optional leading whitespace on value)
    const colon_pos = std.mem.indexOfScalar(u8, line, ':') orelse return ParseError.InvalidHeader;

    const name = line[0..colon_pos];
    var value = line[colon_pos + 1 ..];

    // Trim leading whitespace from value (OWS - optional whitespace)
    while (value.len > 0 and (value[0] == ' ' or value[0] == '\t')) {
        value = value[1..];
    }

    // Trim trailing whitespace from value
    while (value.len > 0 and (value[value.len - 1] == ' ' or value[value.len - 1] == '\t')) {
        value = value[0 .. value.len - 1];
    }

    // Validate header name (token characters only per RFC 7230)
    for (name) |c| {
        if (!isTokenChar(c)) {
            return ParseError.InvalidHeader;
        }
    }

    return .{
        .name = name,
        .value = value,
    };
}

fn parseUri(uri_str: []const u8) Uri {
    var path = uri_str;
    var query: ?[]const u8 = null;
    var fragment: ?[]const u8 = null;

    // Check for fragment
    if (std.mem.indexOfScalar(u8, path, '#')) |frag_pos| {
        fragment = path[frag_pos + 1 ..];
        path = path[0..frag_pos];
    }

    // Check for query string
    if (std.mem.indexOfScalar(u8, path, '?')) |query_pos| {
        query = path[query_pos + 1 ..];
        path = path[0..query_pos];
    }

    return .{
        .raw = uri_str,
        .path = path,
        .query = query,
        .fragment = fragment,
    };
}

/// Check if character is a valid token character per RFC 7230
fn isTokenChar(c: u8) bool {
    return switch (c) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        '0'...'9', 'A'...'Z', 'a'...'z' => true,
        else => false,
    };
}

// ============================================================================
// URL Encoding/Decoding utilities
// ============================================================================

/// Decode a percent-encoded string (URL decoding)
pub fn urlDecode(allocator: Allocator, encoded: []const u8) ![]u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < encoded.len) {
        if (encoded[i] == '%' and i + 2 < encoded.len) {
            const hex = encoded[i + 1 .. i + 3];
            const byte = std.fmt.parseInt(u8, hex, 16) catch {
                try result.append(allocator, encoded[i]);
                i += 1;
                continue;
            };
            try result.append(allocator, byte);
            i += 3;
        } else if (encoded[i] == '+') {
            // '+' represents space in query strings
            try result.append(allocator, ' ');
            i += 1;
        } else {
            try result.append(allocator, encoded[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Parse query string into key-value pairs
pub fn parseQueryString(allocator: Allocator, query: []const u8) ![]QueryParam {
    var params: std.ArrayListUnmanaged(QueryParam) = .empty;
    errdefer params.deinit(allocator);

    var pairs = std.mem.splitScalar(u8, query, '&');
    while (pairs.next()) |pair| {
        if (pair.len == 0) continue;

        if (std.mem.indexOfScalar(u8, pair, '=')) |eq_pos| {
            try params.append(allocator, .{
                .key = pair[0..eq_pos],
                .value = pair[eq_pos + 1 ..],
            });
        } else {
            // Key without value
            try params.append(allocator, .{
                .key = pair,
                .value = "",
            });
        }
    }

    return params.toOwnedSlice(allocator);
}

// ============================================================================
// Response Builder
// ============================================================================

pub const ResponseBuilder = struct {
    allocator: Allocator,
    version: Version = .HTTP_1_1,
    status: StatusCode = .OK,
    headers: std.ArrayListUnmanaged(Header) = .empty,
    body: ?[]const u8 = null,

    pub fn init(allocator: Allocator) ResponseBuilder {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ResponseBuilder) void {
        self.headers.deinit(self.allocator);
    }

    pub fn setStatus(self: *ResponseBuilder, status: StatusCode) *ResponseBuilder {
        self.status = status;
        return self;
    }

    pub fn setVersion(self: *ResponseBuilder, version: Version) *ResponseBuilder {
        self.version = version;
        return self;
    }

    pub fn addHeader(self: *ResponseBuilder, name: []const u8, value: []const u8) !*ResponseBuilder {
        try self.headers.append(self.allocator, .{ .name = name, .value = value });
        return self;
    }

    pub fn setBody(self: *ResponseBuilder, body: []const u8) *ResponseBuilder {
        self.body = body;
        return self;
    }

    pub fn setContentType(self: *ResponseBuilder, content_type: []const u8) !*ResponseBuilder {
        return self.addHeader("Content-Type", content_type);
    }

    /// Build the complete HTTP response as bytes
    pub fn build(self: *ResponseBuilder) ![]u8 {
        var buffer: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buffer.deinit(self.allocator);

        const writer = buffer.writer(self.allocator);

        // Status line
        try writer.print("{s} {d} {s}\r\n", .{
            self.version.toString(),
            @intFromEnum(self.status),
            self.status.reasonPhrase(),
        });

        // Add Content-Length if body exists and not already set
        var has_content_length = false;
        for (self.headers.items) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "Content-Length")) {
                has_content_length = true;
                break;
            }
        }

        if (self.body != null and !has_content_length) {
            try writer.print("Content-Length: {d}\r\n", .{self.body.?.len});
        }

        // Headers
        for (self.headers.items) |header| {
            try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
        }

        // End of headers
        try writer.writeAll("\r\n");

        // Body
        if (self.body) |body| {
            try writer.writeAll(body);
        }

        return buffer.toOwnedSlice(self.allocator);
    }
};

// ============================================================================
// Request Builder (for clients)
// ============================================================================

pub const RequestBuilder = struct {
    allocator: Allocator,
    method: Method = .GET,
    uri: []const u8 = "/",
    version: Version = .HTTP_1_1,
    headers: std.ArrayListUnmanaged(Header) = .empty,
    body: ?[]const u8 = null,

    pub fn init(allocator: Allocator) RequestBuilder {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RequestBuilder) void {
        self.headers.deinit(self.allocator);
    }

    pub fn setMethod(self: *RequestBuilder, method: Method) *RequestBuilder {
        self.method = method;
        return self;
    }

    pub fn setUri(self: *RequestBuilder, uri: []const u8) *RequestBuilder {
        self.uri = uri;
        return self;
    }

    pub fn addHeader(self: *RequestBuilder, name: []const u8, value: []const u8) !*RequestBuilder {
        try self.headers.append(self.allocator, .{ .name = name, .value = value });
        return self;
    }

    pub fn setHost(self: *RequestBuilder, host: []const u8) !*RequestBuilder {
        return self.addHeader("Host", host);
    }

    pub fn setBody(self: *RequestBuilder, body: []const u8) *RequestBuilder {
        self.body = body;
        return self;
    }

    pub fn build(self: *RequestBuilder) ![]u8 {
        var buffer: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buffer.deinit(self.allocator);

        const writer = buffer.writer(self.allocator);

        // Request line
        try writer.print("{s} {s} {s}\r\n", .{
            self.method.toString(),
            self.uri,
            self.version.toString(),
        });

        // Add Content-Length if body exists
        var has_content_length = false;
        for (self.headers.items) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "Content-Length")) {
                has_content_length = true;
                break;
            }
        }

        if (self.body != null and !has_content_length) {
            try writer.print("Content-Length: {d}\r\n", .{self.body.?.len});
        }

        // Headers
        for (self.headers.items) |header| {
            try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
        }

        // End of headers
        try writer.writeAll("\r\n");

        // Body
        if (self.body) |body| {
            try writer.writeAll(body);
        }

        return buffer.toOwnedSlice(self.allocator);
    }
};

// ============================================================================
// Chunked Transfer Encoding Parser
// ============================================================================

pub const ChunkedParser = struct {
    allocator: Allocator,
    state: State = .ReadingSize,
    current_chunk_size: usize = 0,
    body: std.ArrayListUnmanaged(u8) = .empty,

    const State = enum {
        ReadingSize,
        ReadingData,
        ReadingTrailer,
        Complete,
    };

    pub fn init(allocator: Allocator) ChunkedParser {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ChunkedParser) void {
        self.body.deinit(self.allocator);
    }

    /// Feed data to the chunked parser. Returns number of bytes consumed.
    pub fn feed(self: *ChunkedParser, data: []const u8) !usize {
        var pos: usize = 0;

        while (pos < data.len and self.state != .Complete) {
            switch (self.state) {
                .ReadingSize => {
                    const line_end = findCRLF(data[pos..]) orelse return pos;
                    const size_line = data[pos .. pos + line_end];

                    // Parse hex size (may have chunk extensions after semicolon)
                    var size_str = size_line;
                    if (std.mem.indexOfScalar(u8, size_line, ';')) |semi| {
                        size_str = size_line[0..semi];
                    }

                    self.current_chunk_size = std.fmt.parseInt(usize, size_str, 16) catch return error.InvalidChunkSize;
                    pos += line_end + 2;

                    if (self.current_chunk_size == 0) {
                        self.state = .ReadingTrailer;
                    } else {
                        self.state = .ReadingData;
                    }
                },
                .ReadingData => {
                    const remaining = data.len - pos;
                    const to_read = @min(remaining, self.current_chunk_size);

                    try self.body.appendSlice(self.allocator, data[pos .. pos + to_read]);
                    self.current_chunk_size -= to_read;
                    pos += to_read;

                    if (self.current_chunk_size == 0) {
                        // Expect CRLF after chunk data
                        if (pos + 2 <= data.len and data[pos] == '\r' and data[pos + 1] == '\n') {
                            pos += 2;
                            self.state = .ReadingSize;
                        } else {
                            return pos;
                        }
                    }
                },
                .ReadingTrailer => {
                    // Read trailer headers until empty line
                    const line_end = findCRLF(data[pos..]) orelse return pos;
                    if (line_end == 0) {
                        pos += 2;
                        self.state = .Complete;
                    } else {
                        // Skip trailer header
                        pos += line_end + 2;
                    }
                },
                .Complete => break,
            }
        }

        return pos;
    }

    pub fn isComplete(self: *const ChunkedParser) bool {
        return self.state == .Complete;
    }

    pub fn getBody(self: *const ChunkedParser) []const u8 {
        return self.body.items;
    }

    pub const InvalidChunkSize = error.InvalidChunkSize;
};

// ============================================================================
// Tests
// ============================================================================

test "parse simple GET request" {
    const allocator = std.testing.allocator;
    const parser = Parser.init(allocator);

    const raw_request =
        "GET /hello HTTP/1.1\r\n" ++
        "Host: localhost:3000\r\n" ++
        "User-Agent: TestClient\r\n" ++
        "\r\n";

    const result = try parser.parseRequest(raw_request);
    var request = result.request;
    defer parser.freeRequest(&request);

    try std.testing.expectEqual(Method.GET, request.method);
    try std.testing.expectEqualStrings("/hello", request.uri.path);
    try std.testing.expectEqual(Version.HTTP_1_1, request.version);
    try std.testing.expectEqual(@as(usize, 2), request.headers.len);
    try std.testing.expectEqualStrings("localhost:3000", request.getHost().?);
    try std.testing.expectEqualStrings("TestClient", request.getUserAgent().?);
    try std.testing.expect(request.body == null);
}

test "parse POST request with body" {
    const allocator = std.testing.allocator;
    const parser = Parser.init(allocator);

    const raw_request =
        "POST /api/data HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Content-Length: 13\r\n" ++
        "\r\n" ++
        "{\"key\":\"val\"}";

    const result = try parser.parseRequest(raw_request);
    var request = result.request;
    defer parser.freeRequest(&request);

    try std.testing.expectEqual(Method.POST, request.method);
    try std.testing.expectEqualStrings("/api/data", request.uri.path);
    try std.testing.expectEqualStrings("application/json", request.getContentType().?);
    try std.testing.expectEqual(@as(usize, 13), request.getContentLength().?);
    try std.testing.expectEqualStrings("{\"key\":\"val\"}", request.body.?);
}

test "parse request with query string" {
    const allocator = std.testing.allocator;
    const parser = Parser.init(allocator);

    const raw_request =
        "GET /search?q=hello&page=1 HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "\r\n";

    const result = try parser.parseRequest(raw_request);
    var request = result.request;
    defer parser.freeRequest(&request);

    try std.testing.expectEqualStrings("/search", request.uri.path);
    try std.testing.expectEqualStrings("q=hello&page=1", request.uri.query.?);
}

test "parse HTTP response" {
    const allocator = std.testing.allocator;
    const parser = Parser.init(allocator);

    const raw_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/html\r\n" ++
        "Content-Length: 13\r\n" ++
        "\r\n" ++
        "Hello, World!";

    const result = try parser.parseResponse(raw_response);
    var response = result.response;
    defer parser.freeResponse(&response);

    try std.testing.expectEqual(Version.HTTP_1_1, response.version);
    try std.testing.expectEqual(StatusCode.OK, response.status);
    try std.testing.expectEqualStrings("OK", response.reason);
    try std.testing.expectEqualStrings("Hello, World!", response.body.?);
}

test "url decode" {
    const allocator = std.testing.allocator;

    const decoded = try urlDecode(allocator, "hello%20world%21");
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("hello world!", decoded);
}

test "parse query string" {
    const allocator = std.testing.allocator;

    const params = try parseQueryString(allocator, "name=John&age=30&city=NYC");
    defer allocator.free(params);

    try std.testing.expectEqual(@as(usize, 3), params.len);
    try std.testing.expectEqualStrings("name", params[0].key);
    try std.testing.expectEqualStrings("John", params[0].value);
}

test "response builder" {
    const allocator = std.testing.allocator;

    var builder = ResponseBuilder.init(allocator);
    defer builder.deinit();

    _ = builder.setStatus(.OK);
    _ = try builder.setContentType("text/plain");
    _ = try builder.addHeader("X-Custom", "value");
    _ = builder.setBody("Hello!");

    const response = try builder.build();
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Content-Type: text/plain") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Hello!") != null);
}

test "request builder" {
    const allocator = std.testing.allocator;

    var builder = RequestBuilder.init(allocator);
    defer builder.deinit();

    _ = builder.setMethod(.POST);
    _ = builder.setUri("/api/users");
    _ = try builder.setHost("example.com");
    _ = builder.setBody("{\"name\":\"test\"}");

    const request = try builder.build();
    defer allocator.free(request);

    try std.testing.expect(std.mem.indexOf(u8, request, "POST /api/users HTTP/1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, request, "Host: example.com") != null);
}

test "method parsing" {
    try std.testing.expectEqual(Method.GET, Method.fromString("GET").?);
    try std.testing.expectEqual(Method.POST, Method.fromString("POST").?);
    try std.testing.expectEqual(Method.PUT, Method.fromString("PUT").?);
    try std.testing.expectEqual(Method.DELETE, Method.fromString("DELETE").?);
    try std.testing.expect(Method.fromString("INVALID") == null);
}

test "keep-alive detection" {
    const allocator = std.testing.allocator;
    const parser = Parser.init(allocator);

    // HTTP/1.1 defaults to keep-alive
    const req1 =
        "GET / HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "\r\n";

    const result1 = try parser.parseRequest(req1);
    var request1 = result1.request;
    defer parser.freeRequest(&request1);
    try std.testing.expect(request1.isKeepAlive());

    // HTTP/1.0 defaults to close
    const req2 =
        "GET / HTTP/1.0\r\n" ++
        "Host: localhost\r\n" ++
        "\r\n";

    const result2 = try parser.parseRequest(req2);
    var request2 = result2.request;
    defer parser.freeRequest(&request2);
    try std.testing.expect(!request2.isKeepAlive());
}
