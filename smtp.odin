package smtp

import openssl "./openssl"
import "core:bufio"
import "core:c"
import "core:encoding/base64"
import "core:fmt"
import "core:io"
import "core:net"
import "core:strconv"
import "core:strings"
import "core:time"

EmailAddress :: struct {
	name:  string,
	email: string,
}

Attachment_Disposition :: enum {
	Attachment,
	Inline,
}

Attachment :: struct {
	filename:     string,
	content:      []byte,
	content_type: string,
	disposition:  Attachment_Disposition,
	content_id:   string,
}

Send_Options :: struct {
	body_text:   string,
	body_html:   string,
	attachments: []Attachment,
}

Client_Config :: struct {
	timeout:        time.Duration,
	hello_hostname: string,
	tls_insecure:   bool,
}

Client :: struct {
	_comm: Comm,
	_host: string,
	_caps: Capabilities,
}

Comm :: union {
	net.TCP_Socket,
	SSL_Comm,
}

SSL_Comm :: struct {
	ssl:    ^openssl.SSL,
	ctx:    ^openssl.SSL_CTX,
	socket: net.TCP_Socket,
}

SMTP_Error :: struct {
	code:    int,
	message: string,
}

Error :: union {
	net.Dial_Error,
	net.Network_Error,
	net.TCP_Recv_Error,
	net.TCP_Send_Error,
	SMTP_Error,
}

Response :: struct {
	code:  int,
	lines: [dynamic]string,
}

Capabilities :: struct {
	auth_plain: bool,
	auth_login: bool,
	starttls:   bool,
	_8bitmime:  bool,
	size:       int,
}

@(private)
_message_id_counter: u64

DEFAULT_TIMEOUT :: 30 * time.Second
DEFAULT_EHLO :: "localhost"

@(private)
_apply_tls_config :: proc(ctx: ^openssl.SSL_CTX, config: Client_Config) -> Error {
	if config.tls_insecure {return nil}
	openssl.SSL_CTX_set_verify(ctx, openssl.SSL_VERIFY_PEER, nil)
	if openssl.SSL_CTX_set_default_verify_paths(ctx) != 1 {
		return SMTP_Error{0, "SSL_CTX_set_default_verify_paths failed"}
	}
	return nil
}

connect_tls :: proc(
	host: string,
	port: int = 465,
	config: Client_Config = {},
) -> (
	cl: Client,
	err: Error,
) {
	timeout := config.timeout if config.timeout != 0 else DEFAULT_TIMEOUT
	ehlo := config.hello_hostname if config.hello_hostname != "" else DEFAULT_EHLO

	endpoint := fmt.aprintf("%s:%d", host, port)
	defer delete(endpoint)

	socket := net.dial_tcp(endpoint) or_return
	net.set_option(socket, .Receive_Timeout, timeout)
	defer if err != nil {net.close(socket)}

	cl._comm = socket
	cl._host = strings.clone(ehlo)

	ctx := openssl.SSL_CTX_new(openssl.TLS_client_method())
	if ctx == nil {
		err = SMTP_Error{0, "SSL_CTX_new failed"}
		return
	}
	_apply_tls_config(ctx, config) or_return
	ssl := openssl.SSL_new(ctx)
	if ssl == nil {
		openssl.SSL_CTX_free(ctx)
		err = SMTP_Error{0, "SSL_new failed"}
		return
	}
	openssl.SSL_set_fd(ssl, c.int(socket))
	chostname := strings.clone_to_cstring(host)
	openssl.SSL_set_tlsext_host_name(ssl, chostname)
	delete(chostname)

	result := openssl.SSL_connect(ssl)
	if result != 1 {
		ssl_err := openssl.SSL_get_error(ssl, result)
		openssl.ERR_print_errors_stderr()
		openssl.SSL_free(ssl)
		openssl.SSL_CTX_free(ctx)
		err = SMTP_Error{0, "TLS handshake failed"}
		return
	}

	cl._comm = SSL_Comm{ssl, ctx, socket}

	_expect(&cl, 220) or_return

	if caps, ehlo_err := _ehlo(&cl); ehlo_err != nil {
		_helo(&cl) or_return
	} else {
		cl._caps = caps
	}

	return
}

connect_starttls :: proc(
	host: string,
	port: int = 587,
	config: Client_Config = {},
) -> (
	cl: Client,
	err: Error,
) {
	timeout := config.timeout if config.timeout != 0 else DEFAULT_TIMEOUT
	ehlo := config.hello_hostname if config.hello_hostname != "" else DEFAULT_EHLO

	endpoint := fmt.aprintf("%s:%d", host, port)
	defer delete(endpoint)

	socket := net.dial_tcp(endpoint) or_return
	net.set_option(socket, .Receive_Timeout, timeout)
	defer if err != nil {net.close(socket)}

	cl._comm = socket
	cl._host = strings.clone(ehlo)

	_expect(&cl, 220) or_return

	pre_caps, pre_err := _ehlo(&cl)
	if pre_err != nil {
		_helo(&cl) or_return
		pre_caps = {}
	}
	cl._caps = pre_caps

	if !pre_caps.starttls {
		err = SMTP_Error{0, "STARTTLS not supported by server"}
		return
	}

	_write_line(&cl, "STARTTLS") or_return
	_expect(&cl, 220) or_return

	ctx := openssl.SSL_CTX_new(openssl.TLS_client_method())
	if ctx == nil {
		err = SMTP_Error{0, "SSL_CTX_new failed"}
		return
	}
	_apply_tls_config(ctx, config) or_return
	ssl := openssl.SSL_new(ctx)
	if ssl == nil {
		openssl.SSL_CTX_free(ctx)
		err = SMTP_Error{0, "SSL_new failed"}
		return
	}
	openssl.SSL_set_fd(ssl, c.int(socket))
	chostname := strings.clone_to_cstring(host)
	openssl.SSL_set_tlsext_host_name(ssl, chostname)
	delete(chostname)

	result := openssl.SSL_connect(ssl)
	if result != 1 {
		ssl_err := openssl.SSL_get_error(ssl, result)
		openssl.ERR_print_errors_stderr()
		openssl.SSL_free(ssl)
		openssl.SSL_CTX_free(ctx)
		err = SMTP_Error{0, "TLS handshake failed"}
		return
	}

	cl._comm = SSL_Comm{ssl, ctx, socket}

	if post_caps, ehlo_err := _ehlo(&cl); ehlo_err != nil {
		_helo(&cl) or_return
	} else {
		cl._caps = post_caps
	}

	return
}

auth_plain :: proc(cl: ^Client, username, password: string) -> Error {
	auth_bytes := make([]byte, 1 + len(username) + 1 + len(password))
	defer delete(auth_bytes)
	auth_bytes[0] = 0
	copy(auth_bytes[1:], username)
	auth_bytes[1 + len(username)] = 0
	copy(auth_bytes[2 + len(username):], password)

	encoded := base64.encode(auth_bytes)
	defer delete(encoded)

	cmd := fmt.aprintf("AUTH PLAIN %s", encoded)
	defer delete(cmd)
	_write_line(cl, cmd) or_return

	return _expect(cl, 235)
}

auth_login :: proc(cl: ^Client, username, password: string) -> Error {
	_write_line(cl, "AUTH LOGIN") or_return
	resp := _read_response(cl) or_return
	defer _response_destroy(&resp)
	if resp.code != 334 {
		return SMTP_Error{resp.code, "AUTH LOGIN: expected 334 challenge"}
	}

	enc_user := base64.encode(transmute([]byte)username)
	defer delete(enc_user)
	_write_line(cl, enc_user) or_return

	resp = _read_response(cl) or_return
	defer _response_destroy(&resp)
	if resp.code != 334 {
		return SMTP_Error{resp.code, "AUTH LOGIN: expected 334 for password"}
	}

	enc_pass := base64.encode(transmute([]byte)password)
	defer delete(enc_pass)
	_write_line(cl, enc_pass) or_return

	resp = _read_response(cl) or_return
	defer _response_destroy(&resp)
	if resp.code != 235 {
		return SMTP_Error{resp.code, "Authentication failed"}
	}

	return nil
}

send_mail :: proc(
	cl: ^Client,
	from: EmailAddress,
	to: []EmailAddress,
	subject: string,
	opts: Send_Options,
) -> Error {
	from_cmd := fmt.aprintf(
		"MAIL FROM:<%s>%s",
		from.email,
		" BODY=8BITMIME" if cl._caps._8bitmime else "",
	)
	defer delete(from_cmd)
	_write_line(cl, from_cmd) or_return
	_expect(cl, 250) or_return

	for recipient in to {
		to_cmd := fmt.aprintf("RCPT TO:<%s>", recipient.email)
		defer delete(to_cmd)
		_write_line(cl, to_cmd) or_return
		_expect(cl, 250) or_return
	}

	_write_line(cl, "DATA") or_return
	_expect(cl, 354) or_return

	_write_message(cl, from, to, subject, opts) or_return

	_write_line(cl, ".") or_return
	_expect(cl, 250) or_return

	return nil
}

close :: proc(cl: ^Client) {
	if cl == nil {return}
	_close(cl)
}

@(private)
_close :: proc(cl: ^Client) {
	_write_line(cl, "QUIT")
	resp, _ := _read_response(cl)
	defer _response_destroy(&resp)

	switch s in cl._comm {
	case net.TCP_Socket:
		net.close(s)
	case SSL_Comm:
		openssl.SSL_free(s.ssl)
		openssl.SSL_CTX_free(s.ctx)
		net.close(s.socket)
	}

	delete(cl._host)
	cl^ = {}
}

// --- internal stream helpers  ---
@(private)
_tcp_stream :: proc(socket: net.TCP_Socket) -> io.Stream {
	s: io.Stream
	s.procedure = io.Stream_Proc(_tcp_stream_proc)
	s.data = rawptr(uintptr(socket))
	return s
}

@(private)
_tcp_stream_proc :: proc(
	stream_data: rawptr,
	mode: io.Stream_Mode,
	p: []byte,
	offset: i64,
	whence: io.Seek_From,
) -> (
	n: i64,
	err: io.Error,
) {
	socket := net.TCP_Socket(uintptr(stream_data))
	#partial switch mode {
	case .Read:
		if len(p) == 0 {return 0, nil}
		n_read, r_err := net.recv_tcp(socket, p)
		if r_err != nil {return 0, .EOF}
		return i64(n_read), nil
	}
	return -1, nil
}

@(private)
_ssl_stream :: proc(ssl: ^openssl.SSL) -> io.Stream {
	s: io.Stream
	s.procedure = io.Stream_Proc(_ssl_stream_proc)
	s.data = ssl
	return s
}

@(private)
_ssl_stream_proc :: proc(
	stream_data: rawptr,
	mode: io.Stream_Mode,
	p: []byte,
	offset: i64,
	whence: io.Seek_From,
) -> (
	n: i64,
	err: io.Error,
) {
	ssl := (^openssl.SSL)(stream_data)
	#partial switch mode {
	case .Read:
		if len(p) == 0 {return 0, nil}
		ret := openssl.SSL_read(ssl, raw_data(p), c.int(len(p)))
		if ret <= 0 {return 0, .EOF}
		return i64(ret), nil
	}
	return -1, nil
}

@(private)
_make_reader :: proc(cl: ^Client) -> io.Stream {
	switch s in cl._comm {
	case net.TCP_Socket:
		return _tcp_stream(s)
	case SSL_Comm:
		return _ssl_stream(s.ssl)
	}
	return {}
}

// --- I/O helpers ---
@(private)
_write :: proc(cl: ^Client, data: []byte) -> Error {
	switch s in cl._comm {
	case net.TCP_Socket:
		_, send_err := net.send_tcp(s, data)
		if send_err != nil {
			return send_err
		}
		return nil
	case SSL_Comm:
		remaining := data
		for len(remaining) > 0 {
			ret := openssl.SSL_write(s.ssl, raw_data(remaining), c.int(len(remaining)))
			if ret <= 0 {
				return SMTP_Error{0, "SSL write failed"}
			}
			remaining = remaining[ret:]
		}
		return nil
	}
	return nil
}

@(private)
_write_line :: proc(cl: ^Client, line: string) -> Error {
	_write(cl, transmute([]byte)line) or_return
	crlf := "\r\n"
	_write(cl, transmute([]byte)crlf) or_return
	return nil
}

@(private)
_read_response :: proc(cl: ^Client) -> (res: Response, err: Error) {
	stream := _make_reader(cl)
	scanner: bufio.Scanner
	bufio.scanner_init(&scanner, stream)
	defer bufio.scanner_destroy(&scanner)
	scanner.split = bufio.scan_lines

	res.lines = make([dynamic]string)
	first := true

	for {
		if !bufio.scanner_scan(&scanner) {
			_response_destroy(&res)
			err = SMTP_Error{0, "Failed to read SMTP response"}
			return
		}

		line := bufio.scanner_text(&scanner)
		clean := line
		if len(clean) > 0 && clean[len(clean) - 1] == '\r' {
			clean = clean[:len(clean) - 1]
		}
		append(&res.lines, strings.clone(clean))

		if first {
			if len(clean) >= 3 {
				code, c_ok := strconv.parse_int(clean[:3], 10)
				if c_ok {
					res.code = code
				}
			}
			first = false
		}

		if len(clean) >= 4 && clean[3] == ' ' {
			break
		}
	}

	return
}

@(private)
_response_destroy :: proc(res: ^Response) {
	for line in res.lines {
		delete(line)
	}
	delete(res.lines)
}

@(private)
_expect :: proc(cl: ^Client, expected: int) -> Error {
	resp := _read_response(cl) or_return
	defer _response_destroy(&resp)

	if resp.code != expected {
		msg := ""
		if len(resp.lines) > 0 {
			msg = resp.lines[0]
		}
		return SMTP_Error{resp.code, msg}
	}
	return nil
}

@(private)
_ehlo :: proc(cl: ^Client) -> (caps: Capabilities, err: Error) {
	cmd := fmt.aprintf("EHLO %s", cl._host)
	defer delete(cmd)
	_write_line(cl, cmd) or_return

	resp := _read_response(cl) or_return
	defer _response_destroy(&resp)

	if resp.code != 250 {
		err = SMTP_Error{resp.code, "EHLO failed"}
		return
	}

	for i := 1; i < len(resp.lines); i += 1 {
		line := resp.lines[i]
		upper := strings.to_upper(line)
		defer delete(upper)

		if strings.contains(upper, "STARTTLS") {
			caps.starttls = true
		}
		if strings.contains(upper, "8BITMIME") {
			caps._8bitmime = true
		}
		if strings.contains(upper, "AUTH PLAIN") {
			caps.auth_plain = true
		}
		if strings.contains(upper, "AUTH LOGIN") {
			caps.auth_login = true
		}
		if strings.has_prefix(upper, "250-SIZE") || strings.has_prefix(upper, "250 SIZE") {
			size_str := strings.trim_space(
				strings.trim_prefix(strings.trim_prefix(upper, "250-SIZE"), "250 SIZE"),
			)
			size, s_ok := strconv.parse_int(size_str, 10)
			if s_ok {
				caps.size = size
			}
		}
	}

	return
}

@(private)
_helo :: proc(cl: ^Client) -> Error {
	cmd := fmt.aprintf("HELO %s", cl._host)
	defer delete(cmd)
	_write_line(cl, cmd) or_return
	return _expect(cl, 250)
}

@(private)
_generate_message_id :: proc(hostname: string) -> string {
	_message_id_counter += 1
	return fmt.aprintf(
		"<%d.%d@%s>",
		time.to_unix_nanoseconds(time.now()),
		_message_id_counter,
		hostname,
	)
}

@(private)
_make_boundary :: proc() -> string {
	_message_id_counter += 1
	return fmt.aprintf("=_OdSMTP_%d_%x", time.to_unix_nanoseconds(time.now()), _message_id_counter)
}

@(private)
_mime_type_from_ext :: proc(filename: string) -> string {
	dot := -1
	for i := len(filename) - 1; i >= 0; i -= 1 {
		if filename[i] == '.' {dot = i; break}
	}
	if dot < 0 {return "application/octet-stream"}

	ext := strings.to_lower(filename[dot:])
	defer delete(ext)

	switch ext {
	case ".pdf":
		return "application/pdf"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".svg":
		return "image/svg+xml"
	case ".bmp":
		return "image/bmp"
	case ".tiff", ".tif":
		return "image/tiff"
	case ".zip":
		return "application/zip"
	case ".gz", ".gzip":
		return "application/gzip"
	case ".tar":
		return "application/x-tar"
	case ".7z":
		return "application/x-7z-compressed"
	case ".rar":
		return "application/vnd.rar"
	case ".txt":
		return "text/plain"
	case ".html", ".htm":
		return "text/html"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	case ".csv":
		return "text/csv"
	case ".doc":
		return "application/msword"
	case ".docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case ".xls":
		return "application/vnd.ms-excel"
	case ".xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case ".ppt":
		return "application/vnd.ms-powerpoint"
	case ".pptx":
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	case ".mp3":
		return "audio/mpeg"
	case ".mp4":
		return "video/mp4"
	case ".mov":
		return "video/quicktime"
	case ".avi":
		return "video/x-msvideo"
	}
	return "application/octet-stream"
}

@(private)
_write_attachment :: proc(cl: ^Client, att: Attachment) -> Error {
	ct := att.content_type if att.content_type != "" else _mime_type_from_ext(att.filename)

	_write_stuffed_linef(cl, "Content-Type: %s; name=\"%s\"", ct, att.filename) or_return
	_write_stuffed_linef(
		cl,
		"Content-Disposition: %s; filename=\"%s\"",
		"attachment" if att.disposition == .Attachment else "inline",
		att.filename,
	) or_return
	if att.content_id != "" {
		_write_stuffed_linef(cl, "Content-ID: <%s>", att.content_id) or_return
	}
	_write_stuffed_line(cl, "Content-Transfer-Encoding: base64") or_return
	_write_stuffed_line(cl, "") or_return

	encoded := _encode_body_base64(att.content)
	defer delete(encoded)
	_write(cl, transmute([]byte)encoded) or_return
	return nil
}

@(private)
_write_body_content :: proc(cl: ^Client, opts: Send_Options, inlines: []Attachment) -> Error {
	has_text := opts.body_text != ""
	has_html := opts.body_html != ""
	has_inlines := len(inlines) > 0

	if has_text && has_html && has_inlines {
		alt_b := _make_boundary()
		defer delete(alt_b)
		rel_b := _make_boundary()
		defer delete(rel_b)
		_write_stuffed_linef(
			cl,
			"Content-Type: multipart/alternative; boundary=\"%s\"",
			alt_b,
		) or_return
		_write_stuffed_line(cl, "") or_return
		_write_stuffed_linef(cl, "--%s", alt_b) or_return
		_write_body_part(cl, "text/plain", opts.body_text) or_return
		_write_stuffed_linef(cl, "--%s", alt_b) or_return
		_write_stuffed_linef(
			cl,
			"Content-Type: multipart/related; boundary=\"%s\"",
			rel_b,
		) or_return
		_write_stuffed_line(cl, "") or_return
		_write_stuffed_linef(cl, "--%s", rel_b) or_return
		_write_body_part(cl, "text/html", opts.body_html) or_return
		for &ia in inlines {
			_write_stuffed_linef(cl, "--%s", rel_b) or_return
			_write_attachment(cl, ia) or_return
		}
		_write_stuffed_linef(cl, "--%s--", rel_b) or_return
		_write_stuffed_linef(cl, "--%s--", alt_b) or_return
	} else if has_html && has_inlines {
		rel_b := _make_boundary()
		defer delete(rel_b)
		_write_stuffed_linef(
			cl,
			"Content-Type: multipart/related; boundary=\"%s\"",
			rel_b,
		) or_return
		_write_stuffed_line(cl, "") or_return
		_write_stuffed_linef(cl, "--%s", rel_b) or_return
		_write_body_part(cl, "text/html", opts.body_html) or_return
		for &ia in inlines {
			_write_stuffed_linef(cl, "--%s", rel_b) or_return
			_write_attachment(cl, ia) or_return
		}
		_write_stuffed_linef(cl, "--%s--", rel_b) or_return
	} else if has_text && has_html {
		alt_b := _make_boundary()
		defer delete(alt_b)
		_write_stuffed_linef(
			cl,
			"Content-Type: multipart/alternative; boundary=\"%s\"",
			alt_b,
		) or_return
		_write_stuffed_line(cl, "") or_return
		_write_stuffed_linef(cl, "--%s", alt_b) or_return
		_write_body_part(cl, "text/plain", opts.body_text) or_return
		_write_stuffed_linef(cl, "--%s", alt_b) or_return
		_write_body_part(cl, "text/html", opts.body_html) or_return
		_write_stuffed_linef(cl, "--%s--", alt_b) or_return
	} else if has_html {
		_write_body_part(cl, "text/html", opts.body_html) or_return
	} else {
		_write_body_part(cl, "text/plain", opts.body_text) or_return
	}
	return nil
}

@(private)
_encode_2047_subject :: proc(subject: string) -> string {
	for b in subject {
		if b > 127 {
			encoded := base64.encode(transmute([]byte)subject)
			defer delete(encoded)
			return fmt.aprintf("=?UTF-8?B?%s?=", encoded)
		}
	}
	return strings.clone(subject)
}

@(private)
_format_rfc5322_date :: proc(t: time.Time) -> string {
	wkday_strs := [?]string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	month_strs := [?]string {
		"???",
		"Jan",
		"Feb",
		"Mar",
		"Apr",
		"May",
		"Jun",
		"Jul",
		"Aug",
		"Sep",
		"Oct",
		"Nov",
		"Dec",
	}
	wkday := time.weekday(t)
	year, month, day := time.date(t)
	hour, min, sec := time.clock(t)
	return fmt.aprintf(
		"%s, %02d %s %04d %02d:%02d:%02d +0000",
		wkday_strs[wkday],
		day,
		month_strs[month],
		year,
		hour,
		min,
		sec,
	)
}

@(private)
_has_non_ascii :: proc(s: string) -> bool {
	for b in s {
		if b > 127 {return true}
	}
	return false
}

@(private)
_encode_body_base64 :: proc(data: []byte) -> string {
	b64 := base64.encode(data)
	defer delete(b64)

	buf := strings.builder_make()
	defer strings.builder_destroy(&buf)

	for i := 0; i < len(b64); i += 76 {
		end := i + 76 if i + 76 <= len(b64) else len(b64)
		strings.write_string(&buf, b64[i:end])
		strings.write_string(&buf, "\r\n")
	}

	return strings.clone(strings.to_string(buf))
}

@(private)
_write_body_part :: proc(cl: ^Client, content_type, body: string) -> Error {
	cte: string
	switch {
	case cl._caps._8bitmime:
		cte = "8bit"
	case _has_non_ascii(body):
		cte = "base64"
	}

	_write_stuffed_linef(cl, "Content-Type: %s; charset=\"UTF-8\"", content_type) or_return
	if cte != "" {
		_write_stuffed_linef(cl, "Content-Transfer-Encoding: %s", cte) or_return
	}
	_write_stuffed_line(cl, "") or_return

	if cte == "base64" {
		encoded := _encode_body_base64(transmute([]byte)body)
		defer delete(encoded)
		_write(cl, transmute([]byte)encoded) or_return
	} else {
		write_body_lines(cl, body) or_return
	}
	return nil
}

@(private)
_write_message :: proc(
	cl: ^Client,
	from: EmailAddress,
	to: []EmailAddress,
	subject: string,
	opts: Send_Options,
) -> Error {
	// From header
	_write_header_linef(
		cl,
		"From: %s <%s>" if from.name != "" else "From: <%s>",
		from.name,
		from.email,
	) or_return

	// To header
	to_addrs := make([dynamic]string, 0, len(to))
	defer {
		for a in to_addrs {delete(a)}
		delete(to_addrs)
	}
	for recipient in to {
		if recipient.name != "" {
			append(&to_addrs, fmt.aprintf("%s <%s>", recipient.name, recipient.email))
		} else {
			append(&to_addrs, fmt.aprintf("<%s>", recipient.email))
		}
	}
	to_header := strings.join(to_addrs[:], ", ")
	defer delete(to_header)
	_write_header_linef(cl, "To: %s", to_header) or_return

	// Subject (RFC 2047 auto-encode if non-ASCII)
	encoded_subject := _encode_2047_subject(subject)
	defer delete(encoded_subject)
	_write_header_linef(cl, "Subject: %s", encoded_subject) or_return

	// Date (RFC 5322 §3.6.1 - MUST)
	date := _format_rfc5322_date(time.now())
	defer delete(date)
	_write_header_linef(cl, "Date: %s", date) or_return

	// Message-ID (RFC 5322 §3.6.4 - SHOULD)
	msg_id := _generate_message_id(cl._host)
	defer delete(msg_id)
	_write_header_linef(cl, "Message-ID: %s", msg_id) or_return

	// MIME-Version
	_write_stuffed_line(cl, "MIME-Version: 1.0") or_return

	// Separate inlines from file attachments
	inlines: [dynamic]Attachment
	defer delete(inlines)
	file_atts: [dynamic]Attachment
	defer delete(file_atts)
	for att in opts.attachments {
		if att.disposition == .Inline {
			append(&inlines, att)
		} else {
			append(&file_atts, att)
		}
	}
	has_files := len(file_atts) > 0

	if has_files {
		mix_b := _make_boundary()
		defer delete(mix_b)
		_write_header_linef(cl, "Content-Type: multipart/mixed; boundary=\"%s\"", mix_b) or_return
		_write_stuffed_line(cl, "") or_return
		_write_stuffed_linef(cl, "--%s", mix_b) or_return
		_write_body_content(cl, opts, inlines[:]) or_return
		for &fa in file_atts {
			_write_stuffed_linef(cl, "--%s", mix_b) or_return
			_write_attachment(cl, fa) or_return
		}
		_write_stuffed_linef(cl, "--%s--", mix_b) or_return
	} else {
		_write_body_content(cl, opts, inlines[:]) or_return
	}

	return nil
}

@(private)
_write_header_line :: proc(cl: ^Client, line: string) -> Error {
	if len(line) <= 998 {
		return _write_stuffed_line(cl, line)
	}
	_write_stuffed_line(cl, line[:998]) or_return
	remaining := line[998:]
	for len(remaining) > 0 {
		n := 997 if len(remaining) > 997 else len(remaining)
		part := fmt.aprintf(" %s", remaining[:n])
		_write_stuffed_line(cl, part) or_return
		delete(part)
		remaining = remaining[n:]
	}
	return nil
}

@(private)
_write_header_linef :: proc(cl: ^Client, fmt_str: string, args: ..any) -> Error {
	line := fmt.aprintf(fmt_str, ..args)
	defer delete(line)
	return _write_header_line(cl, line)
}

@(private)
_write_stuffed_linef :: proc(cl: ^Client, fmt_str: string, args: ..any) -> Error {
	line := fmt.aprintf(fmt_str, ..args)
	defer delete(line)
	return _write_stuffed_line(cl, line)
}

write_body_lines :: proc(cl: ^Client, body: string) -> Error {
	it := body
	for line in strings.split_lines_iterator(&it) {
		if len(line) <= 998 {
			_write_stuffed_line(cl, line) or_return
			continue
		}
		remaining := line
		for len(remaining) > 0 {
			n := 998 if len(remaining) > 998 else len(remaining)
			_write_stuffed_line(cl, remaining[:n]) or_return
			remaining = remaining[n:]
		}
	}
	return nil
}

@(private)
_write_stuffed_line :: proc(cl: ^Client, line: string) -> Error {
	dot := "."
	if len(line) > 0 && line[0] == '.' {
		_write(cl, transmute([]byte)dot) or_return
	}
	_write_line(cl, line) or_return
	return nil
}

