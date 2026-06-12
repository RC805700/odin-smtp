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

Send_Options :: struct {
	body_text: string,
	body_html: string,
}

Client_Config :: struct {
	timeout:        time.Duration,
	hello_hostname: string,
}

Client :: struct {
	_comm: Comm,
	_host: string,
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
	size:       int,
}

DEFAULT_TIMEOUT :: 30 * time.Second
DEFAULT_EHLO :: "localhost"

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

	_ehlo(&cl) or_return

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

	caps := _ehlo(&cl) or_return

	if !caps.starttls {
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

	_ehlo(&cl) or_return

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
	from_cmd := fmt.aprintf("MAIL FROM:<%s>", from.email)
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

_close :: proc(cl: ^Client) {
	_write_line(cl, "QUIT")
	_read_response(cl)

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

// --- internal stream helpers (same pattern as odin-http client) ---

_tcp_stream :: proc(socket: net.TCP_Socket) -> io.Stream {
	s: io.Stream
	s.procedure = io.Stream_Proc(_tcp_stream_proc)
	s.data = rawptr(uintptr(socket))
	return s
}

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
		if r_err != nil {return -1, nil}
		return i64(n_read), nil
	}
	return -1, nil
}

_ssl_stream :: proc(ssl: ^openssl.SSL) -> io.Stream {
	s: io.Stream
	s.procedure = io.Stream_Proc(_ssl_stream_proc)
	s.data = ssl
	return s
}

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
		if ret <= 0 {return -1, nil}
		return i64(ret), nil
	}
	return -1, nil
}

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

_write_line :: proc(cl: ^Client, line: string) -> Error {
	_write(cl, transmute([]byte)line) or_return
	crlf := "\r\n"
	_write(cl, transmute([]byte)crlf) or_return
	return nil
}

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

_response_destroy :: proc(res: ^Response) {
	for line in res.lines {
		delete(line)
	}
	delete(res.lines)
}

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

_write_message :: proc(
	cl: ^Client,
	from: EmailAddress,
	to: []EmailAddress,
	subject: string,
	opts: Send_Options,
) -> Error {
	builder: strings.Builder

	if from.name != "" {
		fmt.sbprintf(&builder, "From: %s <%s>\n", from.name, from.email)
	} else {
		fmt.sbprintf(&builder, "From: <%s>\n", from.email)
	}

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
	fmt.sbprintf(&builder, "To: %s\n", to_header)

	fmt.sbprintf(&builder, "Subject: %s\n", subject)
	fmt.sbprintf(&builder, "MIME-Version: 1.0\n")

	ns := time.to_unix_nanoseconds(time.now())
	boundary := fmt.aprintf("=_OdSMTP_%d", ns)
	defer delete(boundary)

	has_text := opts.body_text != ""
	has_html := opts.body_html != ""

	if has_text && has_html {
		fmt.sbprintf(&builder, "Content-Type: multipart/alternative; boundary=\"%s\"\n", boundary)
		fmt.sbprintf(&builder, "\n")
		fmt.sbprintf(&builder, "--%s\n", boundary)
		fmt.sbprintf(&builder, "Content-Type: text/plain; charset=\"UTF-8\"\n")
		fmt.sbprintf(&builder, "\n")
		fmt.sbprintf(&builder, "%s\n", opts.body_text)
		fmt.sbprintf(&builder, "--%s\n", boundary)
		fmt.sbprintf(&builder, "Content-Type: text/html; charset=\"UTF-8\"\n")
		fmt.sbprintf(&builder, "\n")
		fmt.sbprintf(&builder, "%s\n", opts.body_html)
		fmt.sbprintf(&builder, "--%s--\n", boundary)
	} else if has_html {
		fmt.sbprintf(&builder, "Content-Type: text/html; charset=\"UTF-8\"\n")
		fmt.sbprintf(&builder, "\n")
		fmt.sbprintf(&builder, "%s\n", opts.body_html)
	} else {
		fmt.sbprintf(&builder, "Content-Type: text/plain; charset=\"UTF-8\"\n")
		fmt.sbprintf(&builder, "\n")
		fmt.sbprintf(&builder, "%s\n", opts.body_text)
	}

	msg := strings.to_string(builder)
	it := msg

	for line in strings.split_lines_iterator(&it) {
		dot := "."
		if len(line) > 0 && line[0] == '.' {
			_write(cl, transmute([]byte)dot) or_return
		}
		_write_line(cl, line) or_return
	}

	return nil
}

