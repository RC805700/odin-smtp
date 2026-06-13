# odin-smtp

A simple SMTP client library for [Odin](https://odin-lang.org).

> **This library was created by a clanker.**

## Features

- Direct TLS (RFC 8314, port 465)
- STARTTLS upgrade (RFC 3207, port 587)
- AUTH PLAIN and AUTH LOGIN (RFC 4616)
- Multipart email: plain text, HTML, and multipart/alternative
- File attachments with automatic MIME type detection
- Inline image embedding (`cid:` references in HTML)
- 8BITMIME-aware content encoding (auto-fallback to base64)
- RFC compliance: Date, Message-ID, Subject encoding, header folding, line-length limits

## Dependencies

- OpenSSL 3.x (bindings from odin-http)

OpenSSL is typically pre-installed on Linux. On Windows the required `.lib` files are included in `openssl/includes/`.

### Types

| Type                     | Description                                                                                                     |
| ------------------------ | --------------------------------------------------------------------------------------------------------------- |
| `EmailAddress`           | `{name, email string}`                                                                                          |
| `Attachment`             | `{filename string, content []byte, content_type string, disposition Attachment_Disposition, content_id string}` |
| `Attachment_Disposition` | `enum { Attachment, Inline }`                                                                                   |
| `Send_Options`           | `{body_text, body_html string, attachments []Attachment}`                                                       |
| `Client_Config`          | `{timeout time.Duration, hello_hostname string, tls_insecure bool}`                                             |
| `Client`                 | SMTP connection handle (opaque)                                                                                 |
| `Error`                  | `net.Dial_Error \| net.Network_Error \| net.TCP_Recv_Error \| net.TCP_Send_Error \| SMTP_Error`                 |
| `Response`               | `{code int, lines [dynamic]string}`                                                                             |
| `Capabilities`           | `{auth_plain, auth_login, starttls, _8bitmime bool, size int}`                                                  |

### Procedures

```odin
connect_tls(host: string, port: int = 465, config: Client_Config = {}) -> (Client, Error)
connect_starttls(host: string, port: int = 587, config: Client_Config = {}) -> (Client, Error)
auth_plain(cl: ^Client, username, password: string) -> Error
auth_login(cl: ^Client, username, password: string) -> Error
send_mail(cl: ^Client, from: EmailAddress, to: []EmailAddress, subject: string, opts: Send_Options) -> Error
close(cl: ^Client)
```

## Usage

### Direct TLS (port 465)

```odin
cl, err := smtp.connect_tls("smtp.example.com", 465)
if err != nil { /* handle */ }
defer smtp.close(&cl)

smtp.auth_plain(&cl, "user@example.com", "password") or_return

from := smtp.EmailAddress{"Sender Name", "sender@example.com"}
to   := []smtp.EmailAddress{{"Recipient", "recipient@example.com"}}
opts := smtp.Send_Options{
    body_text = "Hello from Odin!",
    body_html = "<p>Hello from <b>Odin</b>!</p>",
}
smtp.send_mail(&cl, from, to, "Test Subject", opts) or_return
```

### STARTTLS (port 587)

```odin
cl, err := smtp.connect_starttls("smtp.example.com", 587)
```

### With TLS config

```odin
cl, err := smtp.connect_tls("smtp.example.com", 465, {
    timeout      = 10 * time.Second,
    hello_hostname = "myhost.example.com",
    tls_insecure = true,  // skip certificate verification
})
```

## Examples

See the `examples/` directory:

```sh
# TLS connection (port 465)
odin run examples/tls_send -- \
    --host=smtp.example.com --port=465 \
    --user="user@example.com" --pass="password" \
    --from-email="user@example.com" --from-name="Sender" \
    --to="recipient@example.com" \
    --subject="Hello" --body-text="Test"

# STARTTLS connection (port 587)
odin run examples/starttls_send -- \
    --host=smtp.example.com --port=587 \
    --user="user@example.com" --pass="password" \
    --from-email="user@example.com" --from-name="Sender" \
    --to="recipient@example.com" \
    --subject="Hello" --body-text="Test"

# With file attachment
odin run examples/tls_send -- \
    --host=smtp.example.com --user="user@example.com" --pass="password" \
    --from-email="user@example.com" --to="recipient@example.com" \
    --attach=examples/test-attachment.txt

# With inline image (HTML body references `cid:logo`)
odin run examples/tls_send -- \
    --host=smtp.example.com --user="user@example.com" --pass="password" \
    --from-email="user@example.com" --to="recipient@example.com" \
    --body-html='<img src="cid:logo" alt="Logo"><p>Hello</p>' \
    --inline=logo.png --cid=logo
```

### Attachment usage in code

```odin
data, err := os.read_entire_file_from_path("report.pdf", context.allocator)

opts := smtp.Send_Options{
    body_text = "See attached report",
    attachments = {
        {filename = "report.pdf", content = data},
    },
}
smtp.send_mail(&cl, from, to, "Subject", opts) or_return
```

### Inline image usage

```odin
png := os.read_entire_file_from_path("logo.png", context.allocator)

opts := smtp.Send_Options{
    body_html = `<img src="cid:logo" alt="Logo"><p>Hello</p>`,
    attachments = {
        {
            filename    = "logo.png",
            content     = png,
            disposition = .Inline,
            content_id  = "logo",
        },
    },
}
smtp.send_mail(&cl, from, to, "Subject", opts) or_return
```

## License

MIT
