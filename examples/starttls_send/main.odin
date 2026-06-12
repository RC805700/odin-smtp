package main

import smtp "../.."
import "core:fmt"
import "core:os"

main :: proc() {
	args := os.args[1:]
	if len(args) == 0 {
		fmt.eprintln("Usage: starttls_send --host=<host> [options]")
		fmt.eprintln()
		fmt.eprintln("Options:")
		fmt.eprintln("  --host=<host>       SMTP server hostname (required)")
		fmt.eprintln("  --port=<port>       SMTP server port (default: 587)")
		fmt.eprintln("  --user=<user>       SMTP username")
		fmt.eprintln("  --pass=<pass>       SMTP password")
		fmt.eprintln("  --from-email=<addr> Sender email address (required)")
		fmt.eprintln("  --from-name=<name>  Sender name")
		fmt.eprintln("  --to=<addr>         Recipient email address (required)")
		fmt.eprintln("  --to-name=<name>    Recipient name")
		fmt.eprintln("  --subject=<subj>    Email subject")
		fmt.eprintln("  --body-text=<text>  Plain text body")
		fmt.eprintln("  --body-html=<html>  HTML body")
		os.exit(1)
	}

	cfg := parse_args(args)

	if cfg.host == "" || cfg.from_email == "" || cfg.to_email == "" {
		fmt.eprintln("Error: --host, --from-email, and --to are required")
		os.exit(1)
	}

	fmt.printfln("Connecting to %s:%d (STARTTLS)...", cfg.host, cfg.port)
	cl, err := smtp.connect_starttls(cfg.host, cfg.port)
	if err != nil {
		fmt.eprintfln("Connection failed: %v", err)
		os.exit(1)
	}
	defer smtp.close(&cl)

	if cfg.user != "" {
		fmt.println("Authenticating with AUTH PLAIN...")
		if auth_err := smtp.auth_plain(&cl, cfg.user, cfg.pass); auth_err != nil {
			fmt.eprintfln("Authentication failed: %v", auth_err)
			os.exit(1)
		}
	}

	from := smtp.EmailAddress {
		name  = cfg.from_name,
		email = cfg.from_email,
	}
	to := []smtp.EmailAddress{{name = cfg.to_name, email = cfg.to_email}}
	opts := smtp.Send_Options {
		body_text = cfg.body_text,
		body_html = cfg.body_html,
	}

	fmt.printfln("Sending email to %s...", cfg.to_email)
	if send_err := smtp.send_mail(&cl, from, to, cfg.subject, opts); send_err != nil {
		fmt.eprintfln("Failed to send: %v", send_err)
		os.exit(1)
	}

	fmt.println("Email sent successfully!")
}

Config :: struct {
	host:       string,
	port:       int,
	user:       string,
	pass:       string,
	from_email: string,
	from_name:  string,
	to_email:   string,
	to_name:    string,
	subject:    string,
	body_text:  string,
	body_html:  string,
}

parse_args :: proc(args: []string) -> Config {
	cfg := Config {
		port      = 587,
		subject   = "Test from odin-smtp",
		body_text = "This is a test email sent with odin-smtp via STARTTLS.",
		body_html = "<p>This is a test email sent with <b>odin-smtp</b> via STARTTLS.</p>",
	}
	for arg in args {
		eq := -1
		for i := 0; i < len(arg); i += 1 {
			if arg[i] == '=' {
				eq = i
				break
			}
		}
		if eq < 0 {
			fmt.eprintfln("Warning: ignoring argument %q (expected --key=value)", arg)
			continue
		}
		key := arg[:eq]
		val := arg[eq + 1:]
		switch key {
		case "--host":
			cfg.host = val
		case "--port":
			cfg.port = _parse_port(val, 587)
		case "--user":
			cfg.user = val
		case "--pass":
			cfg.pass = val
		case "--from-email":
			cfg.from_email = val
		case "--from-name":
			cfg.from_name = val
		case "--to":
			cfg.to_email = val
		case "--to-name":
			cfg.to_name = val
		case "--subject":
			cfg.subject = val
		case "--body-text":
			cfg.body_text = val
		case "--body-html":
			cfg.body_html = val
		case "--help":
		case:
			fmt.eprintfln("Warning: unknown flag %s", key)
		}
	}
	return cfg
}

_parse_port :: proc(s: string, default: int) -> int {
	n: int
	for i := 0; i < len(s); i += 1 {
		c := s[i]
		if c < '0' || c > '9' {
			fmt.eprintfln("Warning: invalid port %q, using %d", s, default)
			return default
		}
		n = n * 10 + int(c - '0')
	}
	return n
}

