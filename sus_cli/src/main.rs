//! Sus generates block lists for suspicious domains.

use std::io;

use clap::Parser;
use ls_rules::LsRules;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    description: Option<String>,
}

/// Validates a hostname.
///
/// Based on [RFC 952](https://datatracker.ietf.org/doc/html/rfc952) and
/// [RFC 1123](https://datatracker.ietf.org/doc/html/rfc1123).
fn is_valid_domain(name: &str) -> bool {
    fn is_valid_char(byte: u8) -> bool {
        byte.is_ascii_lowercase()
            || byte.is_ascii_uppercase()
            || byte.is_ascii_digit()
            || byte == b'-'
            || byte == b'.'
    }

    name.bytes().all(is_valid_char)
        && !(name.is_empty()
            || name.starts_with('-')
            || name.ends_with('-')
            || name.starts_with('.')
            || name.ends_with('.'))
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let domains = itertools::process_results(io::stdin().lines(), |lines| {
        let mut domains = Vec::new();

        for line in lines {
            let mut split_line = line.split_whitespace();
            if let Some(maybe_ip_addr) = split_line.next() {
                if maybe_ip_addr == "0.0.0.0" {
                    domains.extend(
                        split_line
                            .take_while(|&token| !token.starts_with('#'))
                            .filter(|&s| is_valid_domain(s))
                            .map(std::string::ToString::to_string),
                    );
                }
            }
        }

        domains
    })?;
    let domains = domains.iter().map(String::as_str).collect();

    let mut rules = LsRules::default();
    rules.name = args.name.as_deref();
    rules.description = args.description.as_deref();
    rules.denied_remote_domains = Some(domains);

    serde_json::to_writer(&mut io::stdout(), &rules)?;

    Ok(())
}
