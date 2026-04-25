// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Parser tests — covering happy paths, error cases, and real-world configs.

use super::*;
use crate::model::*;

// ── Happy path ────────────────────────────────────────

#[test]
fn parse_single_site_with_reverse_proxy() {
    let config = parse(
        "example.com {
            reverse_proxy localhost:8080
        }",
    )
    .expect("should parse");

    assert_eq!(config.sites.len(), 1);
    assert_eq!(config.sites[0].address, "example.com");
    assert_eq!(config.sites[0].directives.len(), 1);
    assert!(matches!(
        &config.sites[0].directives[0],
        Directive::ReverseProxy(_)
    ));
}

#[test]
fn parse_multiple_sites() {
    let config = parse(
        "api.example.com {
            reverse_proxy localhost:3000
        }

        web.example.com {
            reverse_proxy localhost:8080
        }",
    )
    .expect("should parse");

    assert_eq!(config.sites.len(), 2);
    assert_eq!(config.sites[0].address, "api.example.com");
    assert_eq!(config.sites[1].address, "web.example.com");
}

#[test]
fn parse_wildcard_domain() {
    let config = parse(
        "*.example.com {
            reverse_proxy localhost:9000
        }",
    )
    .expect("should parse");

    assert_eq!(config.sites[0].address, "*.example.com");
}

#[test]
fn parse_port_shorthand() {
    let config = parse(
        "example.com {
            reverse_proxy :3000
        }",
    )
    .expect("should parse");

    if let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] {
        assert_eq!(
            rp.upstreams[0],
            UpstreamAddr::SocketAddr("127.0.0.1:3000".parse().expect("valid"))
        );
    } else {
        panic!("expected ReverseProxy directive");
    }
}

#[test]
fn parse_multiple_upstreams() {
    let config = parse(
        "example.com {
            reverse_proxy 10.0.0.1:8080 10.0.0.2:8080
        }",
    )
    .expect("should parse");

    if let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] {
        assert_eq!(rp.upstreams.len(), 2);
    } else {
        panic!("expected ReverseProxy directive");
    }
}

#[test]
fn parse_tls_variants() {
    let auto = parse("a.com { tls auto }").expect("parse");
    let off = parse("a.com { tls off }").expect("parse");
    let internal = parse("a.com { tls internal }").expect("parse");
    let manual = parse("a.com { tls /cert.pem /key.pem }").expect("parse");

    assert!(matches!(
        auto.sites[0].directives[0],
        Directive::Tls(TlsDirective::Auto)
    ));
    assert!(matches!(
        off.sites[0].directives[0],
        Directive::Tls(TlsDirective::Off)
    ));
    assert!(matches!(
        internal.sites[0].directives[0],
        Directive::Tls(TlsDirective::Internal)
    ));
    if let Directive::Tls(TlsDirective::Manual {
        ref cert_path,
        ref key_path,
    }) = manual.sites[0].directives[0]
    {
        assert_eq!(cert_path, "/cert.pem");
        assert_eq!(key_path, "/key.pem");
    } else {
        panic!("expected Manual TLS");
    }
}

#[test]
fn parse_tls_dns_challenge_literal_token() {
    let config = parse(
        "*.example.com {
            tls {
                dns cloudflare my-api-token-123
            }
        }",
    )
    .expect("parse");

    if let Directive::Tls(TlsDirective::DnsChallenge {
        ref provider,
        ref api_token,
    }) = config.sites[0].directives[0]
    {
        assert_eq!(provider, "cloudflare");
        assert_eq!(api_token, "my-api-token-123");
    } else {
        panic!("expected DnsChallenge TLS directive");
    }
}

#[test]
#[allow(unsafe_code)]
fn parse_tls_dns_challenge_env_var() {
    // Set the env var for this test — unsafe in Rust 1.80+ but necessary
    unsafe {
        std::env::set_var("TEST_CF_TOKEN_080", "secret-token-from-env");
    }

    let config = parse(
        "*.example.com {
            tls {
                dns cloudflare {env.TEST_CF_TOKEN_080}
            }
        }",
    )
    .expect("parse");

    if let Directive::Tls(TlsDirective::DnsChallenge {
        ref provider,
        ref api_token,
    }) = config.sites[0].directives[0]
    {
        assert_eq!(provider, "cloudflare");
        assert_eq!(api_token, "secret-token-from-env");
    } else {
        panic!("expected DnsChallenge TLS directive");
    }

    unsafe {
        std::env::remove_var("TEST_CF_TOKEN_080");
    }
}

#[test]
#[allow(unsafe_code)]
fn parse_tls_dns_challenge_missing_env_var() {
    // Make sure the env var doesn't exist
    unsafe {
        std::env::remove_var("NONEXISTENT_TOKEN_VAR_080");
    }

    let result = parse(
        "*.example.com {
            tls {
                dns cloudflare {env.NONEXISTENT_TOKEN_VAR_080}
            }
        }",
    );

    assert!(result.is_err(), "should fail on missing env var");
}

#[test]
fn parse_tls_dns_empty_block_fails() {
    let result = parse(
        "*.example.com {
            tls {
            }
        }",
    );

    assert!(result.is_err(), "empty tls block should fail");
}

#[test]
fn parse_header_set_and_delete() {
    let config = parse(
        r#"a.com {
            header X-Custom "my value"
            header -Server
        }"#,
    )
    .expect("parse");

    assert!(matches!(
        &config.sites[0].directives[0],
        Directive::Header(HeaderDirective::Set { name, value })
            if name == "X-Custom" && value == "my value"
    ));
    assert!(matches!(
        &config.sites[0].directives[1],
        Directive::Header(HeaderDirective::Delete { name })
            if name == "Server"
    ));
}

#[test]
fn parse_redir_with_and_without_code() {
    let with_code = parse("a.com { redir /old /new 301 }").expect("parse");
    let default_code = parse("a.com { redir /old /new }").expect("parse");

    if let Directive::Redir(r) = &with_code.sites[0].directives[0] {
        assert_eq!(r.code, 301);
    }
    if let Directive::Redir(r) = &default_code.sites[0].directives[0] {
        assert_eq!(r.code, 308); // Caddy default
    }
}

#[test]
fn parse_encode() {
    let config = parse("a.com { encode gzip zstd }").expect("parse");
    if let Directive::Encode(e) = &config.sites[0].directives[0] {
        assert_eq!(e.encodings, vec!["gzip", "zstd"]);
    } else {
        panic!("expected Encode directive");
    }
}

#[test]
fn parse_multiple_directives() {
    let config = parse(
        r#"example.com {
            reverse_proxy localhost:8080
            tls auto
            header X-Powered-By "Dwaar"
            encode gzip
        }"#,
    )
    .expect("parse");

    assert_eq!(config.sites[0].directives.len(), 4);
}

#[test]
fn parse_comments_ignored() {
    let config = parse(
        "# Main site
        example.com {
            # Backend
            reverse_proxy localhost:8080
        }",
    )
    .expect("parse");

    assert_eq!(config.sites.len(), 1);
}

#[test]
fn parse_empty_config() {
    let config = parse("").expect("parse");
    assert!(config.sites.is_empty());
}

#[test]
fn parse_whitespace_only() {
    let config = parse("   \n\n  \t  \n").expect("parse");
    assert!(config.sites.is_empty());
}

// ── Error cases ───────────────────────────────────────

#[test]
fn error_missing_closing_brace() {
    let err = parse("example.com {\n    reverse_proxy localhost:8080\n").expect_err("should fail");
    assert!(matches!(err.kind, ParseErrorKind::UnexpectedEof { .. }));
}

#[test]
fn error_unknown_directive_with_suggestion() {
    let err = parse("a.com { reverse_proxi localhost:8080 }").expect_err("should fail");
    if let ParseErrorKind::UnknownDirective { name, suggestion } = &err.kind {
        assert_eq!(name, "reverse_proxi");
        assert_eq!(suggestion.as_deref(), Some("reverse_proxy"));
    } else {
        panic!("expected UnknownDirective, got: {err:?}");
    }
}

#[test]
fn passthrough_directive_parses_without_error() {
    // `log` is now a fully implemented directive — must parse as Directive::Log
    let config = parse("a.com { log }").expect("log should parse");
    assert!(matches!(&config.sites[0].directives[0], Directive::Log(_)));
}

#[test]
fn passthrough_directive_with_args() {
    // `bind` is now fully implemented — parses as Directive::Bind
    let config = parse("a.com { bind 0.0.0.0 }").expect("bind should parse");
    assert!(matches!(&config.sites[0].directives[0], Directive::Bind(_)));
}

// ── bind directive parser tests (ISSUE-066) ──────────────────────────────────

#[test]
fn bind_single_port_shorthand() {
    let config = parse("a.com { bind :8443 }").expect("bind :port should parse");
    let Directive::Bind(b) = &config.sites[0].directives[0] else {
        panic!("expected Directive::Bind");
    };
    assert_eq!(b.addresses, vec![":8443"]);
}

#[test]
fn bind_bare_ip() {
    let config = parse("a.com { bind 127.0.0.1 }").expect("bind bare IP should parse");
    let Directive::Bind(b) = &config.sites[0].directives[0] else {
        panic!("expected Directive::Bind");
    };
    assert_eq!(b.addresses, vec!["127.0.0.1"]);
}

#[test]
fn bind_multiple_addresses() {
    let config = parse("a.com { bind 127.0.0.1 ::1 }").expect("bind multi-addr should parse");
    let Directive::Bind(b) = &config.sites[0].directives[0] else {
        panic!("expected Directive::Bind");
    };
    assert_eq!(b.addresses, vec!["127.0.0.1", "::1"]);
}

#[test]
fn bind_missing_address_is_an_error() {
    // `bind` with no arguments must be a parse error, not silently ignored.
    assert!(
        parse("a.com { bind }").is_err(),
        "bind with no args should fail"
    );
}

#[test]
fn passthrough_directive_with_block() {
    // `log` with a block is now fully implemented — parses as Directive::Log
    let config = parse(
        "a.com {\n    log {\n        output file /var/log/access.log\n        format json\n    }\n}\n",
    )
    .expect("log with block should parse");
    assert!(matches!(&config.sites[0].directives[0], Directive::Log(_)));
}

#[test]
fn recognized_directive_with_nested_blocks() {
    // `templates` is a recognized Caddyfile directive parsed with parse_recognized
    let config = parse(
        "a.com {\n    templates {\n        mime text/html {\n            charset utf-8\n        }\n    }\n}\n",
    )
    .expect("nested blocks should parse as recognized directive");
    assert!(matches!(
        &config.sites[0].directives[0],
        Directive::Templates(RecognizedDirective { .. })
    ));
}

#[test]
fn passthrough_does_not_affect_other_directives() {
    // `log` is now implemented — parses as Directive::Log
    let config = parse(
        "a.com {\n    reverse_proxy :8080\n    log {\n        output file /var/log/a.log\n    }\n    tls auto\n}\n",
    )
    .expect("log mixed with real directives");
    assert_eq!(config.sites[0].directives.len(), 3);
    assert!(matches!(
        config.sites[0].directives[0],
        Directive::ReverseProxy(_)
    ));
    assert!(matches!(&config.sites[0].directives[1], Directive::Log(_)));
    assert!(matches!(config.sites[0].directives[2], Directive::Tls(_)));
}

#[test]
fn all_caddy_typed_directives_parse() {
    // Every known Caddy directive must parse without error.
    // Note: placeholder syntax like {host} requires tokenizer changes
    // (Phase 2), so we test with simple args here.
    let directives = [
        // Implemented directives
        "log",
        "bind 0.0.0.0",
        "abort",
        "error \"msg\" 500",
        "request_header X-Foo bar",
        "method GET",
        "try_files /index.html",
        "vars key val",
        "skip_log",
        "log_skip",
        "request_body {\n        max_size 10MB\n    }",
        "handle_errors {\n        respond 500\n    }",
        // Typed directives (ISSUE-056)
        "metrics",
        "templates",
        "tracing",
        "map host_label server_name {~.* backend1 default backend2}",
        "push",
        "acme_server",
        "invoke route_name",
        "intercept 500 {\n        respond 502\n    }",
        "log_append X-Real True",
        "log_name my_logger",
        "fs",
    ];
    for d in directives {
        let input = format!("a.com {{\n    {d}\n}}");
        let result = parse(&input);
        assert!(
            result.is_ok(),
            "directive '{d}' should parse, got: {result:?}"
        );
    }
}

#[test]
fn error_reverse_proxy_no_upstream() {
    let err = parse("a.com { reverse_proxy }").expect_err("should fail");
    assert!(matches!(err.kind, ParseErrorKind::InvalidValue { .. }));
}

#[test]
fn error_includes_line_and_column() {
    let err = parse("a.com {\n    badstuff\n}").expect_err("should fail");
    assert_eq!(err.line, 2);
}

// ── Real-world Caddyfile samples ──────────────────────

// ── rate_limit directive (ISSUE-031) ─────────────────

#[test]
fn parse_rate_limit() {
    let config = parse("a.com { rate_limit 100/s }").expect("parse");
    if let Directive::RateLimit(rl) = &config.sites[0].directives[0] {
        assert_eq!(rl.requests_per_second, 100);
    } else {
        panic!("expected RateLimit directive");
    }
}

#[test]
fn parse_rate_limit_large_value() {
    let config = parse("a.com { rate_limit 10000/s }").expect("parse");
    if let Directive::RateLimit(rl) = &config.sites[0].directives[0] {
        assert_eq!(rl.requests_per_second, 10000);
    } else {
        panic!("expected RateLimit directive");
    }
}

#[test]
fn error_rate_limit_no_arg() {
    let err = parse("a.com { rate_limit }").expect_err("should fail");
    assert!(matches!(err.kind, ParseErrorKind::InvalidValue { .. }));
}

#[test]
fn error_rate_limit_non_numeric() {
    let err = parse("a.com { rate_limit abc/s }").expect_err("should fail");
    assert!(matches!(err.kind, ParseErrorKind::InvalidValue { .. }));
}

#[test]
fn error_rate_limit_wrong_unit() {
    let err = parse("a.com { rate_limit 100/m }").expect_err("should fail");
    assert!(matches!(err.kind, ParseErrorKind::InvalidValue { .. }));
}

#[test]
fn error_rate_limit_zero() {
    let err = parse("a.com { rate_limit 0/s }").expect_err("should fail");
    assert!(matches!(err.kind, ParseErrorKind::InvalidValue { .. }));
}

#[test]
fn parse_rate_limit_with_other_directives() {
    let config = parse(
        "a.com {
        reverse_proxy 127.0.0.1:8080
        rate_limit 200/s
        tls auto
    }",
    )
    .expect("parse");
    assert_eq!(config.sites[0].directives.len(), 3);
    assert!(matches!(
        &config.sites[0].directives[1],
        Directive::RateLimit(rl) if rl.requests_per_second == 200
    ));
}

#[test]
fn format_roundtrip_rate_limit() {
    let input = "a.com {\n    rate_limit 100/s\n}\n";
    let config = parse(input).expect("parse");
    let formatted = crate::format::format_config(&config);
    assert_eq!(formatted, input);
}

// ── Real-world Caddyfile samples ──────────────────────

#[test]
fn parse_typical_caddyfile() {
    let config = parse(
        r#"
        api.example.com {
            reverse_proxy localhost:3000
            tls auto
            encode gzip
            header -Server
        }

        web.example.com {
            reverse_proxy localhost:8080
            header X-Frame-Options "SAMEORIGIN"
        }

        *.staging.example.com {
            reverse_proxy localhost:9000
            tls internal
        }
        "#,
    )
    .expect("typical caddyfile should parse");

    assert_eq!(config.sites.len(), 3);
    assert_eq!(config.sites[0].address, "api.example.com");
    assert_eq!(config.sites[0].directives.len(), 4);
    assert_eq!(config.sites[1].address, "web.example.com");
    assert_eq!(config.sites[2].address, "*.staging.example.com");
}

// ── respond directive (ISSUE-051) ─────────────────────

#[test]
fn respond_with_body_and_status() {
    let config = parse(
        r#"
        example.com {
            respond "Not Found" 404
        }
        "#,
    )
    .expect("should parse");
    let d = &config.sites[0].directives[0];
    let Directive::Respond(r) = d else {
        panic!("expected Respond directive");
    };
    assert_eq!(r.status, 404);
    assert_eq!(r.body, "Not Found");
}

#[test]
fn respond_status_only() {
    let config = parse("health.example.com {\n    respond 204\n}\n").expect("should parse");
    let Directive::Respond(r) = &config.sites[0].directives[0] else {
        panic!("expected Respond");
    };
    assert_eq!(r.status, 204);
    assert!(r.body.is_empty());
}

#[test]
fn respond_body_only() {
    let config = parse(
        r#"
        example.com {
            respond "ok"
        }
        "#,
    )
    .expect("should parse");
    let Directive::Respond(r) = &config.sites[0].directives[0] else {
        panic!("expected Respond");
    };
    assert_eq!(r.status, 200);
    assert_eq!(r.body, "ok");
}

#[test]
fn respond_no_args_is_200_empty() {
    let config = parse("a.com {\n    respond\n}\n").expect("should parse");
    let Directive::Respond(r) = &config.sites[0].directives[0] else {
        panic!("expected Respond");
    };
    assert_eq!(r.status, 200);
    assert!(r.body.is_empty());
}

#[test]
fn respond_followed_by_other_directive() {
    let config =
        parse("a.com {\n    respond 204\n    header X-Custom \"val\"\n}\n").expect("should parse");
    assert_eq!(config.sites[0].directives.len(), 2);
    assert!(matches!(
        config.sites[0].directives[0],
        Directive::Respond(_)
    ));
    assert!(matches!(
        config.sites[0].directives[1],
        Directive::Header(_)
    ));
}

#[test]
fn respond_invalid_status_code_rejected() {
    let result = parse(
        r#"
        example.com {
            respond "err" 999
        }
        "#,
    );
    assert!(result.is_err());
}

// ── rewrite and uri directives (ISSUE-049) ───────────

#[test]
fn rewrite_replaces_path() {
    let config =
        parse("a.com {\n    reverse_proxy :8080\n    rewrite /new\n}\n").expect("should parse");
    let Directive::Rewrite(r) = &config.sites[0].directives[1] else {
        panic!("expected Rewrite");
    };
    assert_eq!(r.to, "/new");
}

#[test]
fn uri_strip_prefix() {
    let config = parse("a.com {\n    reverse_proxy :8080\n    uri strip_prefix /api\n}\n")
        .expect("should parse");
    let Directive::Uri(u) = &config.sites[0].directives[1] else {
        panic!("expected Uri");
    };
    assert!(matches!(&u.operation, UriOperation::StripPrefix(p) if p == "/api"));
}

#[test]
fn uri_strip_suffix() {
    let config = parse("a.com {\n    reverse_proxy :8080\n    uri strip_suffix .html\n}\n")
        .expect("should parse");
    let Directive::Uri(u) = &config.sites[0].directives[1] else {
        panic!("expected Uri");
    };
    assert!(matches!(&u.operation, UriOperation::StripSuffix(s) if s == ".html"));
}

#[test]
fn uri_replace() {
    let config = parse("a.com {\n    reverse_proxy :8080\n    uri replace /old /new\n}\n")
        .expect("should parse");
    let Directive::Uri(u) = &config.sites[0].directives[1] else {
        panic!("expected Uri");
    };
    assert!(matches!(
        &u.operation,
        UriOperation::Replace { find, replace } if find == "/old" && replace == "/new"
    ));
}

#[test]
fn uri_unknown_operation_rejected() {
    let result = parse("a.com {\n    reverse_proxy :8080\n    uri explode /foo\n}\n");
    assert!(result.is_err());
}

#[test]
fn rewrite_missing_path_rejected() {
    let result = parse("a.com {\n    reverse_proxy :8080\n    rewrite\n}\n");
    assert!(result.is_err());
}

// ── basicauth directive (ISSUE-046) ──────────────────

#[test]
fn basicauth_parses_credentials() {
    let config = parse(
        r"
        a.com {
            reverse_proxy :8080
            basicauth {
                admin $2a$14$somehash
                user $2a$14$otherhash
            }
        }
        ",
    )
    .expect("should parse");
    let Directive::BasicAuth(ba) = &config.sites[0].directives[1] else {
        panic!("expected BasicAuth");
    };
    assert_eq!(ba.credentials.len(), 2);
    assert_eq!(ba.credentials[0].username, "admin");
    assert_eq!(ba.credentials[1].username, "user");
    assert!(ba.realm.is_none());
}

#[test]
fn basic_auth_underscore_form_accepted() {
    let config =
        parse("a.com {\n    reverse_proxy :8080\n    basic_auth {\n        admin hash\n    }\n}\n")
            .expect("should parse");
    assert!(matches!(
        config.sites[0].directives[1],
        Directive::BasicAuth(_)
    ));
}

#[test]
fn basicauth_empty_block_rejected() {
    let result = parse("a.com {\n    reverse_proxy :8080\n    basicauth {\n    }\n}\n");
    assert!(result.is_err());
}

#[test]
fn basicauth_missing_brace_rejected() {
    let result = parse("a.com {\n    reverse_proxy :8080\n    basicauth admin hash\n}\n");
    assert!(result.is_err());
}

// ── forward_auth directive (ISSUE-047) ───────────────

#[test]
fn forward_auth_parses_full_block() {
    let config = parse(
        "a.com {\n    reverse_proxy :8080\n    forward_auth 127.0.0.1:9091 {\n        uri /api/verify\n        copy_headers Remote-User Remote-Groups\n    }\n}\n",
    )
    .expect("should parse");
    let Directive::ForwardAuth(fa) = &config.sites[0].directives[1] else {
        panic!("expected ForwardAuth");
    };
    assert_eq!(fa.uri.as_deref(), Some("/api/verify"));
    assert_eq!(fa.copy_headers, vec!["Remote-User", "Remote-Groups"]);
}

#[test]
fn forward_auth_minimal_block() {
    let config =
        parse("a.com {\n    reverse_proxy :8080\n    forward_auth 127.0.0.1:9091 {\n    }\n}\n")
            .expect("should parse");
    let Directive::ForwardAuth(fa) = &config.sites[0].directives[1] else {
        panic!("expected ForwardAuth");
    };
    assert!(fa.uri.is_none());
    assert!(fa.copy_headers.is_empty());
}

#[test]
fn forward_auth_missing_upstream_rejected() {
    let result = parse("a.com {\n    reverse_proxy :8080\n    forward_auth {\n    }\n}\n");
    assert!(result.is_err());
}

#[test]
fn forward_auth_unknown_subdirective_rejected() {
    let result = parse(
        "a.com {\n    reverse_proxy :8080\n    forward_auth 127.0.0.1:9091 {\n        method POST\n    }\n}\n",
    );
    assert!(result.is_err());
}

#[test]
fn forward_auth_plaintext_non_loopback_rejected_at_parse_time() {
    // Non-loopback plaintext target without explicit opt-in → hard parse error.
    // This matches the issue #118 behaviour where dwaar --test Dwaarfile must
    // surface the misconfiguration loudly instead of waiting for a request.
    let result = parse(
        "a.com {\n    reverse_proxy :8080\n    forward_auth authelia.prod:9091 {\n        uri /api/verify\n    }\n}\n",
    );
    let err = result.expect_err("plaintext non-loopback forward_auth must fail to parse");
    let msg = format!("{err}");
    assert!(
        msg.contains("plaintext and non-loopback"),
        "unexpected error message: {msg}"
    );
    assert!(
        msg.contains("insecure_plaintext"),
        "error should hint at insecure_plaintext (the Dwaarfile directive name): {msg}"
    );
}

#[test]
fn forward_auth_plaintext_non_loopback_allowed_with_opt_in() {
    // Same config as above but with insecure_plaintext → succeeds.
    // (Parser emits a tracing::warn! here; we don't capture logs in this test.)
    let config = parse(
        "a.com {\n    reverse_proxy :8080\n    forward_auth authelia.prod:9091 {\n        uri /api/verify\n        insecure_plaintext\n    }\n}\n",
    )
    .expect("opt-in plaintext should parse");
    let Directive::ForwardAuth(fa) = &config.sites[0].directives[1] else {
        panic!("expected ForwardAuth");
    };
    assert!(fa.insecure_plaintext);
    assert!(!fa.tls);
}

#[test]
fn forward_auth_plaintext_loopback_accepted() {
    // Loopback IP (127.0.0.1) → plaintext is fine, no opt-in required,
    // no warning emitted.
    let config = parse(
        "a.com {\n    reverse_proxy :8080\n    forward_auth 127.0.0.1:9091 {\n        uri /api/verify\n    }\n}\n",
    )
    .expect("loopback plaintext should parse");
    let Directive::ForwardAuth(fa) = &config.sites[0].directives[1] else {
        panic!("expected ForwardAuth");
    };
    assert!(!fa.tls);
    assert!(!fa.insecure_plaintext);
}

// ── file_server and root directives (ISSUE-048) ──────

#[test]
fn file_server_parses() {
    let config = parse("a.com {\n    root * /var/www\n    file_server\n}\n").expect("should parse");
    assert!(matches!(config.sites[0].directives[0], Directive::Root(_)));
    assert!(matches!(
        config.sites[0].directives[1],
        Directive::FileServer(FileServerDirective { browse: false })
    ));
}

#[test]
fn file_server_browse() {
    let config =
        parse("a.com {\n    root * /var/www\n    file_server browse\n}\n").expect("should parse");
    assert!(matches!(
        config.sites[0].directives[1],
        Directive::FileServer(FileServerDirective { browse: true })
    ));
}

#[test]
fn root_without_matcher() {
    let config = parse("a.com {\n    root /var/www\n    file_server\n}\n").expect("should parse");
    let Directive::Root(r) = &config.sites[0].directives[0] else {
        panic!("expected Root");
    };
    assert_eq!(r.path, "/var/www");
}

#[test]
fn root_with_star_matcher() {
    let config =
        parse("a.com {\n    root * /srv/static\n    file_server\n}\n").expect("should parse");
    let Directive::Root(r) = &config.sites[0].directives[0] else {
        panic!("expected Root");
    };
    assert_eq!(r.path, "/srv/static");
}

// ── handle/handle_path/route directives (ISSUE-050) ──

#[test]
fn handle_with_pattern() {
    let config = parse("a.com {\n    handle /api/* {\n        reverse_proxy :3000\n    }\n}\n")
        .expect("should parse");
    let Directive::Handle(h) = &config.sites[0].directives[0] else {
        panic!("expected Handle");
    };
    assert_eq!(h.matcher.as_deref(), Some("/api/*"));
    assert_eq!(h.directives.len(), 1);
}

#[test]
fn handle_catch_all() {
    let config =
        parse("a.com {\n    handle {\n        respond 404\n    }\n}\n").expect("should parse");
    let Directive::Handle(h) = &config.sites[0].directives[0] else {
        panic!("expected Handle");
    };
    assert!(h.matcher.is_none());
}

#[test]
fn handle_path_strips_prefix() {
    let config =
        parse("a.com {\n    handle_path /api/* {\n        reverse_proxy :3000\n    }\n}\n")
            .expect("should parse");
    let Directive::HandlePath(hp) = &config.sites[0].directives[0] else {
        panic!("expected HandlePath");
    };
    assert_eq!(hp.path_prefix, "/api/*");
}

#[test]
fn route_block() {
    let config = parse("a.com {\n    route {\n        reverse_proxy :3000\n    }\n}\n")
        .expect("should parse");
    assert!(matches!(config.sites[0].directives[0], Directive::Route(_)));
}

#[test]
fn multiple_handle_blocks() {
    let config = parse(
        "a.com {\n    handle /api/* {\n        reverse_proxy :3000\n    }\n    handle /static/* {\n        root * /var/www\n        file_server\n    }\n    handle {\n        respond 404\n    }\n}\n",
    )
    .expect("should parse");
    assert_eq!(config.sites[0].directives.len(), 3);
    assert!(matches!(
        config.sites[0].directives[0],
        Directive::Handle(_)
    ));
    assert!(matches!(
        config.sites[0].directives[1],
        Directive::Handle(_)
    ));
    assert!(matches!(
        config.sites[0].directives[2],
        Directive::Handle(_)
    ));
}

#[test]
fn handle_nested_with_middleware() {
    let config = parse(
        "a.com {\n    handle /admin/* {\n        basicauth {\n            admin hash\n        }\n        reverse_proxy :3000\n    }\n}\n",
    )
    .expect("should parse");
    let Directive::Handle(h) = &config.sites[0].directives[0] else {
        panic!("expected Handle");
    };
    assert_eq!(h.directives.len(), 2);
    assert!(matches!(h.directives[0], Directive::BasicAuth(_)));
    assert!(matches!(h.directives[1], Directive::ReverseProxy(_)));
}

// ── Global options block (Phase 1) ─────────────────────

#[test]
fn global_options_parses() {
    let config = parse(
        "{\n    http_port 8080\n    https_port 8443\n    email admin@example.com\n    debug\n}\n\na.com {\n    reverse_proxy :3000\n}\n",
    )
    .expect("should parse");
    let opts = config.global_options.as_ref().expect("has global options");
    assert_eq!(opts.http_port, Some(8080));
    assert_eq!(opts.https_port, Some(8443));
    assert_eq!(opts.email.as_deref(), Some("admin@example.com"));
    assert!(opts.debug);
    assert_eq!(config.sites.len(), 1);
}

#[test]
fn global_options_empty_block() {
    let config = parse("{\n}\na.com {\n    reverse_proxy :3000\n}\n").expect("should parse");
    let opts = config.global_options.as_ref().expect("has global options");
    assert_eq!(opts.http_port, None);
    assert!(!opts.debug);
}

#[test]
fn global_options_with_auto_https() {
    let config = parse("{\n    auto_https off\n}\na.com {\n    reverse_proxy :3000\n}\n")
        .expect("should parse");
    let opts = config.global_options.as_ref().expect("has global options");
    assert_eq!(opts.auto_https.as_deref(), Some("off"));
}

#[test]
fn global_options_unknown_stored_as_passthrough() {
    let config = parse(
        "{\n    storage file_system\n    admin off\n}\na.com {\n    reverse_proxy :3000\n}\n",
    )
    .expect("should parse");
    let opts = config.global_options.as_ref().expect("has global options");
    assert!(!opts.passthrough.is_empty());
}

#[test]
fn global_options_with_sub_block() {
    let config = parse(
        "{\n    log {\n        output file /var/log/caddy.log\n        level INFO\n    }\n}\na.com {\n    reverse_proxy :3000\n}\n",
    )
    .expect("sub-block in global options should parse");
    assert!(config.global_options.is_some());
}

#[test]
fn no_global_options_returns_none() {
    let config = parse("a.com {\n    reverse_proxy :3000\n}\n").expect("should parse");
    assert!(config.global_options.is_none());
}

#[test]
fn global_options_only_no_sites() {
    let config = parse("{\n    debug\n}\n").expect("global options without sites");
    assert!(config.global_options.is_some());
    assert!(config.sites.is_empty());
}

// ── reverse_proxy block form (ISSUE-065) ─────────────────────────────────────

#[test]
fn reverse_proxy_inline_backward_compat() {
    // Inline form must still work after block-form support is added.
    let config = parse("a.com {\n    reverse_proxy localhost:8080\n}\n").expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    assert_eq!(rp.upstreams.len(), 1);
    assert!(rp.lb_policy.is_none());
    assert!(!rp.transport_tls);
}

#[test]
fn reverse_proxy_inline_multi_upstream() {
    let config = parse("a.com {\n    reverse_proxy 127.0.0.1:8080 127.0.0.1:8081\n}\n")
        .expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    assert_eq!(rp.upstreams.len(), 2);
}

#[test]
fn reverse_proxy_block_basic() {
    let config = parse(
        "a.com {
            reverse_proxy {
                to 127.0.0.1:8080
                lb_policy round_robin
            }
        }",
    )
    .expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    assert_eq!(rp.upstreams.len(), 1);
    assert_eq!(rp.lb_policy, Some(LbPolicy::RoundRobin));
}

#[test]
fn reverse_proxy_block_all_lb_policies() {
    for (name, expected) in [
        ("round_robin", LbPolicy::RoundRobin),
        ("least_conn", LbPolicy::LeastConn),
        ("random", LbPolicy::Random),
        ("ip_hash", LbPolicy::IpHash),
    ] {
        let src = format!(
            "a.com {{\n    reverse_proxy {{\n        to 127.0.0.1:9000\n        lb_policy {name}\n    }}\n}}\n"
        );
        let config = parse(&src).unwrap_or_else(|_| panic!("should parse lb_policy {name}"));
        let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
            panic!("expected ReverseProxy");
        };
        assert_eq!(rp.lb_policy, Some(expected));
    }
}

#[test]
fn reverse_proxy_block_health_options() {
    let config = parse(
        "a.com {
            reverse_proxy {
                to 127.0.0.1:8080
                health_uri /ping
                health_interval 5
                fail_duration 30
            }
        }",
    )
    .expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    assert_eq!(rp.health_uri.as_deref(), Some("/ping"));
    assert_eq!(rp.health_interval, Some(5));
    assert_eq!(rp.fail_duration, Some(30));
}

#[test]
fn reverse_proxy_block_max_conns() {
    let config = parse(
        "a.com {
            reverse_proxy {
                to 127.0.0.1:8080
                max_conns 100
            }
        }",
    )
    .expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    assert_eq!(rp.max_conns, Some(100));
}

#[test]
fn reverse_proxy_block_transport_tls_server_name() {
    let config = parse(
        "a.com {
            reverse_proxy {
                to backend.internal:443
                transport {
                    tls_server_name backend.internal
                }
            }
        }",
    )
    .expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    assert!(rp.transport_tls);
    assert_eq!(rp.tls_server_name.as_deref(), Some("backend.internal"));
}

#[test]
fn reverse_proxy_block_transport_plain_tls() {
    // `transport { tls }` with no server name
    let config = parse(
        "a.com {
            reverse_proxy {
                to 127.0.0.1:8443
                transport {
                    tls
                }
            }
        }",
    )
    .expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    assert!(rp.transport_tls);
    assert!(rp.tls_server_name.is_none());
}

#[test]
fn reverse_proxy_block_transport_tls_client_auth() {
    let config = parse(
        "a.com {
            reverse_proxy {
                to backend:8443
                transport {
                    tls
                    tls_client_auth /path/to/client.pem /path/to/client-key.pem
                    tls_server_name backend.internal
                }
            }
        }",
    )
    .expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    assert!(rp.transport_tls);
    assert_eq!(rp.tls_server_name.as_deref(), Some("backend.internal"));
    assert_eq!(
        rp.tls_client_auth
            .as_ref()
            .map(|(c, k)| (c.as_str(), k.as_str())),
        Some(("/path/to/client.pem", "/path/to/client-key.pem"))
    );
}

#[test]
fn reverse_proxy_block_transport_tls_trusted_ca() {
    let config = parse(
        "a.com {
            reverse_proxy {
                to backend:8443
                transport {
                    tls
                    tls_trusted_ca_certs /path/to/ca.pem
                }
            }
        }",
    )
    .expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    assert!(rp.transport_tls);
    assert_eq!(rp.tls_trusted_ca_certs.as_deref(), Some("/path/to/ca.pem"));
}

#[test]
fn reverse_proxy_block_transport_full_mtls() {
    let config = parse(
        r#"a.com {
            reverse_proxy {
                to backend:8443
                transport {
                    tls
                    tls_client_auth "/certs/client.pem" "/certs/client-key.pem"
                    tls_server_name backend.internal
                    tls_trusted_ca_certs "/certs/ca-bundle.pem"
                }
            }
        }"#,
    )
    .expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    assert!(rp.transport_tls);
    assert_eq!(rp.tls_server_name.as_deref(), Some("backend.internal"));
    assert_eq!(
        rp.tls_client_auth
            .as_ref()
            .map(|(c, k)| (c.as_str(), k.as_str())),
        Some(("/certs/client.pem", "/certs/client-key.pem"))
    );
    assert_eq!(
        rp.tls_trusted_ca_certs.as_deref(),
        Some("/certs/ca-bundle.pem")
    );
}

#[test]
fn reverse_proxy_block_multi_upstream() {
    let config = parse(
        "a.com {
            reverse_proxy {
                to 127.0.0.1:8080 127.0.0.1:8081 127.0.0.1:8082
                lb_policy least_conn
            }
        }",
    )
    .expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    assert_eq!(rp.upstreams.len(), 3);
    assert_eq!(rp.lb_policy, Some(LbPolicy::LeastConn));
}

#[test]
fn reverse_proxy_block_empty_to_is_error() {
    // Block form with no `to` subdirective must error.
    let result = parse(
        "a.com {
            reverse_proxy {
                lb_policy round_robin
            }
        }",
    );
    assert!(result.is_err(), "empty upstream list must be rejected");
}

#[test]
fn reverse_proxy_block_unknown_lb_policy_is_error() {
    let result = parse(
        "a.com {
            reverse_proxy {
                to 127.0.0.1:8080
                lb_policy magic
            }
        }",
    );
    assert!(result.is_err(), "unknown lb_policy must be rejected");
}

// ── scale_to_zero parser tests (ISSUE-082) ──────────────────────────────────

#[test]
fn reverse_proxy_block_scale_to_zero_basic() {
    let config = parse(
        r#"a.com {
            reverse_proxy {
                to 127.0.0.1:8080
                scale_to_zero {
                    wake_timeout 30s
                    wake_command "docker start myapp"
                }
            }
        }"#,
    )
    .expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    let s2z = rp
        .scale_to_zero
        .as_ref()
        .expect("should have scale_to_zero");
    assert_eq!(s2z.wake_timeout_secs, 30);
    assert_eq!(s2z.wake_command, "docker start myapp");
}

#[test]
fn reverse_proxy_block_scale_to_zero_bare_seconds() {
    let config = parse(
        r#"a.com {
            reverse_proxy {
                to 127.0.0.1:8080
                scale_to_zero {
                    wake_timeout 60
                    wake_command "systemctl start myapp"
                }
            }
        }"#,
    )
    .expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    let s2z = rp
        .scale_to_zero
        .as_ref()
        .expect("should have scale_to_zero");
    assert_eq!(s2z.wake_timeout_secs, 60);
}

#[test]
fn reverse_proxy_block_scale_to_zero_default_timeout() {
    let config = parse(
        r#"a.com {
            reverse_proxy {
                to 127.0.0.1:8080
                scale_to_zero {
                    wake_command "docker start myapp"
                }
            }
        }"#,
    )
    .expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    let s2z = rp
        .scale_to_zero
        .as_ref()
        .expect("should have scale_to_zero");
    assert_eq!(s2z.wake_timeout_secs, 30, "default should be 30s");
}

#[test]
fn reverse_proxy_block_scale_to_zero_missing_command_is_error() {
    let result = parse(
        "a.com {
            reverse_proxy {
                to 127.0.0.1:8080
                scale_to_zero {
                    wake_timeout 10s
                }
            }
        }",
    );
    assert!(
        result.is_err(),
        "scale_to_zero without wake_command must fail"
    );
}

#[test]
fn reverse_proxy_inline_has_no_scale_to_zero() {
    let config = parse("a.com {\n    reverse_proxy 127.0.0.1:8080\n}").expect("should parse");
    let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] else {
        panic!("expected ReverseProxy");
    };
    assert!(rp.scale_to_zero.is_none());
}

// ── Intercept / CopyResponseHeaders parser tests (ISSUE-067) ─────────────

#[test]
fn parse_intercept_with_status_and_respond() {
    // Caddyfile respond syntax: respond "body" STATUS (body before status code)
    let config = parse(
        r#"example.com {
            reverse_proxy 127.0.0.1:8080
            intercept 404 {
                respond "not found page" 200
            }
        }"#,
    )
    .expect("should parse");

    assert_eq!(config.sites[0].directives.len(), 2);
    let Directive::Intercept(i) = &config.sites[0].directives[1] else {
        panic!("expected Intercept directive");
    };
    assert_eq!(i.statuses, vec![404]);
    assert_eq!(i.directives.len(), 1);
    let Directive::Respond(r) = &i.directives[0] else {
        panic!("expected nested Respond directive");
    };
    assert_eq!(r.status, 200);
    assert_eq!(r.body, "not found page");
}

#[test]
fn parse_intercept_multiple_statuses() {
    let config = parse(
        "example.com {
            reverse_proxy 127.0.0.1:8080
            intercept 404 503 502 {
                respond 200
            }
        }",
    )
    .expect("should parse");

    let Directive::Intercept(i) = &config.sites[0].directives[1] else {
        panic!("expected Intercept directive");
    };
    assert_eq!(i.statuses, vec![404, 503, 502]);
}

#[test]
fn parse_intercept_inside_handle_block() {
    let config = parse(
        r#"example.com {
            handle /api/* {
                reverse_proxy 127.0.0.1:8080
                intercept 404 {
                    respond "api not found" 200
                }
            }
        }"#,
    )
    .expect("should parse");

    let Directive::Handle(h) = &config.sites[0].directives[0] else {
        panic!("expected Handle directive");
    };
    let intercept = h
        .directives
        .iter()
        .find(|d| matches!(d, Directive::Intercept(_)));
    assert!(
        intercept.is_some(),
        "intercept should parse inside handle block"
    );
}

#[test]
fn parse_copy_response_headers_include() {
    let config = parse(
        "example.com {
            reverse_proxy 127.0.0.1:8080
            copy_response_headers {
                X-Custom
                X-Other
            }
        }",
    )
    .expect("should parse");

    let crh = config.sites[0].directives.iter().find_map(|d| match d {
        Directive::CopyResponseHeaders(crh) => Some(crh),
        _ => None,
    });
    let crh = crh.expect("should have copy_response_headers");
    assert!(crh.headers.contains(&"X-Custom".to_string()));
    assert!(crh.headers.contains(&"X-Other".to_string()));
}

#[test]
fn parse_copy_response_headers_exclude_prefix() {
    let config = parse(
        "example.com {
            reverse_proxy 127.0.0.1:8080
            copy_response_headers {
                -Set-Cookie
                -Server
            }
        }",
    )
    .expect("should parse");

    let crh = config.sites[0].directives.iter().find_map(|d| match d {
        Directive::CopyResponseHeaders(crh) => Some(crh),
        _ => None,
    });
    let crh = crh.expect("should have copy_response_headers");
    // Parser stores the raw string including the '-' prefix; compiler strips it
    assert!(crh.headers.contains(&"-Set-Cookie".to_string()));
    assert!(crh.headers.contains(&"-Server".to_string()));
}

#[test]
fn parse_cache_directive_full() {
    let config = parse(
        "example.com {
            cache {
                max_size 1g
                match_path /static/* /assets/*
                default_ttl 3600
                stale_while_revalidate 60
            }
            reverse_proxy localhost:8080
        }",
    )
    .expect("should parse");

    let cache = config.sites[0].directives.iter().find_map(|d| match d {
        Directive::Cache(c) => Some(c),
        _ => None,
    });
    let cache = cache.expect("should have cache directive");
    assert_eq!(cache.max_size, Some(1024 * 1024 * 1024)); // 1 GiB
    assert_eq!(cache.match_paths, vec!["/static/*", "/assets/*"]);
    assert_eq!(cache.default_ttl, Some(3600));
    assert_eq!(cache.stale_while_revalidate, Some(60));
}

#[test]
fn parse_cache_directive_minimal() {
    let config = parse(
        "example.com {
            cache {
                match_path /api/*
            }
            reverse_proxy localhost:8080
        }",
    )
    .expect("should parse");

    let cache = config.sites[0].directives.iter().find_map(|d| match d {
        Directive::Cache(c) => Some(c),
        _ => None,
    });
    let cache = cache.expect("should have cache directive");
    assert_eq!(cache.max_size, None);
    assert_eq!(cache.match_paths, vec!["/api/*"]);
    assert_eq!(cache.default_ttl, None);
    assert_eq!(cache.stale_while_revalidate, None);
}

// ── drain_timeout (ISSUE-075) ───────────────────────────────────────────────

#[test]
fn drain_timeout_seconds() {
    let config = parse("{\n    drain_timeout 30s\n}\na.com {\n    reverse_proxy :3000\n}\n")
        .expect("should parse");
    let opts = config.global_options.as_ref().expect("has global options");
    assert_eq!(opts.drain_timeout_secs, Some(30));
}

#[test]
fn drain_timeout_minutes() {
    let config = parse("{\n    drain_timeout 2m\n}\na.com {\n    reverse_proxy :3000\n}\n")
        .expect("should parse");
    let opts = config.global_options.as_ref().expect("has global options");
    assert_eq!(opts.drain_timeout_secs, Some(120));
}

#[test]
fn drain_timeout_bare_number() {
    let config = parse("{\n    drain_timeout 60\n}\na.com {\n    reverse_proxy :3000\n}\n")
        .expect("should parse");
    let opts = config.global_options.as_ref().expect("has global options");
    assert_eq!(opts.drain_timeout_secs, Some(60));
}

#[test]
fn drain_timeout_default_when_absent() {
    let config =
        parse("{\n    debug\n}\na.com {\n    reverse_proxy :3000\n}\n").expect("should parse");
    let opts = config.global_options.as_ref().expect("has global options");
    assert_eq!(opts.drain_timeout_secs, None);
}

// ── timeouts (ISSUE-076) ────────────────────────────────────────────────────

#[test]
fn timeouts_all_fields() {
    let input = r"
{
    timeouts {
        header 10s
        body 30s
        keepalive 60s
        max_requests 1000
    }
}
a.com {
    reverse_proxy :3000
}
";
    let config = parse(input).expect("should parse");
    let opts = config.global_options.as_ref().expect("has global options");
    let t = opts.timeouts.as_ref().expect("has timeouts");
    assert_eq!(t.header_secs, 10);
    assert_eq!(t.body_secs, 30);
    assert_eq!(t.keepalive_secs, 60);
    assert_eq!(t.max_requests, 1000);
}

#[test]
fn timeouts_partial_override() {
    let input = "{\n    timeouts {\n        header 5s\n        max_requests 500\n    }\n}\na.com {\n    reverse_proxy :3000\n}\n";
    let config = parse(input).expect("should parse");
    let t = config
        .global_options
        .as_ref()
        .expect("global")
        .timeouts
        .as_ref()
        .expect("timeouts");
    assert_eq!(t.header_secs, 5);
    assert_eq!(t.body_secs, 30); // default
    assert_eq!(t.keepalive_secs, 60); // default
    assert_eq!(t.max_requests, 500);
}

#[test]
fn timeouts_duration_minutes() {
    let input = "{\n    timeouts {\n        keepalive 2m\n        body 1m\n    }\n}\na.com {\n    reverse_proxy :3000\n}\n";
    let config = parse(input).expect("should parse");
    let t = config
        .global_options
        .as_ref()
        .expect("global")
        .timeouts
        .as_ref()
        .expect("timeouts");
    assert_eq!(t.keepalive_secs, 120);
    assert_eq!(t.body_secs, 60);
}

#[test]
fn timeouts_bare_number() {
    let input =
        "{\n    timeouts {\n        header 15\n    }\n}\na.com {\n    reverse_proxy :3000\n}\n";
    let config = parse(input).expect("should parse");
    let t = config
        .global_options
        .as_ref()
        .expect("global")
        .timeouts
        .as_ref()
        .expect("timeouts");
    assert_eq!(t.header_secs, 15);
}

#[test]
fn timeouts_absent_means_none() {
    let input = "{\n    debug\n}\na.com {\n    reverse_proxy :3000\n}\n";
    let config = parse(input).expect("should parse");
    let opts = config.global_options.as_ref().expect("global");
    assert!(opts.timeouts.is_none());
}

#[test]
fn timeouts_invalid_duration_errors() {
    let input =
        "{\n    timeouts {\n        header abc\n    }\n}\na.com {\n    reverse_proxy :3000\n}\n";
    let err = parse(input).expect_err("should fail");
    assert!(
        format!("{err:?}").contains("timeouts.header"),
        "error should mention timeouts.header"
    );
}

#[test]
fn timeouts_unknown_key_errors() {
    let input =
        "{\n    timeouts {\n        unknown 10s\n    }\n}\na.com {\n    reverse_proxy :3000\n}\n";
    let err = parse(input).expect_err("should fail");
    assert!(
        format!("{err:?}").contains("unknown timeout key"),
        "error should mention unknown key"
    );
}

// ── HTTP/3 global option (ISSUE-079) ────────────────────────────────

#[test]
fn h3_on_in_servers_block() {
    let config =
        parse("{\n    servers {\n        h3 on\n    }\n}\na.com {\n    reverse_proxy :3000\n}\n")
            .expect("should parse");
    let opts = config.global_options.as_ref().expect("has global options");
    assert!(opts.h3_enabled);
}

#[test]
fn h3_off_in_servers_block() {
    let config =
        parse("{\n    servers {\n        h3 off\n    }\n}\na.com {\n    reverse_proxy :3000\n}\n")
            .expect("should parse");
    let opts = config.global_options.as_ref().expect("has global options");
    assert!(!opts.h3_enabled);
}

#[test]
fn h3_default_is_disabled() {
    let config =
        parse("{\n    debug\n}\na.com {\n    reverse_proxy :3000\n}\n").expect("should parse");
    let opts = config.global_options.as_ref().expect("has global options");
    assert!(!opts.h3_enabled);
}

#[test]
fn servers_block_empty() {
    let config = parse("{\n    servers {\n    }\n}\na.com {\n    reverse_proxy :3000\n}\n")
        .expect("should parse");
    let opts = config.global_options.as_ref().expect("has global options");
    assert!(!opts.h3_enabled);
}

#[test]
fn servers_block_unknown_keys_skipped() {
    let config = parse(
        "{\n    servers {\n        h3 on\n        strict_sni_host on\n    }\n}\na.com {\n    reverse_proxy :3000\n}\n",
    )
    .expect("should parse");
    let opts = config.global_options.as_ref().expect("has global options");
    assert!(opts.h3_enabled);
}

// ── ISSUE-101: wasm_plugin directive ────────────────────────────────────────

/// Parse a `wasm_plugin` directive with all optional fields specified.
#[test]
fn parse_wasm_plugin_all_fields() {
    let config = parse(
        "example.com {
            wasm_plugin /plugins/shape.wasm {
                priority 75
                fuel 500000
                memory 8
                timeout 25
                config region=eu-west
                config tier=pro
            }
        }",
    )
    .expect("should parse");

    let Directive::WasmPlugin(ref wp) = config.sites[0].directives[0] else {
        panic!("expected WasmPlugin directive");
    };
    assert_eq!(wp.module_path, "/plugins/shape.wasm");
    assert_eq!(wp.priority, 75);
    assert_eq!(wp.fuel, Some(500_000));
    assert_eq!(wp.memory_mb, Some(8));
    assert_eq!(wp.timeout_ms, Some(25));
    assert_eq!(
        wp.config,
        vec![
            ("region".to_string(), "eu-west".to_string()),
            ("tier".to_string(), "pro".to_string()),
        ]
    );
}

/// Parse a minimal `wasm_plugin` — path only, no block. Defaults applied.
#[test]
fn parse_wasm_plugin_minimal() {
    let config = parse(
        "example.com {
            wasm_plugin /plugins/simple.wasm
        }",
    )
    .expect("should parse");

    let Directive::WasmPlugin(ref wp) = config.sites[0].directives[0] else {
        panic!("expected WasmPlugin directive");
    };
    assert_eq!(wp.module_path, "/plugins/simple.wasm");
    // Default priority 50 when block is omitted.
    assert_eq!(wp.priority, 50);
    assert!(wp.fuel.is_none());
    assert!(wp.memory_mb.is_none());
    assert!(wp.timeout_ms.is_none());
    assert!(wp.config.is_empty());
}

/// Parse a `wasm_plugin` with only some fields set — others should be None.
#[test]
fn parse_wasm_plugin_partial_fields() {
    let config = parse(
        "example.com {
            wasm_plugin /plugins/partial.wasm {
                priority 10
                fuel 1000000
            }
        }",
    )
    .expect("should parse");

    let Directive::WasmPlugin(ref wp) = config.sites[0].directives[0] else {
        panic!("expected WasmPlugin directive");
    };
    assert_eq!(wp.priority, 10);
    assert_eq!(wp.fuel, Some(1_000_000));
    assert!(wp.memory_mb.is_none());
    assert!(wp.timeout_ms.is_none());
}

/// `priority 0` is rejected — 0 is reserved.
#[test]
fn parse_wasm_plugin_priority_zero_rejected() {
    let result = parse(
        "example.com {
            wasm_plugin /plugins/shape.wasm {
                priority 0
            }
        }",
    );
    assert!(result.is_err(), "priority 0 should be rejected");
    let err = result.expect_err("must be error");
    assert!(
        err.to_string().contains("priority"),
        "error should mention priority, got: {err}"
    );
}

/// Unknown block subdirectives are silently skipped (forward compat).
#[test]
fn parse_wasm_plugin_unknown_subdirective_skipped() {
    let config = parse(
        "example.com {
            wasm_plugin /plugins/future.wasm {
                priority 20
                future_option some_value
            }
        }",
    )
    .expect("unknown subdirectives should not cause a parse error");

    let Directive::WasmPlugin(ref wp) = config.sites[0].directives[0] else {
        panic!("expected WasmPlugin directive");
    };
    assert_eq!(wp.priority, 20);
}

/// `tracing { otlp_endpoint ... }` with default sample_ratio.
#[test]
fn parse_tracing_block_with_default_sample_ratio() {
    let config = parse(
        r#"{
            tracing {
                otlp_endpoint http://127.0.0.1:4317/v1/traces
            }
        }
        example.com {
            reverse_proxy localhost:8080
        }"#,
    )
    .expect("should parse tracing block");

    let tc = config
        .global_options
        .as_ref()
        .and_then(|g| g.tracing.as_ref())
        .expect("tracing config present");
    assert_eq!(tc.otlp_endpoint, "http://127.0.0.1:4317/v1/traces");
    assert!((tc.sample_ratio - 1.0).abs() < f64::EPSILON);
}

/// `tracing { otlp_endpoint ... sample_ratio 0.5 }` parses ratio.
#[test]
fn parse_tracing_block_with_sample_ratio() {
    let config = parse(
        r#"{
            tracing {
                otlp_endpoint http://127.0.0.1:4318/v1/traces
                sample_ratio 0.5
            }
        }
        example.com {
            reverse_proxy localhost:8080
        }"#,
    )
    .expect("should parse tracing block with sample_ratio");

    let tc = config
        .global_options
        .as_ref()
        .and_then(|g| g.tracing.as_ref())
        .expect("tracing config present");
    assert_eq!(tc.otlp_endpoint, "http://127.0.0.1:4318/v1/traces");
    assert!((tc.sample_ratio - 0.5).abs() < 1e-9);
}

/// `sample_ratio` values outside [0,1] are clamped.
#[test]
fn parse_tracing_block_sample_ratio_clamped() {
    let config = parse(
        r#"{
            tracing {
                otlp_endpoint http://127.0.0.1:4318/v1/traces
                sample_ratio 2.0
            }
        }
        example.com {
            reverse_proxy localhost:8080
        }"#,
    )
    .expect("should parse with clamped ratio");

    let tc = config
        .global_options
        .as_ref()
        .and_then(|g| g.tracing.as_ref())
        .expect("tracing config present");
    assert!(
        (tc.sample_ratio - 1.0).abs() < f64::EPSILON,
        "ratio should be clamped to 1.0"
    );
}

/// `sample_ratio nan` and `sample_ratio inf` must not silently zero sampling.
/// `f64::parse` accepts both literals; without an `is_finite` guard, NaN/inf
/// would propagate through `clamp` and disable tracing without warning.
#[test]
fn parse_tracing_block_sample_ratio_rejects_non_finite() {
    for non_finite in ["nan", "inf", "-inf", "NaN", "Inf"] {
        let src = format!(
            r#"{{
                tracing {{
                    otlp_endpoint http://127.0.0.1:4318/v1/traces
                    sample_ratio {non_finite}
                }}
            }}
            example.com {{
                reverse_proxy localhost:8080
            }}"#
        );
        let config = parse(&src).expect("should parse with non-finite ratio");
        let tc = config
            .global_options
            .as_ref()
            .and_then(|g| g.tracing.as_ref())
            .expect("tracing config present");
        assert!(
            (tc.sample_ratio - 1.0).abs() < f64::EPSILON,
            "non-finite ratio {non_finite} must fall back to default 1.0, got {}",
            tc.sample_ratio
        );
    }
}
