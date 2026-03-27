// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! CLI argument parsing for Dwaar.
//!
//! Dwaar wraps Pingora's `Opt` with its own CLI to provide a cleaner
//! user experience. Pingora's flags (-u, -d, -t, -c) are mapped to
//! Dwaar-specific names (--upgrade, --daemon, --test, --config).

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// The gateway for your applications.
#[derive(Parser, Debug)]
#[command(
    name = "dwaar",
    version = env!("CARGO_PKG_VERSION"),
    about = "The gateway for your applications. Pingora performance. Caddy simplicity.",
    long_about = None,
)]
pub(crate) struct Cli {
    /// Path to Dwaarfile configuration
    #[arg(short, long, default_value = "./Dwaarfile", env = "DWAAR_CONFIG")]
    pub config: PathBuf,

    /// Validate configuration and exit without starting the server
    #[arg(short, long)]
    pub test: bool,

    /// Run as a background daemon
    #[arg(short, long)]
    pub daemon: bool,

    /// Perform a zero-downtime upgrade from a running Dwaar instance
    #[arg(short, long)]
    pub upgrade: bool,

    /// Enable Docker container auto-discovery via socket API.
    /// Optionally specify the socket path (default: /var/run/docker.sock).
    #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = "/var/run/docker.sock")]
    pub docker_socket: Option<PathBuf>,

    /// Enable Admin API on a Unix domain socket for Deploy Agent integration.
    /// Optionally specify the socket path (default: /var/run/dwaar-admin.sock).
    #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = "/var/run/dwaar-admin.sock")]
    pub admin_socket: Option<PathBuf>,

    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Available subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    /// Show version information
    Version,
    /// Validate Dwaarfile and exit without starting the server
    Validate {
        /// Path to Dwaarfile (overrides --config)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Format Dwaarfile to canonical style
    Fmt {
        /// Path to Dwaarfile (overrides --config)
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Check formatting without modifying the file (exit 1 if unformatted)
        #[arg(long)]
        check: bool,
    },
}

impl Cli {
    /// Parse CLI arguments from `std::env::args`.
    ///
    /// This is a thin wrapper around `clap::Parser::parse()` to keep
    /// the import isolated to this module.
    pub(crate) fn parse_args() -> Self {
        <Self as Parser>::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn default_config_path() {
        let cli = Cli::try_parse_from(["dwaar"]).expect("should parse with no args");
        assert_eq!(cli.config, PathBuf::from("./Dwaarfile"));
        assert!(!cli.test);
        assert!(!cli.daemon);
        assert!(!cli.upgrade);
        assert!(cli.command.is_none());
    }

    #[test]
    fn custom_config_path() {
        let cli = Cli::try_parse_from(["dwaar", "--config", "/etc/dwaar/Dwaarfile"])
            .expect("should parse --config");
        assert_eq!(cli.config, PathBuf::from("/etc/dwaar/Dwaarfile"));
    }

    #[test]
    fn short_config_flag() {
        let cli = Cli::try_parse_from(["dwaar", "-c", "/tmp/test.conf"]).expect("should parse -c");
        assert_eq!(cli.config, PathBuf::from("/tmp/test.conf"));
    }

    #[test]
    fn test_flag() {
        let cli = Cli::try_parse_from(["dwaar", "--test"]).expect("should parse --test");
        assert!(cli.test);
    }

    #[test]
    fn short_test_flag() {
        let cli = Cli::try_parse_from(["dwaar", "-t"]).expect("should parse -t");
        assert!(cli.test);
    }

    #[test]
    fn daemon_flag() {
        let cli = Cli::try_parse_from(["dwaar", "--daemon"]).expect("should parse --daemon");
        assert!(cli.daemon);
    }

    #[test]
    fn upgrade_flag() {
        let cli = Cli::try_parse_from(["dwaar", "--upgrade"]).expect("should parse --upgrade");
        assert!(cli.upgrade);
    }

    #[test]
    fn version_subcommand() {
        let cli =
            Cli::try_parse_from(["dwaar", "version"]).expect("should parse version subcommand");
        assert!(matches!(cli.command, Some(Commands::Version)));
    }

    #[test]
    fn validate_subcommand() {
        let cli =
            Cli::try_parse_from(["dwaar", "validate"]).expect("should parse validate subcommand");
        assert!(matches!(
            cli.command,
            Some(Commands::Validate { config: None })
        ));
    }

    #[test]
    fn validate_with_custom_config() {
        let cli = Cli::try_parse_from(["dwaar", "validate", "--config", "/tmp/test.conf"])
            .expect("should parse validate with config");
        if let Some(Commands::Validate { config }) = &cli.command {
            assert_eq!(
                config.as_deref(),
                Some(std::path::Path::new("/tmp/test.conf"))
            );
        } else {
            panic!("expected Validate command");
        }
    }

    #[test]
    fn fmt_subcommand() {
        let cli = Cli::try_parse_from(["dwaar", "fmt"]).expect("should parse fmt");
        assert!(matches!(
            cli.command,
            Some(Commands::Fmt {
                config: None,
                check: false
            })
        ));
    }

    #[test]
    fn fmt_check_flag() {
        let cli =
            Cli::try_parse_from(["dwaar", "fmt", "--check"]).expect("should parse fmt --check");
        if let Some(Commands::Fmt { check, .. }) = &cli.command {
            assert!(check);
        } else {
            panic!("expected Fmt command");
        }
    }

    #[test]
    fn combined_flags() {
        let cli = Cli::try_parse_from(["dwaar", "-c", "/etc/dwaar.conf", "--daemon", "--test"])
            .expect("should parse combined flags");
        assert_eq!(cli.config, PathBuf::from("/etc/dwaar.conf"));
        assert!(cli.daemon);
        assert!(cli.test);
    }

    #[test]
    fn unknown_flag_fails() {
        let result = Cli::try_parse_from(["dwaar", "--unknown"]);
        assert!(result.is_err());
    }

    #[test]
    fn docker_socket_disabled_by_default() {
        let cli = Cli::try_parse_from(["dwaar"]).expect("parse");
        assert!(cli.docker_socket.is_none());
    }

    #[test]
    fn docker_socket_default_path() {
        let cli = Cli::try_parse_from(["dwaar", "--docker-socket"]).expect("parse");
        assert_eq!(
            cli.docker_socket,
            Some(PathBuf::from("/var/run/docker.sock"))
        );
    }

    #[test]
    fn docker_socket_custom_path() {
        let cli = Cli::try_parse_from(["dwaar", "--docker-socket", "/custom/docker.sock"])
            .expect("parse");
        assert_eq!(
            cli.docker_socket,
            Some(PathBuf::from("/custom/docker.sock"))
        );
    }

    #[test]
    fn admin_socket_disabled_by_default() {
        let cli = Cli::try_parse_from(["dwaar"]).expect("parse");
        assert!(cli.admin_socket.is_none());
    }

    #[test]
    fn admin_socket_default_path() {
        let cli = Cli::try_parse_from(["dwaar", "--admin-socket"]).expect("parse");
        assert_eq!(
            cli.admin_socket,
            Some(PathBuf::from("/var/run/dwaar-admin.sock"))
        );
    }

    #[test]
    fn admin_socket_custom_path() {
        let cli =
            Cli::try_parse_from(["dwaar", "--admin-socket", "/tmp/custom.sock"]).expect("parse");
        assert_eq!(cli.admin_socket, Some(PathBuf::from("/tmp/custom.sock")));
    }
}
