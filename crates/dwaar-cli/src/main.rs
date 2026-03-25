// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Dwaar CLI entry point.

fn main() {
    use std::io::Write;
    let version = env!("CARGO_PKG_VERSION");
    let _ = writeln!(std::io::stderr(), "dwaar v{version}");
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_compiles() {
        let x = 1 + 1;
        assert_eq!(x, 2);
    }
}
