// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // tonic-build 0.14 split proto compilation into tonic-prost-build.
    tonic_prost_build::compile_protos("proto/dwaar.proto")?;
    // `println!` emits cargo build-script directives; the workspace
    // disallowed-macros lint targets library/runtime code, not build.rs.
    #[allow(clippy::disallowed_macros)]
    {
        println!("cargo:rerun-if-changed=proto/dwaar.proto");
    }
    Ok(())
}
