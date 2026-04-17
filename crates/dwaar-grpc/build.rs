// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/dwaar.proto")?;
    println!("cargo:rerun-if-changed=proto/dwaar.proto");
    Ok(())
}
