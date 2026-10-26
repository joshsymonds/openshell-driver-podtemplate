// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Command-line entry point for the `odp-probe` helper.
//!
//! The probe and installer logic lives in the library; this binary only passes
//! the process arguments to [`odp_probe::run`].

use std::process::ExitCode;

fn main() -> ExitCode {
    odp_probe::run(std::env::args_os())
}
