// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Turns a `PodTemplate` into the workload pod, per `DESIGN.md` section 6.

mod mutate;
mod probes;
mod validate;

pub mod upstream;
pub use mutate::{MutationParams, mutate};
pub use validate::{TemplateError, ValidatedTemplate, validate};
