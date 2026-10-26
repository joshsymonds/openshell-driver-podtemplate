// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! The driver error type that every driver operation returns.

use crate::template::TemplateError;

/// The error every driver operation returns. Each variant maps to one gRPC status
/// code when it crosses the service boundary.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// The sandbox already exists.
    #[error("sandbox already exists")]
    AlreadyExists,
    /// The sandbox does not exist.
    #[error("sandbox not found")]
    NotFound,
    /// The request is malformed or breaks a template rule. Carries the rule text.
    #[error("{0}")]
    InvalidArgument(String),
    /// A precondition does not hold, such as a sandbox state, gateway metadata or an
    /// admission rule. Carries the reason.
    #[error("{0}")]
    Precondition(String),
    /// The caller presented no valid credential. Carries the reason.
    #[error("{0}")]
    Unauthenticated(String),
    /// The caller is not allowed to perform the operation. Carries the reason.
    #[error("{0}")]
    PermissionDenied(String),
    /// An unexpected failure. Carries the message.
    #[error("{0}")]
    Message(String),
}

impl DriverError {
    /// Maps a Kubernetes API error. A 409 whose reason is `AlreadyExists` becomes
    /// `AlreadyExists`, a 404 becomes `NotFound`, and every other error becomes `Message`.
    pub fn from_kube(error: kube::Error) -> Self {
        match error {
            kube::Error::Api(api) if api.code == 409 && api.reason == "AlreadyExists" => {
                Self::AlreadyExists
            }
            kube::Error::Api(api) if api.code == 404 => Self::NotFound,
            other => Self::Message(other.to_string()),
        }
    }
}

impl From<TemplateError> for DriverError {
    fn from(error: TemplateError) -> Self {
        Self::InvalidArgument(error.to_string())
    }
}

impl From<DriverError> for tonic::Status {
    fn from(error: DriverError) -> Self {
        let message = error.to_string();
        match error {
            DriverError::AlreadyExists => Self::already_exists(message),
            DriverError::NotFound => Self::not_found(message),
            DriverError::InvalidArgument(_) => Self::invalid_argument(message),
            DriverError::Precondition(_) => Self::failed_precondition(message),
            DriverError::Unauthenticated(_) => Self::unauthenticated(message),
            DriverError::PermissionDenied(_) => Self::permission_denied(message),
            DriverError::Message(_) => Self::internal(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use kube::core::ErrorResponse;

    use super::DriverError;
    use crate::template::TemplateError;

    fn api_error(code: u16, reason: &str) -> kube::Error {
        kube::Error::Api(ErrorResponse {
            status: "Failure".to_string(),
            message: "api failure".to_string(),
            reason: reason.to_string(),
            code,
        })
    }

    #[test]
    fn error_display_names_sandbox_variants_and_carries_messages() {
        assert_eq!(
            DriverError::AlreadyExists.to_string(),
            "sandbox already exists"
        );
        assert_eq!(DriverError::NotFound.to_string(), "sandbox not found");
        assert_eq!(
            DriverError::InvalidArgument("bad field".to_string()).to_string(),
            "bad field"
        );
        assert_eq!(
            DriverError::Precondition("not ready".to_string()).to_string(),
            "not ready"
        );
        assert_eq!(
            DriverError::Unauthenticated("no token".to_string()).to_string(),
            "no token"
        );
        assert_eq!(
            DriverError::PermissionDenied("forbidden".to_string()).to_string(),
            "forbidden"
        );
        assert_eq!(DriverError::Message("boom".to_string()).to_string(), "boom");
    }

    #[test]
    fn error_status_maps_each_variant_to_its_code_and_message() {
        let cases = [
            (
                DriverError::AlreadyExists,
                tonic::Code::AlreadyExists,
                "sandbox already exists",
            ),
            (
                DriverError::NotFound,
                tonic::Code::NotFound,
                "sandbox not found",
            ),
            (
                DriverError::InvalidArgument("bad field".to_string()),
                tonic::Code::InvalidArgument,
                "bad field",
            ),
            (
                DriverError::Precondition("not ready".to_string()),
                tonic::Code::FailedPrecondition,
                "not ready",
            ),
            (
                DriverError::Unauthenticated("no token".to_string()),
                tonic::Code::Unauthenticated,
                "no token",
            ),
            (
                DriverError::PermissionDenied("forbidden".to_string()),
                tonic::Code::PermissionDenied,
                "forbidden",
            ),
            (
                DriverError::Message("boom".to_string()),
                tonic::Code::Internal,
                "boom",
            ),
        ];
        for (error, code, message) in cases {
            let status = tonic::Status::from(error);
            assert_eq!(status.code(), code);
            assert_eq!(status.message(), message);
        }
    }

    #[test]
    fn error_from_kube_maps_409_already_exists_to_already_exists() {
        let error = DriverError::from_kube(api_error(409, "AlreadyExists"));
        assert!(matches!(error, DriverError::AlreadyExists));
    }

    #[test]
    fn error_from_kube_maps_409_conflict_to_message() {
        let source = api_error(409, "Conflict");
        let expected = source.to_string();
        let error = DriverError::from_kube(source);
        assert!(matches!(error, DriverError::Message(ref m) if *m == expected));
    }

    #[test]
    fn error_from_kube_maps_404_to_not_found() {
        let error = DriverError::from_kube(api_error(404, "NotFound"));
        assert!(matches!(error, DriverError::NotFound));
    }

    #[test]
    fn error_from_kube_maps_other_errors_to_message() {
        let source = kube::Error::TlsRequired;
        let expected = source.to_string();
        let error = DriverError::from_kube(source);
        assert!(matches!(error, DriverError::Message(ref m) if *m == expected));
    }

    #[test]
    fn error_from_template_error_maps_to_invalid_argument_with_rule_text() {
        let source = TemplateError::ContainerCount(2);
        let expected = source.to_string();
        let error = DriverError::from(source);
        assert!(matches!(error, DriverError::InvalidArgument(ref m) if *m == expected));
        assert!(expected.starts_with("rule 1:"));
    }
}
