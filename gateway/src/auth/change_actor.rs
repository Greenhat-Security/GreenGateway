//! Who committed an authority change, as its durable evidence records it
//! (issue #425).
//!
//! An admin endpoint builds a [`ChangeActor`] from the authenticated
//! [`Principal`], and an operator command builds a [`ChangeActor::system`]
//! one. The store that writes the change's evidence takes it as given, in the
//! change's own transaction: Connection deletes, service-token rotates and
//! revokes, and JWT revokes, and in standalone mode also Connection creates
//! and replaces and every encrypted local-secret change. It carries the four
//! facts the proposed `authority_event.v1` actor is made of -- the subject,
//! the canonical issuer, the actor kind and the auth mode -- and nothing else:
//! never a credential, a session identifier, roles or an email address.

use super::principal::{
    canonical_issuer, AuthMethod, Principal, MAX_PRINCIPAL_ISSUER_BYTES,
    MAX_PRINCIPAL_SUBJECT_BYTES,
};

/// What kind of actor committed a change. The values are the closed
/// `actor_kind` vocabulary of the evidence tables: PostgreSQL migration 24 and
/// the standalone token database hold the same CHECK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActorKind {
    /// A principal an identity provider or the inbound TLS handshake vouched
    /// for: a session cookie, a bearer JWT or a client certificate.
    Principal,
    /// A gateway-issued service token.
    ServiceToken,
    /// An operator command acting on the deployment's own authority under a
    /// fixed label, such as `revoke-jwt`. Nobody authenticated it, so it has
    /// no issuer and never masquerades as a named person. The cluster-mode
    /// `revoke-jwt` command and the standalone `connection-secrets reencrypt`
    /// command record one.
    System,
}

impl ActorKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Principal => "principal",
            Self::ServiceToken => "service_token",
            Self::System => "system",
        }
    }

    /// The kind a stored `actor_kind` value names, if it names one. Only the
    /// cluster-mode delivery projection reads stored kinds.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    pub(crate) fn from_stored(value: &str) -> Option<Self> {
        [Self::Principal, Self::ServiceToken, Self::System]
            .into_iter()
            .find(|kind| kind.as_str() == value)
    }
}

/// The auth mode a system actor records: the proposed event contract's
/// `system`, which no [`AuthMethod`] produces.
pub(crate) const SYSTEM_AUTH_MODE: &str = "system";

/// Every auth mode evidence may record with each kind: the audit labels of
/// [`AuthMethod`] for the principals that produce them, and
/// [`SYSTEM_AUTH_MODE`]. The evidence tables' CHECK constraints hold the same
/// pairs, and the delivery projection refuses any other.
pub(crate) fn auth_mode_agrees(kind: ActorKind, auth_mode: &str) -> bool {
    match kind {
        ActorKind::Principal => [
            AuthMethod::Cookie,
            AuthMethod::Bearer,
            AuthMethod::ClientCertificate,
        ]
        .iter()
        .any(|method| method.audit_mode() == auth_mode),
        ActorKind::ServiceToken => auth_mode == AuthMethod::ServiceToken.audit_mode(),
        ActorKind::System => auth_mode == SYSTEM_AUTH_MODE,
    }
}

/// Who committed one change. Kind and auth mode always agree, because only the
/// constructors set them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChangeActor {
    subject: String,
    issuer: Option<String>,
    kind: ActorKind,
    auth_mode: &'static str,
}

impl ChangeActor {
    /// The authenticated principal, with its issuer in the canonical form
    /// audit and policy use. A service-token principal is its own kind: its
    /// subject is the gateway's `service-token:<id>` label, which an identity
    /// provider could also assert for a person, so only the kind tells the two
    /// apart.
    pub(crate) fn from_principal(principal: &Principal) -> Self {
        let kind = match principal.auth_method {
            AuthMethod::ServiceToken => ActorKind::ServiceToken,
            AuthMethod::Cookie | AuthMethod::Bearer | AuthMethod::ClientCertificate => {
                ActorKind::Principal
            }
        };
        Self {
            subject: principal.user_id.clone(),
            issuer: principal.issuer.as_deref().and_then(canonical_issuer),
            kind,
            auth_mode: principal.auth_method.audit_mode(),
        }
    }

    /// An operator command's fixed label, recorded as system provenance.
    /// The cluster-mode `revoke-jwt` command and the standalone
    /// `connection-secrets reencrypt` command record one.
    pub(crate) fn system(label: &'static str) -> Self {
        Self {
            subject: label.to_owned(),
            issuer: None,
            kind: ActorKind::System,
            auth_mode: SYSTEM_AUTH_MODE,
        }
    }

    /// The recorded actor identifier: the principal's subject, or the system
    /// label.
    pub(crate) fn subject(&self) -> &str {
        &self.subject
    }

    pub(crate) fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    pub(crate) fn kind(&self) -> ActorKind {
        self.kind
    }

    pub(crate) fn auth_mode(&self) -> &'static str {
        self.auth_mode
    }

    /// Whether evidence can record this actor exactly as it is: a subject of
    /// 1 to [`MAX_PRINCIPAL_SUBJECT_BYTES`] bytes and, only for a principal,
    /// an issuer of 1 to [`MAX_PRINCIPAL_ISSUER_BYTES`] bytes. Those are the
    /// bounds authentication already enforces, so an authenticated principal
    /// always passes. A store refuses anything else before it changes
    /// anything, rather than truncate the actor or commit the change
    /// anonymously; the evidence tables' CHECK constraints are the backstop.
    pub(crate) fn is_recordable(&self) -> bool {
        let subject = !self.subject.is_empty() && self.subject.len() <= MAX_PRINCIPAL_SUBJECT_BYTES;
        let issuer = match self.issuer.as_deref() {
            None => true,
            Some(issuer) => {
                self.kind == ActorKind::Principal
                    && !issuer.is_empty()
                    && issuer.len() <= MAX_PRINCIPAL_ISSUER_BYTES
            }
        };
        subject && issuer && auth_mode_agrees(self.kind, self.auth_mode)
    }

    /// A bearer-authenticated principal with no issuer, for the tests of the
    /// stores that record actors.
    #[cfg(test)]
    pub(crate) fn for_test(subject: &str) -> Self {
        Self {
            subject: subject.to_owned(),
            issuer: None,
            kind: ActorKind::Principal,
            auth_mode: AuthMethod::Bearer.audit_mode(),
        }
    }

    /// The same principal vouched for by `issuer` exactly as given, with no
    /// canonicalization, so a test can reach every bound.
    #[cfg(test)]
    pub(crate) fn for_test_with_issuer(subject: &str, issuer: &str) -> Self {
        Self {
            issuer: Some(issuer.to_owned()),
            ..Self::for_test(subject)
        }
    }

    /// A service-token actor, as [`Self::from_principal`] builds one for a
    /// service-token principal.
    #[cfg(test)]
    pub(crate) fn service_token_for_test(subject: &str) -> Self {
        Self {
            subject: subject.to_owned(),
            issuer: None,
            kind: ActorKind::ServiceToken,
            auth_mode: AuthMethod::ServiceToken.audit_mode(),
        }
    }

    /// A service-token actor that also claims an issuer: a shape no
    /// validator produces, for the tests that prove a store refuses it.
    #[cfg(test)]
    pub(crate) fn service_token_with_issuer_for_test(subject: &str, issuer: &str) -> Self {
        Self {
            issuer: Some(issuer.to_owned()),
            ..Self::service_token_for_test(subject)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(auth_method: AuthMethod, issuer: Option<&str>) -> Principal {
        Principal {
            user_id: "actor@example.test".to_owned(),
            issuer: issuer.map(str::to_owned),
            email: Some("actor@example.test".to_owned()),
            org_id: Some("org-1".to_owned()),
            roles: vec!["admin".to_owned()],
            session_id: "session-1".to_owned(),
            auth_method,
        }
    }

    #[test]
    fn a_principal_is_recorded_by_subject_canonical_issuer_kind_and_auth_mode() {
        let actor = ChangeActor::from_principal(&principal(
            AuthMethod::Cookie,
            Some(" https://idp.example.test/ "),
        ));
        assert_eq!(actor.subject(), "actor@example.test");
        assert_eq!(actor.issuer(), Some("https://idp.example.test"));
        assert_eq!(actor.kind(), ActorKind::Principal);
        assert_eq!(actor.auth_mode(), "session_cookie");
        assert!(actor.is_recordable());

        for (method, mode) in [
            (AuthMethod::Bearer, "bearer_token"),
            (AuthMethod::ClientCertificate, "client_certificate"),
        ] {
            let actor = ChangeActor::from_principal(&principal(method, None));
            assert_eq!(
                (actor.kind(), actor.auth_mode(), actor.issuer()),
                (ActorKind::Principal, mode, None)
            );
            assert!(actor.is_recordable());
        }
    }

    #[test]
    fn a_service_token_and_a_command_are_their_own_kinds() {
        let token = ChangeActor::from_principal(&Principal {
            user_id: "service-token:token_1".to_owned(),
            ..principal(AuthMethod::ServiceToken, None)
        });
        assert_eq!(
            (token.kind(), token.auth_mode(), token.issuer()),
            (ActorKind::ServiceToken, "service_token", None)
        );
        assert!(token.is_recordable());
        // The stores' tests stand in for real principals with these.
        assert_eq!(
            token,
            ChangeActor::service_token_for_test("service-token:token_1")
        );
        assert_eq!(
            ChangeActor::from_principal(&principal(AuthMethod::Bearer, None)),
            ChangeActor::for_test("actor@example.test")
        );

        let command = ChangeActor::system("operator:revoke-jwt");
        assert_eq!(
            (
                command.subject(),
                command.kind(),
                command.auth_mode(),
                command.issuer()
            ),
            ("operator:revoke-jwt", ActorKind::System, "system", None)
        );
        assert!(command.is_recordable());
    }

    #[test]
    fn an_issuer_that_canonicalizes_to_nothing_is_absent() {
        let actor = ChangeActor::from_principal(&principal(AuthMethod::Bearer, Some(" /// ")));
        assert_eq!(actor.issuer(), None);
        assert!(actor.is_recordable());
    }

    #[test]
    fn the_recordable_bounds_are_the_principal_bounds_exactly() {
        let subject = "s".repeat(MAX_PRINCIPAL_SUBJECT_BYTES);
        let issuer = "i".repeat(MAX_PRINCIPAL_ISSUER_BYTES);
        assert!(ChangeActor::for_test_with_issuer(&subject, &issuer).is_recordable());

        for refused in [
            ChangeActor::for_test(""),
            ChangeActor::for_test(&format!("{subject}s")),
            ChangeActor::for_test_with_issuer("subject", ""),
            ChangeActor::for_test_with_issuer("subject", &format!("{issuer}i")),
            // Only a principal has an issuer.
            ChangeActor::service_token_with_issuer_for_test(
                "service-token:token_1",
                "https://idp.example.test",
            ),
        ] {
            assert!(!refused.is_recordable(), "{refused:?}");
        }
    }

    #[test]
    fn kind_and_auth_mode_pairs_are_exactly_the_ones_authentication_produces() {
        let modes = [
            "session_cookie",
            "bearer_token",
            "client_certificate",
            "service_token",
            "system",
        ];
        let agreeing = |kind| {
            modes
                .into_iter()
                .filter(|mode| auth_mode_agrees(kind, mode))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            agreeing(ActorKind::Principal),
            ["session_cookie", "bearer_token", "client_certificate"]
        );
        assert_eq!(agreeing(ActorKind::ServiceToken), ["service_token"]);
        assert_eq!(agreeing(ActorKind::System), ["system"]);
        for (stored, kind) in [
            ("principal", ActorKind::Principal),
            ("service_token", ActorKind::ServiceToken),
            ("system", ActorKind::System),
        ] {
            assert_eq!(kind.as_str(), stored);
            assert_eq!(ActorKind::from_stored(stored), Some(kind));
        }
        assert_eq!(ActorKind::from_stored("bearer_token"), None);
        assert_eq!(ActorKind::from_stored(""), None);
    }
}
