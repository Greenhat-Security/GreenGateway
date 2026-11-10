use super::{at_setting, BundleDiagnostic, Code, FileName, Node, SettingValue, Settings};
use crate::{
    bundle::Profile,
    catalog::{self, Domain, Field},
    compiler::{
        self,
        listeners::{
            check_document, DocumentListenerIntent, DocumentListenerRefusal,
            DEVELOPMENT_LISTEN_ADDR,
        },
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    env::VarError,
};

impl Settings {
    pub(in crate::bundle) fn listener_diagnostics(
        &self,
        profile: Profile,
        document: &Node,
        file: &FileName,
    ) -> Vec<BundleDiagnostic> {
        let mut refused = BTreeSet::new();
        let mut inputs = self.listener_inputs(profile, &mut refused);
        let intent = self.listener_intent();
        refused.extend(check_document(
            |name| inputs.remove(name).ok_or(VarError::NotPresent),
            intent,
            profile == Profile::Development,
        ));
        refused.extend(
            inputs
                .into_keys()
                .map(DocumentListenerRefusal::Configuration),
        );
        listener_issues(refused, file, document)
    }

    fn listener_inputs(
        &self,
        profile: Profile,
        refused: &mut BTreeSet<DocumentListenerRefusal>,
    ) -> BTreeMap<&'static str, String> {
        let mut inputs = BTreeMap::new();
        for setting in self
            .values
            .iter()
            .filter(|setting| setting.field.domain == Domain::Listeners)
        {
            let value = match &setting.value {
                SettingValue::Text(value) => value.clone(),
                SettingValue::Word(value) => (*value).to_owned(),
                SettingValue::Integer(value) => value.to_string(),
                _ => {
                    refused.insert(DocumentListenerRefusal::Configuration(
                        setting.field.environment,
                    ));
                    continue;
                }
            };
            inputs.insert(setting.field.environment, value);
        }
        let development = profile == Profile::Development;
        if development {
            inputs
                .entry(compiler::LISTEN_ADDR)
                .or_insert_with(|| DEVELOPMENT_LISTEN_ADDR.to_owned());
        }
        inputs
    }

    fn listener_intent(&self) -> DocumentListenerIntent {
        let required = |path| matches!(self.own_value(path), Some(SettingValue::Word("required")));
        DocumentListenerIntent {
            public_tls: required("/spec/listeners/public/tls"),
            public_crl: required("/spec/listeners/public/client_certificate_crl"),
            admin_tls: required("/spec/listeners/admin/tls"),
            admin_crl: required("/spec/listeners/admin/client_certificate_crl"),
        }
    }

    /// Bind each TLS mount only when the pinned deployment requests it.
    /// Cert/key list pairing and mTLS configuration use the serving parser.
    pub(in crate::bundle) fn listener_bootstrap(
        &self,
        profile: Profile,
        document: &Node,
        file: &FileName,
        mut get_var: impl FnMut(&str) -> Result<String, VarError>,
    ) -> Result<BTreeMap<&'static str, String>, Vec<BundleDiagnostic>> {
        let mut refused = BTreeSet::new();
        let mut inputs = self.listener_inputs(profile, &mut refused);
        let intent = self.listener_intent();
        let client_ca = |setting| {
            matches!(
                inputs.get(setting).map(String::as_str),
                Some("optional" | "required")
            )
        };
        let mounts = [
            (compiler::TLS_CERT_FILE, intent.public_tls),
            (compiler::TLS_KEY_FILE, intent.public_tls),
            (
                compiler::CLIENT_CERT_CA_FILE,
                client_ca(compiler::CLIENT_CERT_MODE),
            ),
            (compiler::CLIENT_CERT_CRL_FILE, intent.public_crl),
            (compiler::ADMIN_TLS_CERT_FILE, intent.admin_tls),
            (compiler::ADMIN_TLS_KEY_FILE, intent.admin_tls),
            (
                compiler::ADMIN_CLIENT_CERT_CA_FILE,
                client_ca(compiler::ADMIN_CLIENT_CERT_MODE),
            ),
            (compiler::ADMIN_CLIENT_CERT_CRL_FILE, intent.admin_crl),
        ];
        let mut bound = BTreeMap::new();
        for (name, required) in mounts {
            match (required, get_var(name)) {
                (false, Err(VarError::NotPresent)) => {}
                (true, Ok(value)) if !value.trim().is_empty() => {
                    bound.insert(name, value);
                }
                _ => {
                    refused.insert(DocumentListenerRefusal::Configuration(name));
                }
            }
        }
        refused.extend(
            compiler::listeners::check_mounted(|name| {
                inputs
                    .remove(name)
                    .or_else(|| bound.get(name).cloned())
                    .ok_or(VarError::NotPresent)
            })
            .into_iter()
            .map(DocumentListenerRefusal::Configuration),
        );
        refused.extend(
            inputs
                .into_keys()
                .map(DocumentListenerRefusal::Configuration),
        );
        if refused.is_empty() {
            Ok(bound)
        } else {
            Err(listener_issues(refused, file, document))
        }
    }
}

fn listener_issues(
    refused: BTreeSet<DocumentListenerRefusal>,
    file: &FileName,
    document: &Node,
) -> Vec<BundleDiagnostic> {
    let mut issues = Vec::new();
    for refusal in refused {
        let (code, setting) = match refusal {
            DocumentListenerRefusal::Configuration(name) => (Code::InvalidListenerSetting, name),
            DocumentListenerRefusal::DevelopmentBind(name) => {
                (Code::DevelopmentListenerNotLoopback, name)
            }
        };
        let path = mount_path(setting)
            .or_else(|| catalog::field(setting).and_then(Field::document_path))
            .unwrap_or("/spec/listeners");
        let issue = at_setting(code, file, document, path.split('/').skip(1));
        if !issues.contains(&issue) {
            issues.push(issue);
        }
    }
    issues
}

pub(super) fn mount_path(setting: &str) -> Option<&'static str> {
    Some(match setting {
        compiler::TLS_CERT_FILE | compiler::TLS_KEY_FILE => "/spec/listeners/public/tls",
        compiler::ADMIN_TLS_CERT_FILE | compiler::ADMIN_TLS_KEY_FILE => "/spec/listeners/admin/tls",
        compiler::CLIENT_CERT_CA_FILE => "/spec/listeners/public/client_certificates",
        compiler::ADMIN_CLIENT_CERT_CA_FILE => "/spec/listeners/admin/client_certificates",
        compiler::CLIENT_CERT_CRL_FILE => "/spec/listeners/public/client_certificate_crl",
        compiler::ADMIN_CLIENT_CERT_CRL_FILE => "/spec/listeners/admin/client_certificate_crl",
        _ => return None,
    })
}
