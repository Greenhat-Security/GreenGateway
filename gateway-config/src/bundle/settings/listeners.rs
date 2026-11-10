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
        let mut inputs = BTreeMap::new();
        let mut refused = BTreeSet::new();
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
        let required = |path| matches!(self.own_value(path), Some(SettingValue::Word("required")));
        let intent = DocumentListenerIntent {
            public_tls: required("/spec/listeners/public/tls"),
            public_crl: required("/spec/listeners/public/client_certificate_crl"),
            admin_tls: required("/spec/listeners/admin/tls"),
            admin_crl: required("/spec/listeners/admin/client_certificate_crl"),
        };
        refused.extend(check_document(
            |name| inputs.remove(name).ok_or(VarError::NotPresent),
            intent,
            development,
        ));
        refused.extend(
            inputs
                .into_keys()
                .map(DocumentListenerRefusal::Configuration),
        );
        refused
            .into_iter()
            .map(|refusal| {
                let (code, setting) = match refusal {
                    DocumentListenerRefusal::Configuration(name) => {
                        (Code::InvalidListenerSetting, name)
                    }
                    DocumentListenerRefusal::DevelopmentBind(name) => {
                        (Code::DevelopmentListenerNotLoopback, name)
                    }
                };
                let path = match setting {
                    compiler::ADMIN_TLS_KEY_FILE => "/spec/listeners/admin/tls",
                    compiler::CLIENT_CERT_CRL_FILE => {
                        "/spec/listeners/public/client_certificate_crl"
                    }
                    compiler::ADMIN_CLIENT_CERT_CRL_FILE => {
                        "/spec/listeners/admin/client_certificate_crl"
                    }
                    name => catalog::field(name)
                        .and_then(Field::document_path)
                        .unwrap_or("/spec/listeners"),
                };
                at_setting(code, file, document, path.split('/').skip(1))
            })
            .collect()
    }
}
