//! Compile a deployment when its inputs are available offline. The mounted
//! resources stay with the bundle. The compiler only needs to know whether
//! its host-routing policy requirement is satisfied.

use std::{
    collections::{BTreeMap, BTreeSet},
    env::VarError,
};

use super::{at_setting, SettingValue, Settings, StandaloneStore, ACKNOWLEDGED_PATH, STORES_PATH};
use crate::{
    bundle::{syntax::Node, BundleDiagnostic, Code, FileName, Profile},
    catalog::{self, Field, Sensitivity},
    compiler::{self, ConfigPlan},
    state_dir::StateDirectory,
};

impl Settings {
    pub(in crate::bundle) fn compile_plan(
        &self,
        profile: Profile,
        bundled_policy: bool,
        document: &Node,
        file: &FileName,
        bound_stores: Option<(&StateDirectory, &[StandaloneStore])>,
    ) -> Result<Option<Box<ConfigPlan>>, Vec<BundleDiagnostic>> {
        let unsupported = |path: &'static str| {
            vec![at_setting(
                Code::NotRepresentable,
                file,
                document,
                path.split('/').skip(1),
            )]
        };
        let mut inputs = BTreeMap::new();
        for setting in &self.own {
            match (setting.member.path, &setting.value) {
                // The profile stage handles acknowledgements separately.
                (ACKNOWLEDGED_PATH, SettingValue::Words(_)) => {}
                (STORES_PATH, SettingValue::Words(stores)) if stores.is_empty() => {}
                (STORES_PATH, SettingValue::Words(_)) => {
                    let Some((directory, stores)) = bound_stores else {
                        return Ok(None);
                    };
                    for store in stores {
                        let name = store
                            .environment()
                            .ok_or_else(|| unsupported(STORES_PATH))?;
                        let path = directory
                            .file(store.file)
                            .into_os_string()
                            .into_string()
                            .map_err(|_| unsupported(STORES_PATH))?;
                        inputs.insert(name, path);
                    }
                }
                // "required" needs host certificate/key/CRL bindings. "off"
                // requires none and is the documented environment default.
                (
                    "/spec/listeners/public/tls"
                    | "/spec/listeners/admin/tls"
                    | "/spec/listeners/public/client_certificate_crl"
                    | "/spec/listeners/admin/client_certificate_crl",
                    SettingValue::Word("off"),
                ) => {}
                (
                    "/spec/admin_login/client_id" | "/spec/admin_login/redirect_uri",
                    SettingValue::Text(_),
                )
                | ("/spec/admin_login/client_secret", SettingValue::Secret(_))
                | (
                    "/spec/listeners/public/tls"
                    | "/spec/listeners/admin/tls"
                    | "/spec/listeners/public/client_certificate_crl"
                    | "/spec/listeners/admin/client_certificate_crl",
                    SettingValue::Word("required"),
                ) => return Ok(None),
                _ => return Err(unsupported(setting.member.path)),
            }
        }
        let bootstrap: BTreeSet<_> = inputs.keys().copied().collect();
        for setting in &self.values {
            let name = setting.field.environment;
            let value = match (&setting.value, setting.field.sensitivity) {
                (SettingValue::Word("postgres"), _) if name == compiler::STATE_BACKEND => {
                    return Ok(None);
                }
                // The empty slots of a structured document must never be
                // handed to the compiler as resolved values.
                (SettingValue::Structured(structured), Sensitivity::MayCarrySecret)
                    if structured.secrets.is_empty() =>
                {
                    structured.environment.to_string()
                }
                (
                    SettingValue::Secret(_) | SettingValue::Structured(_),
                    Sensitivity::MayCarrySecret,
                ) => return Ok(None),
                (value, Sensitivity::Public) => {
                    let Some(text) = value.public_input() else {
                        return Err(unsupported(
                            setting.field.document_path().unwrap_or("/spec"),
                        ));
                    };
                    text
                }
                _ => {
                    return Err(unsupported(
                        setting.field.document_path().unwrap_or("/spec"),
                    ))
                }
            };
            inputs.insert(name, value);
        }
        let development_listen_default =
            profile == Profile::Development && !inputs.contains_key(compiler::LISTEN_ADDR);
        if development_listen_default {
            inputs.insert(
                compiler::LISTEN_ADDR,
                compiler::listeners::DEVELOPMENT_LISTEN_ADDR.to_owned(),
            );
        }
        let compiled = compiler::plan::compile_source(
            |name| inputs.remove(name).ok_or(VarError::NotPresent),
            bundled_policy,
        );
        let mut diagnostics = Vec::new();
        let mut refuse = |field: Option<&'static Field>| {
            let path = if field.is_some_and(|field| bootstrap.contains(field.environment)) {
                STORES_PATH
            } else {
                field.and_then(Field::document_path).unwrap_or("/spec")
            };
            let diagnostic = at_setting(
                Code::InvalidDeploymentSetting,
                file,
                document,
                path.split('/').skip(1),
            );
            if !diagnostics.contains(&diagnostic) {
                diagnostics.push(diagnostic);
            }
        };
        for name in inputs.into_keys() {
            refuse(catalog::field(name));
        }
        let mut plan = match compiled {
            Ok(plan) => plan,
            Err(error) => {
                if error.diagnostics().is_empty() {
                    refuse(None);
                }
                for issue in error.diagnostics() {
                    refuse(issue.variable.and_then(catalog::field));
                }
                return Err(diagnostics);
            }
        };
        if diagnostics.is_empty() {
            plan.mark_bundle_sources(development_listen_default, &bootstrap);
            Ok(Some(Box::new(plan)))
        } else {
            Err(diagnostics)
        }
    }
}
