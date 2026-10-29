use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyUsagePurpose};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    Apiserver,
    Kubelet,
    ControllerManager,
    KubeProxy,
    Admin,
    Webhook,
    RequestHeaderClient,
    D2kServer,
    D2kClient,
    DatastoreServer,
    DatastoreClient,
}

#[allow(clippy::too_many_lines)]
pub fn profile(component: Component) -> CertificateParams {
    match component {
        Component::Apiserver => {
            let mut params = CertificateParams::new(vec!["kube-apiserver".to_string()]).unwrap();
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, "Kubernetes");
            // DNS and IPs are dynamically injected usually, but the base profile can be here.
            params
        },
        Component::Kubelet => {
            let mut params =
                CertificateParams::new(vec!["system:node:fixture-node".to_string()]).unwrap();
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, "system:nodes");
            params
        },
        Component::ControllerManager => {
            let mut params =
                CertificateParams::new(vec!["system:kube-controller-manager".to_string()]).unwrap();
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            params.distinguished_name.push(
                rcgen::DnType::OrganizationName,
                "system:kube-controller-manager",
            );
            params
        },
        Component::KubeProxy => {
            let mut params = CertificateParams::new(vec!["system:kube-proxy".to_string()]).unwrap();
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "system:kube-proxy");
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, "system:kube-proxy");
            params
        },
        Component::Admin => {
            let mut params = CertificateParams::new(vec!["diorama-admin".to_string()]).unwrap();
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, "system:masters");
            params
        },
        Component::Webhook => {
            let mut params = CertificateParams::new(vec!["diorama-webhook".to_string()]).unwrap();
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, "system:masters");
            params
        },
        Component::RequestHeaderClient => {
            let mut params = CertificateParams::new(vec!["system:auth-proxy".to_string()]).unwrap();
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, "system:auth-proxy");
            params
        },
        Component::D2kServer => {
            let mut params = CertificateParams::new(vec!["d2k".to_string()]).unwrap();
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, "diorama");
            params
        },
        Component::D2kClient => {
            let mut params = CertificateParams::new(vec!["d2k-client".to_string()]).unwrap();
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, "diorama");
            params
        },
        Component::DatastoreServer => {
            let mut params = CertificateParams::new(vec!["datastore-server".to_string()]).unwrap();
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, "diorama");
            params
        },
        Component::DatastoreClient => {
            let mut params = CertificateParams::new(vec!["datastore-client".to_string()]).unwrap();
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, "diorama");
            params
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{Component, profile};
    use rcgen::{DnType, DnValue};

    #[test]
    fn kube_proxy_common_name_matches_rbac_user() {
        let params = profile(Component::KubeProxy);
        assert_eq!(
            params.distinguished_name.get(&DnType::CommonName),
            Some(&DnValue::Utf8String("system:kube-proxy".to_string()))
        );
    }
}
