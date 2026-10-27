//! Kubernetes request path parsing.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    Health,
    Version,
    ApiVersions,
    CoreDiscovery,
    ApiGroupList,
    ApiGroup { group: String },
    GroupDiscovery { group: String, version: String },
    OpenApiV2,
    OpenApiV3Index,
    OpenApiV3Core,
    OpenApiV3StorageV1,
    OpenApiV3Group { group: String, version: String },
    OpenIdConfig,
    OpenIdJwks,
    Resource(ResourcePath),
    NotFound,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResourcePath {
    pub(crate) group: String,
    pub(crate) version: String,
    pub(crate) namespace: Option<String>,
    pub(crate) resource: String,
    pub(crate) name: Option<String>,
    /// Trailing segment after the name, such as `log`, `status`, or `proxy/<path>`.
    pub(crate) subresource: Option<String>,
    pub(crate) trailing_slash: bool,
}

pub(crate) fn parse(path: &str) -> Route {
    let trailing_slash = path.ends_with('/');
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    match parts.as_slice() {
        ["healthz" | "livez" | "readyz"] => Route::Health,
        ["version"] => Route::Version,
        [".well-known", "openid-configuration"] => Route::OpenIdConfig,
        ["openid", "v1", "jwks"] => Route::OpenIdJwks,
        ["openapi", "v2"] => Route::OpenApiV2,
        ["openapi", "v3"] => Route::OpenApiV3Index,
        ["openapi", "v3", "api", "v1"] => Route::OpenApiV3Core,
        ["openapi", "v3", "apis", "storage.k8s.io", "v1"] => Route::OpenApiV3StorageV1,
        ["openapi", "v3", "apis", group, version] => Route::OpenApiV3Group {
            group: (*group).to_string(),
            version: (*version).to_string(),
        },
        ["api"] => Route::ApiVersions,
        ["api", "v1"] => Route::CoreDiscovery,
        ["api", "v1", rest @ ..] => parse_resource("", "v1", rest, trailing_slash),
        ["apis"] => Route::ApiGroupList,
        ["apis", group] => Route::ApiGroup {
            group: (*group).to_string(),
        },
        ["apis", group, version] => Route::GroupDiscovery {
            group: (*group).to_string(),
            version: (*version).to_string(),
        },
        ["apis", group, version, rest @ ..] if is_api_version(version) => {
            parse_resource(group, version, rest, trailing_slash)
        },
        _ => Route::NotFound,
    }
}

fn is_api_version(version: &str) -> bool {
    let mut chars = version.chars();
    matches!(chars.next(), Some('v')) && chars.next().is_some_and(|ch| ch.is_ascii_digit())
}

fn parse_resource(group: &str, version: &str, parts: &[&str], trailing_slash: bool) -> Route {
    if parts.is_empty() {
        return Route::NotFound;
    }
    if parts[0] == "proxy" && parts.get(1) == Some(&"namespaces") && parts.len() >= 5 {
        let sub = if parts.len() > 5 {
            format!("proxy/{}", parts[5..].join("/"))
        } else {
            "proxy".to_string()
        };
        return Route::Resource(ResourcePath {
            group: group.to_string(),
            version: version.to_string(),
            namespace: Some(parts[2].to_string()),
            resource: parts[3].to_string(),
            name: Some(parts[4].to_string()),
            subresource: Some(sub),
            trailing_slash,
        });
    }
    let (namespace, resource, name, subresource) = if parts[0] == "namespaces" && parts.len() >= 3 {
        if parts.len() > 5 {
            if parts.get(4) == Some(&"proxy") {
                let sub = parts[4..].join("/");
                (
                    Some(parts[1].to_string()),
                    parts[2].to_string(),
                    Some(parts[3].to_string()),
                    Some(sub),
                )
            } else {
                return Route::NotFound;
            }
        } else {
            let name = parts.get(3).map(ToString::to_string);
            let subresource = parts.get(4).map(ToString::to_string);
            (
                Some(parts[1].to_string()),
                parts[2].to_string(),
                name,
                subresource,
            )
        }
    } else if parts.len() <= 3 {
        let name = parts.get(1).map(ToString::to_string);
        let subresource = parts.get(2).map(ToString::to_string);
        (None, parts[0].to_string(), name, subresource)
    } else {
        return Route::NotFound;
    };
    Route::Resource(ResourcePath {
        group: group.to_string(),
        version: version.to_string(),
        namespace,
        resource,
        name,
        subresource,
        trailing_slash,
    })
}

/// Whether the client offers `v2` aggregated discovery (`apidiscovery.k8s.io`).
/// Matches clients that ask for aggregated discovery (`g=apidiscovery.k8s.io`
/// with `v=v2` or `v=v2beta1` and `as=APIGroupDiscoveryList`).
pub(crate) fn aggregated_discovery_version(accept: Option<&str>) -> Option<&'static str> {
    let accept = accept?;
    for entry in accept.split(',') {
        let mut group_ok = false;
        let mut as_discovery = false;
        let mut version: Option<&'static str> = None;
        for param in entry.split(';') {
            let p = param.trim().replace(' ', "");
            if p == "g=apidiscovery.k8s.io" {
                group_ok = true;
            } else if p == "as=APIGroupDiscoveryList" {
                as_discovery = true;
            } else if p == "v=v2" {
                version = Some("v2");
            } else if p == "v=v2beta1" {
                version = Some("v2beta1");
            }
        }
        if group_ok && (as_discovery || version.is_some()) {
            return Some(version.unwrap_or("v2"));
        }
    }
    None
}

#[cfg(test)]
pub(crate) fn wants_aggregated_discovery(accept: Option<&str>) -> bool {
    aggregated_discovery_version(accept).is_some()
}

#[cfg(test)]
mod tests {
    use super::{Route, parse, wants_aggregated_discovery};

    #[test]
    fn parses_core_namespace_and_namespaced_pod() {
        assert!(
            matches!(parse("/api/v1/namespaces"), Route::Resource(path) if path.resource == "namespaces" && path.name.is_none())
        );
        assert!(matches!(
            parse("/api/v1/namespaces/demo"),
            Route::Resource(path) if path.resource == "namespaces" && path.name.as_deref() == Some("demo")
        ));
        assert!(matches!(
            parse("/api/v1/namespaces/demo/pods/nginx"),
            Route::Resource(path)
                if path.namespace.as_deref() == Some("demo")
                    && path.resource == "pods"
                    && path.name.as_deref() == Some("nginx")
                    && path.subresource.is_none()
        ));
    }

    #[test]
    fn parses_subresources_and_openapi() {
        assert!(matches!(
            parse("/api/v1/namespaces/default/pods/hello/log"),
            Route::Resource(path)
                if path.resource == "pods"
                    && path.name.as_deref() == Some("hello")
                    && path.subresource.as_deref() == Some("log")
        ));
        assert!(matches!(
            parse("/api/v1/nodes/n1/status"),
            Route::Resource(path)
                if path.resource == "nodes" && path.subresource.as_deref() == Some("status")
        ));
        assert!(matches!(
            parse("/api/v1/namespaces/default/pods/hello/log/extra"),
            Route::NotFound
        ));
        assert!(matches!(
            parse("/api/v1/namespaces/default/pods/wheezy:80/proxy/results/udp"),
            Route::Resource(path)
                if path.resource == "pods"
                    && path.name.as_deref() == Some("wheezy:80")
                    && path.subresource.as_deref() == Some("proxy/results/udp")
        ));
        assert!(matches!(parse("/openapi/v3"), Route::OpenApiV3Index));
        assert!(matches!(parse("/openapi/v3/api/v1"), Route::OpenApiV3Core));
        assert!(matches!(
            parse("/openapi/v3/apis/storage.k8s.io/v1"),
            Route::OpenApiV3StorageV1
        ));
        assert!(matches!(
            parse("/openapi/v3/apis/apps/v1"),
            Route::OpenApiV3Group { group, version }
                if group == "apps" && version == "v1"
        ));
        assert!(matches!(parse("/openapi/v2"), Route::OpenApiV2));
    }

    #[test]
    fn aggregated_discovery_requires_explicit_v2() {
        // Modern kubectl/client-go and kube offer v2.
        assert!(wants_aggregated_discovery(Some(
            "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList,application/json"
        )));
        assert!(wants_aggregated_discovery(Some(
            "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList,application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList,application/json"
        )));
        // Extra parameters (profiling peers) do not opt out.
        assert!(wants_aggregated_discovery(Some(
            "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList;profile=nopeer"
        )));
        // Plain JSON gets legacy, but v2beta1 is accepted.
        assert!(!wants_aggregated_discovery(None));
        assert!(!wants_aggregated_discovery(Some("application/json")));
        assert!(wants_aggregated_discovery(Some(
            "application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList,application/json"
        )));
    }

    #[test]
    fn parses_discovery_and_apps() {
        assert!(matches!(parse("/api"), Route::ApiVersions));
        assert!(matches!(parse("/api/v1"), Route::CoreDiscovery));
        assert!(matches!(parse("/apis"), Route::ApiGroupList));
        assert!(matches!(
            parse("/apis/apps/v1/namespaces/demo/deployments"),
            Route::Resource(path) if path.group == "apps" && path.resource == "deployments"
        ));
        assert!(matches!(parse("/nope"), Route::NotFound));
    }
}
