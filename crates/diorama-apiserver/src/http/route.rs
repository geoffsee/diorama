//! Kubernetes request path parsing.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    Health,
    Version,
    ApiVersions,
    CoreDiscovery,
    ApiGroupList,
    GroupDiscovery { group: String, version: String },
    OpenApiV3Index,
    OpenApiV3Core,
    OpenApiV3StorageV1,
    OpenApiV3Group { group: String, version: String },
    Resource(ResourcePath),
    NotFound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResourcePath {
    pub(crate) group: String,
    pub(crate) namespace: Option<String>,
    pub(crate) resource: String,
    pub(crate) name: Option<String>,
    /// Trailing segment after the name, such as `log` or `status`.
    pub(crate) subresource: Option<String>,
}

pub(crate) fn parse(path: &str) -> Route {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    match parts.as_slice() {
        ["healthz" | "livez" | "readyz"] => Route::Health,
        ["version"] => Route::Version,
        ["openapi", "v3"] => Route::OpenApiV3Index,
        ["openapi", "v3", "api", "v1"] => Route::OpenApiV3Core,
        ["openapi", "v3", "apis", "storage.k8s.io", "v1"] => Route::OpenApiV3StorageV1,
        ["openapi", "v3", "apis", group, version] => Route::OpenApiV3Group {
            group: (*group).to_string(),
            version: (*version).to_string(),
        },
        ["api"] => Route::ApiVersions,
        ["api", "v1"] => Route::CoreDiscovery,
        ["api", "v1", rest @ ..] => parse_resource("", rest),
        ["apis"] => Route::ApiGroupList,
        ["apis", group, version] => Route::GroupDiscovery {
            group: (*group).to_string(),
            version: (*version).to_string(),
        },
        ["apis", group, "v1", rest @ ..] => parse_resource(group, rest),
        _ => Route::NotFound,
    }
}

fn parse_resource(group: &str, parts: &[&str]) -> Route {
    if parts.is_empty() {
        return Route::NotFound;
    }
    let (namespace, resource, name, subresource) = if parts[0] == "namespaces" && parts.len() >= 3 {
        if parts.len() > 5 {
            return Route::NotFound;
        }
        let name = parts.get(3).map(ToString::to_string);
        let subresource = parts.get(4).map(ToString::to_string);
        (
            Some(parts[1].to_string()),
            parts[2].to_string(),
            name,
            subresource,
        )
    } else if parts.len() <= 3 {
        let name = parts.get(1).map(ToString::to_string);
        let subresource = parts.get(2).map(ToString::to_string);
        (None, parts[0].to_string(), name, subresource)
    } else {
        return Route::NotFound;
    };
    Route::Resource(ResourcePath {
        group: group.to_string(),
        namespace,
        resource,
        name,
        subresource,
    })
}

/// Whether the client offers `v2` aggregated discovery (`apidiscovery.k8s.io`).
///
/// Only `v2` is served. Clients that offer solely `v2beta1` (client-go older
/// than 1.28, as vendored by Sonobuoy) fail to parse a `v2` response, so they
/// receive legacy discovery, which is also in their `Accept` list.
pub(crate) fn wants_aggregated_discovery(accept: Option<&str>) -> bool {
    let Some(accept) = accept else {
        return false;
    };
    accept.split(',').any(|entry| {
        let mut group_ok = false;
        let mut version_v2 = false;
        for param in entry.split(';').skip(1) {
            match param.trim() {
                "g=apidiscovery.k8s.io" => group_ok = true,
                "v=v2" => version_v2 = true,
                _ => {},
            }
        }
        group_ok && version_v2
    })
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
        assert!(matches!(parse("/openapi/v2"), Route::NotFound));
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
        // Plain JSON and v2beta1-only clients (Sonobuoy's client-go) get legacy.
        assert!(!wants_aggregated_discovery(None));
        assert!(!wants_aggregated_discovery(Some("application/json")));
        assert!(!wants_aggregated_discovery(Some(
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
