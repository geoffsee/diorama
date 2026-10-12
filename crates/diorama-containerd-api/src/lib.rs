//! Client bindings for the official containerd API v1.10.0 module.
//!
//! Managed runtime import operations use these services alongside CRI. Callers must
//! attach the `containerd-namespace` gRPC metadata for their owned namespace; these
//! bindings do not choose a namespace, import images, or adopt external runtime state.
//! Regeneration is explicit; ordinary builds consume committed source.

// Preserve upstream comments and tonic's nested RPC templates in generated source.
#[allow(clippy::doc_markdown, clippy::excessive_nesting)]
pub mod containerd {
    pub mod services {
        pub mod containers {
            pub mod v1 {
                include!("generated/containerd.services.containers.v1.rs");
            }
        }
        pub mod content {
            pub mod v1 {
                include!("generated/containerd.services.content.v1.rs");
            }
        }
        pub mod diff {
            pub mod v1 {
                include!("generated/containerd.services.diff.v1.rs");
            }
        }
        pub mod events {
            pub mod v1 {
                include!("generated/containerd.services.events.v1.rs");
            }
        }
        pub mod images {
            pub mod v1 {
                include!("generated/containerd.services.images.v1.rs");
            }
        }
        pub mod leases {
            pub mod v1 {
                include!("generated/containerd.services.leases.v1.rs");
            }
        }
        pub mod namespaces {
            pub mod v1 {
                include!("generated/containerd.services.namespaces.v1.rs");
            }
        }
        pub mod snapshots {
            pub mod v1 {
                include!("generated/containerd.services.snapshots.v1.rs");
            }
        }
        pub mod tasks {
            pub mod v1 {
                include!("generated/containerd.services.tasks.v1.rs");
            }
        }
        pub mod transfer {
            pub mod v1 {
                include!("generated/containerd.services.transfer.v1.rs");
            }
        }
        pub mod version {
            pub mod v1 {
                include!("generated/containerd.services.version.v1.rs");
            }
        }
    }
    pub mod types {
        include!("generated/containerd.types.rs");
    }
    pub mod v1 {
        pub mod types {
            include!("generated/containerd.v1.types.rs");
        }
    }
}
