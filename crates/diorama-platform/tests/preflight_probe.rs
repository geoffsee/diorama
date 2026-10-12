use diorama_platform::preflight_probe::{collect_supplemental, probe_ports};
use diorama_platform::{PlatformError, ProbeLimits};

#[test]
fn invalid_limits_fail_before_filesystem_observation() {
    for limits in [
        ProbeLimits {
            bytes_per_file: 0,
            ..ProbeLimits::default()
        },
        ProbeLimits {
            bytes_per_file: 4 * 1024 * 1024 + 1,
            ..ProbeLimits::default()
        },
        ProbeLimits {
            directory_entries: 16385,
            ..ProbeLimits::default()
        },
        ProbeLimits {
            requested_paths: 257,
            ..ProbeLimits::default()
        },
    ] {
        assert_eq!(
            collect_supplemental(limits),
            Err(PlatformError::InvalidLimits)
        );
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_host_does_not_attempt_fallback_io() {
    assert_eq!(
        collect_supplemental(ProbeLimits::default()),
        Err(PlatformError::UnsupportedHost)
    );
    assert_eq!(probe_ports(true), Err(PlatformError::UnsupportedHost));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "opens fixed wildcard ports; disposable Linux namespace only"]
fn disposable_wildcard_ports_detect_both_families_and_release_all_owned_sockets() {
    use diorama_platform::{Observation, preflight::PortAvailability};
    use rustix::net::{self, AddressFamily, SocketFlags, SocketType};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, TcpListener};
    assert_eq!(
        std::env::var("diorama_PREFLIGHT_DISPOSABLE").as_deref(),
        Ok("1")
    );
    assert!(std::path::Path::new("/.dockerenv").exists());
    assert_eq!(rustix::process::geteuid().as_raw(), 65532);
    let available = Observation::Present(PortAvailability::Available);
    let failed = Observation::Present(PortAvailability::BindFailed);
    assert_eq!(probe_ports(true).unwrap(), [available; 4]);
    println!("diorama_PREFLIGHT_PORTS free_all available");
    for (slot, port) in [2379, 6443, 10443, 6060].into_iter().enumerate() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).unwrap();
        let mut expected = [available; 4];
        expected[slot] = failed;
        assert_eq!(probe_ports(true).unwrap(), expected);
        // Failed probe must never close or replace the competing listener.
        assert_eq!(listener.local_addr().unwrap().port(), port);
        if port == 6060 {
            let values = probe_ports(false).unwrap();
            assert_eq!(&values[..3], &[available; 3]);
            assert!(matches!(values[3], Observation::Unknown(_)));
            println!("diorama_PREFLIGHT_PORTS pprof_disabled unprobed");
        }
        drop(listener);
        assert_eq!(probe_ports(true).unwrap(), [available; 4]);
        let rebound = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).unwrap();
        drop(rebound);
        println!("diorama_PREFLIGHT_PORTS ipv4_{port} conflict_then_rebind");
        let listener = net::socket_with(
            AddressFamily::INET6,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        net::sockopt::set_ipv6_v6only(&listener, true).unwrap();
        net::bind(
            &listener,
            &SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0),
        )
        .unwrap();
        net::listen(&listener, 1).unwrap();
        assert_eq!(probe_ports(true).unwrap(), expected);
        drop(listener);
        assert_eq!(probe_ports(true).unwrap(), [available; 4]);
        println!("diorama_PREFLIGHT_PORTS ipv6_{port} conflict_then_rebind");
    }
    // Actual supplemental discovery remains an observation even on this artificial host.
    let _ = collect_supplemental(ProbeLimits::default()).unwrap();
}
