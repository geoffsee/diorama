//! Wire fixtures are hand-encoded from the official CRI field numbers, not Rust encoding.

use diorama_cri::runtime::v1::{CgroupDriver, RuntimeConfigResponse};
use prost::Message;

#[test]
fn preserves_absent_linux_configuration_instead_of_inventing_systemd() {
    let response = RuntimeConfigResponse::decode(&[][..]).expect("empty protobuf is valid");
    assert!(response.linux.is_none());
}

#[test]
fn distinguishes_present_zero_driver_from_absent_configuration() {
    // RuntimeConfigResponse.linux is message field 1; length zero is a present empty message.
    let response = RuntimeConfigResponse::decode(&[0x0a, 0x00][..]).expect("valid Linux message");
    let linux = response
        .linux
        .expect("Linux message was present on the wire");
    assert_eq!(linux.cgroup_driver(), CgroupDriver::Systemd);
}

#[test]
fn preserves_unknown_driver_number_for_caller_validation() {
    // Nested LinuxRuntimeConfiguration.cgroup_driver is enum field 1, with unknown value 17.
    let response = RuntimeConfigResponse::decode(&[0x0a, 0x02, 0x08, 0x11][..])
        .expect("unknown enum numbers are legal protobuf");
    let linux = response
        .linux
        .expect("Linux message was present on the wire");
    assert_eq!(linux.cgroup_driver, 17);
    assert!(CgroupDriver::try_from(linux.cgroup_driver).is_err());
}
