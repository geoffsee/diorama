//! Independently hand-encoded fixtures from the official API field numbers.

use diorama_containerd_api::containerd::services::{
    content::v1::{WriteAction, WriteContentRequest},
    images::v1::UpdateImageRequest,
};
use prost::Message;

#[test]
fn empty_write_request_preserves_stat_zero_instead_of_assuming_write() {
    // The upstream enum assigns STAT=0 and WRITE=1, despite prose calling WRITE the default.
    let request = WriteContentRequest::decode(&[][..]).expect("empty protobuf is valid");
    assert_eq!(request.action(), WriteAction::Stat);
}

#[test]
fn commit_preserves_raw_archive_bytes_and_reference() {
    // action=2, ref="imp", total=3, data=[0x00,0xff,0x0a]. No Rust encoder builds this fixture.
    let wire = [
        0x08, 0x02, 0x12, 0x03, b'i', b'm', b'p', 0x18, 0x03, 0x32, 0x03, 0x00, 0xff, 0x0a,
    ];
    let request = WriteContentRequest::decode(&wire[..]).expect("valid commit protobuf");
    assert_eq!(request.action(), WriteAction::Commit);
    assert_eq!(request.r#ref, "imp");
    assert_eq!(request.total, 3);
    assert_eq!(request.data, [0x00, 0xff, 0x0a]);
}

#[test]
fn preserves_unknown_write_action_for_explicit_validation() {
    let request = WriteContentRequest::decode(&[0x08, 0x11][..]).expect("valid unknown enum value");
    assert_eq!(request.action, 17);
    assert!(WriteAction::try_from(request.action).is_err());
}

#[test]
fn distinguishes_absent_image_update_mask_from_present_empty_mask() {
    let absent = UpdateImageRequest::decode(&[][..]).expect("empty protobuf is valid");
    // update_mask is field 2; an empty message remains explicitly present.
    let present = UpdateImageRequest::decode(&[0x12, 0x00][..]).expect("valid present mask");
    assert!(absent.update_mask.is_none());
    assert!(
        present
            .update_mask
            .is_some_and(|mask| mask.paths.is_empty())
    );
}
