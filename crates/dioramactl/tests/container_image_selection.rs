use dioramactl::container_image::select_container_image;
use dioramactl::contract::InstallOptions;

#[test]
fn test_select_container_image_default() {
    let options = InstallOptions {
        version: "v1.2.3".into(),
        ..InstallOptions::default()
    };

    let image = select_container_image(&options, None).unwrap();
    assert_eq!(image, "ghcr.io/geoffsee/diorama:v1.2.3");
}

#[test]
fn test_select_container_image_override() {
    let options = InstallOptions {
        version: "v1.2.3".into(),
        container_image: Some("custom/image:latest".into()),
        ..InstallOptions::default()
    };

    let image = select_container_image(&options, None).unwrap();
    assert_eq!(image, "custom/image:latest");
}
