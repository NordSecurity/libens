use std::{error::Error, process::Command, str};

fn parse_version() -> Result<String, Box<dyn Error>> {
    println!("cargo:rerun-if-changed=.git/HEAD");

    println!(
        "cargo:warning=LIB_VERSION_ENV -> {:?}",
        option_env!("LIB_VERSION")
    );

    let version = match option_env!("LIB_VERSION") {
        Some(v) => v.to_string(),
        None => format!(
            "dev-{}",
            str::from_utf8(
                &Command::new("git")
                    .arg("rev-parse")
                    .arg("HEAD")
                    .output()?
                    .stdout
            )?
        ),
    };

    Ok(version)
}

fn create_winres(version: &str) -> Result<(), Box<dyn Error>> {
    fn parse_ver(parse: &str) -> Option<[u16; 3]> {
        let (major, parse) = parse.split_once('.')?;
        let major: u16 = major.parse().ok()?;

        let (minor, parse) = parse.split_once('.')?;
        let minor: u16 = minor.parse().ok()?;

        let patch: u16 = parse.split(['-', '+']).next()?.parse().ok()?;

        Some([major, minor, patch])
    }

    let version = version.strip_prefix('v').unwrap_or(version);

    let ver_uint = if let Some([major, minor, patch]) = parse_ver(version) {
        ((major as u64) << 48) | ((minor as u64) << 32) | ((patch as u64) << 16)
    } else {
        0
    };

    winresource::WindowsResource::new()
        .set_version_info(winresource::VersionInfo::FILEVERSION, ver_uint)
        .set_version_info(winresource::VersionInfo::PRODUCTVERSION, ver_uint)
        .set("ProductVersion", version)
        .set("FileVersion", version)
        .compile()?;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    uniffi::generate_scaffolding("./ens.udl").expect("failed to generate uniffi scaffolding");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    if target_os.as_str() == "windows" {
        let version = parse_version()?;
        println!("cargo:warning=LIB_VERSION = {version}");

        create_winres(&version)?;
    }

    let pkg_name = env!("CARGO_PKG_NAME");
    let soname = format!("{}.so", pkg_name);

    if target_os == "linux" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,{}", soname);
    } else if target_os == "android" {
        println!(
            "cargo:rustc-cdylib-link-arg=-Wl,-z,max-page-size=16384,-soname,{}",
            soname
        );
    }

    Ok(())
}
