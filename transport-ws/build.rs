// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

fn main() -> std::io::Result<()> {
    let root =
        std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).canonicalize()?;
    let package = std::env::var("CARGO_PKG_NAME").unwrap();
    let mut source =
        String::from("#[doc(hidden)]\n#[macro_export]\nmacro_rules! __busbar_context_tests {\n");
    type Source = (&'static str, &'static str, &'static str);
    let contexts: &[(&str, &[Source])] = &[
        (
            "listener_session",
            &[("inline", "tests/root/listener_session.rs", "")],
        ),
        (
            "boot_session_locate",
            &[("inline", "tests/root/boot_locate.rs", "")],
        ),
    ];
    for (context, entries) in contexts {
        source.push_str(&format!("    ({context}, {package:?}) => {{\n"));
        for (mode, relative, module) in *entries {
            let path = root.join(relative);
            if path.canonicalize()? != path {
                return Err(std::io::Error::other(
                    "test source must remain within the owner's declared path",
                ));
            }
            println!("cargo::rerun-if-changed={}", path.display());
            if *mode == "inline" {
                source.push_str(&format!("        include!({path:?});\n"));
            } else {
                source.push_str(&format!(
                    "        #[path = {path:?}]\n        mod {module};\n"
                ));
            }
        }
        source.push_str("    };\n");
    }
    source.push_str("}\n");
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(output.join("context_test_source.rs"), source)
}
