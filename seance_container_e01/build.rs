use std::env;
use std::path::{Path, PathBuf};

fn main() {
    // Invalidate the built crate whenever the wrapper or this script changes.
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");
    // Windows discovers libewf via this env var (see the windows branch below).
    println!("cargo:rerun-if-env-changed=LIBEWF_DIR");

    // Include paths passed to bindgen's clang invocation.
    let mut clang_args: Vec<String> = Vec::new();

    // Prefer pkg-config for portable discovery. On success it emits the
    // cargo:rustc-link-search / cargo:rustc-link-lib directives for us.
    let found = match pkg_config::Config::new().probe("libewf") {
        Ok(lib) => {
            for path in &lib.include_paths {
                clang_args.push(format!("-I{}", path.display()));
            }
            true
        }
        Err(_) => {
            // pkg-config did not locate libewf. On macOS, fall back to the
            // Homebrew install prefix (Apple Silicon or Intel).
            if cfg!(target_os = "macos") {
                let mut located = false;
                for prefix in ["/opt/homebrew", "/usr/local"] {
                    let include_dir = format!("{prefix}/include");
                    if Path::new(&format!("{include_dir}/libewf.h")).exists() {
                        println!("cargo:rustc-link-search={prefix}/lib");
                        clang_args.push(format!("-I{include_dir}"));
                        located = true;
                        break;
                    }
                }
                if located {
                    println!("cargo:rustc-link-lib=ewf");
                }
                located
            } else if cfg!(target_os = "windows") {
                // Windows has no libewf package (not in vcpkg/MSYS2/conan), so
                // CI builds it from libyal source and points here via LIBEWF_DIR,
                // which must contain include/ (headers) and lib/ (libewf.lib).
                match env::var("LIBEWF_DIR") {
                    Ok(dir) => {
                        let include_dir = format!("{dir}/include");
                        if Path::new(&format!("{include_dir}/libewf.h")).exists() {
                            println!("cargo:rustc-link-search=native={dir}/lib");
                            println!("cargo:rustc-link-lib=libewf");
                            clang_args.push(format!("-I{include_dir}"));
                            true
                        } else {
                            false
                        }
                    }
                    Err(_) => false,
                }
            } else {
                false
            }
        }
    };

    if !found {
        // Surface a clear, actionable message, then fail: E01/EWF container
        // support genuinely cannot be built without libewf.
        println!("cargo:warning=libewf development files were not found.");
        println!("cargo:warning=Install the dependency and rebuild:");
        println!("cargo:warning=  Debian/Ubuntu: sudo apt-get install -y libewf-dev pkg-config");
        println!("cargo:warning=  macOS (Homebrew): brew install libewf");
        println!("cargo:warning=  Windows: build libewf from source and set LIBEWF_DIR");
        // This crate has no feature to switch off — it exists to link libewf.
        // The opt-out lives in the crates that depend on it, so point there
        // rather than at a flag that does not exist here.
        panic!(
            "libewf not found. Install `libewf-dev` (Debian/Ubuntu) or `libewf` via Homebrew \
             (macOS), or set LIBEWF_DIR to a source-built libewf (Windows); E01/EWF container \
             support cannot be built without it. To build without E01, drop the `e01` feature \
             of the depending crate (e.g. `cargo build -p seance_cli --no-default-features`); \
             note that `--workspace` builds this crate directly whatever the features say, so \
             add `--exclude seance_container_e01`."
        );
    }

    // Generate bindings against the discovered headers.
    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Only include libewf symbols, not everything the header pulls in.
        .allowlist_function("libewf_.*")
        .allowlist_type("libewf_.*")
        .allowlist_var("LIBEWF_.*")
        // The generated size/align asserts bake in the generating host's libc
        // layout (FILE is pulled in by libewf_*_fprint) and fail on other glibcs.
        .layout_tests(false);

    for arg in &clang_args {
        builder = builder.clang_arg(arg);
    }

    let bindings = builder.generate().expect("Unable to generate bindings");
    let mut text = bindings.to_string();

    // libewf releases after 2014 dropped `*_read_random` in favour of
    // `*_read_buffer_at_offset`, same arguments. The code calls the old names,
    // so alias them when the headers only have the new ones (the Windows build
    // uses libewf 20240506).
    for (old, new) in [
        (
            "libewf_handle_read_random",
            "libewf_handle_read_buffer_at_offset",
        ),
        (
            "libewf_file_entry_read_random",
            "libewf_file_entry_read_buffer_at_offset",
        ),
    ] {
        if !text.contains(&format!("fn {old}(")) && text.contains(&format!("fn {new}(")) {
            text.push_str(&format!("\npub use self::{new} as {old};\n"));
        }
    }

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    std::fs::write(out_path.join("bindings.rs"), text).expect("Couldn't write bindings!");
}
