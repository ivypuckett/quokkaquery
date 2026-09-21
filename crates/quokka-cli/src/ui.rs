//! `quokka ui` — starting the window, and the one thing about it that is the CLI's
//! problem rather than the UI's.
//!
//! **The window must not be started from inside a tokio runtime.** `quokka-ui` takes
//! iced with its `tokio` feature, which makes iced's executor a
//! `tokio::runtime::Runtime` that iced builds for itself — and building one inside
//! another is a panic, not a slowdown. Every other subcommand runs on a runtime `main`
//! creates; this one is dispatched before that runtime exists and gets iced's instead.
//!
//! Which is also why nothing is opened here. The audit log, the config file and the
//! spool directory are all opened by the window's first task, so every sqlx pool belongs
//! to the runtime that will drive it.

use anyhow::Result;

/// Which renderer §7 asks for: `wgpu` by default, `tiny-skia` selectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "lower")]
pub enum RendererArg {
    /// wgpu, falling back to software by itself if the GPU cannot be reached.
    Gpu,
    /// tiny-skia. For a remote desktop or a VM where GPU access is unreliable enough
    /// that failing over once per start is not good enough.
    Software,
}

#[cfg(feature = "ui")]
pub fn run(
    config_path: Option<std::path::PathBuf>,
    audit_path: std::path::PathBuf,
    actor: quokka_core::Actor,
    renderer: RendererArg,
) -> Result<u8> {
    let boot = quokka_ui::Boot {
        config_path,
        audit_path,
        actor,
        // The drivers are wired in here rather than in `quokka-ui`, which depends on
        // `quokka-core` and `quokka-spool` and nothing else. A surface that could open a
        // driver would be a surface with a second path to a database.
        factories: quokka_driver::builtin_factories(),
    };
    let renderer = match renderer {
        RendererArg::Gpu => quokka_ui::Renderer::Gpu,
        RendererArg::Software => quokka_ui::Renderer::Software,
    };

    quokka_ui::run(boot, renderer)
        .map_err(|e| anyhow::anyhow!("the window could not open: {e}"))?;
    Ok(crate::exit::OK)
}

/// The subcommand still exists in a headless build, so that asking for it gets an
/// explanation rather than "unrecognized subcommand".
#[cfg(not(feature = "ui"))]
pub fn run(
    _config_path: Option<std::path::PathBuf>,
    _audit_path: std::path::PathBuf,
    _actor: quokka_core::Actor,
    _renderer: RendererArg,
) -> Result<u8> {
    anyhow::bail!(
        "this build has no window: it was compiled with --no-default-features, which \
         drops `quokka-ui` and the whole wgpu/winit stack with it.\n\
         \n\
         That is the point of that build — a container, a CI runner or an agent's box \
         wants a headless CLI — so the fix is to install the default build:\n\
         \n\
         \x20   cargo install quokkaquery\n\
         \n\
         Everything the window does is available here: `quokka query`, `quokka schema \
         describe`, `quokka audit`."
    )
}
