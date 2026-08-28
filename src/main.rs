//! Entry point: parse arguments, set up logging, dispatch, and report failures usefully.

use anyhow::Result;
use clap::Parser;
use memsync::app::{self, Paths};
use memsync::cli::{Cli, Command, KeyCommand, RootCommand};

fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    if let Err(error) = run(&cli) {
        // The chain matters: "cannot access X: permission denied" is actionable, "sync
        // failed" is not.
        eprintln!("memsync: {error}");
        for cause in error.chain().skip(1) {
            eprintln!("  caused by: {cause}");
        }
        std::process::exit(1);
    }
}

fn run(cli: &Cli) -> Result<()> {
    let paths = Paths::for_user()?;
    match &cli.command {
        Command::Init {
            remote,
            label,
            store_path,
            no_discover,
        } => app::init(
            &paths,
            remote,
            label.clone(),
            store_path.clone(),
            !no_discover,
        ),
        Command::Sync { quiet } => app::sync(&paths, *quiet),
        Command::Status => app::status(&paths),
        Command::Key { command } => match command {
            KeyCommand::Show => app::key_show(&paths),
            KeyCommand::List => app::key_list(&paths),
            KeyCommand::Add { key, label } => app::key_add(&paths, key, label),
            KeyCommand::Remove { label } => app::key_remove(&paths, label),
            KeyCommand::Export => app::key_export(&paths),
        },
        Command::Root { command } => match command {
            RootCommand::List => app::root_list(&paths),
            RootCommand::Store => app::root_store(&paths),
            RootCommand::Add { id, path } | RootCommand::Map { id, path } => {
                app::root_set(&paths, id, path)
            }
            RootCommand::Remove { id } => app::root_remove(&paths, id),
        },
        Command::InstallHooks { command } => app::install_hooks(&paths, command.clone()),
        Command::UninstallHooks => app::uninstall_hooks(&paths),
    }
}

/// Logging is off by default: this runs from a session hook, where unexpected output is
/// noise. `-v` and `-vv` turn it on, and `RUST_LOG` still wins for debugging.
fn init_tracing(verbosity: u8) {
    let default = match verbosity {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}
