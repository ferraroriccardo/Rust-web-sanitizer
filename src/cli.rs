use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about = "Web Sanitiser in Rust")]
pub struct Args {
    /// Lista di file locali o URL da sanificare
    #[arg(required = true, help = "Lista di file locali o URL da sanificare")]
    pub src: Vec<String>,

    #[arg(short, long, conflicts_with = "quiet")]
    pub verbose: bool,

    #[arg(short, long)]
    pub quiet: bool,

    /// Percorso del file di configurazione TOML
    #[arg(short, long, default_value = "config.toml")]
    pub config: String,

    /// Abilita l'output del report in formato JSON
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Cartella opzionale in cui salvare i file HTML sanificati
    #[arg(short, long)]
    pub out_dir: Option<String>,
}

#[derive(Debug)]
pub enum Verbosity {
    Verbose,
    Quiet,
    Default,
}

#[derive(Debug)]
pub struct CliConfig {
    pub sources: Vec<String>,
    pub verbosity: Verbosity,
    pub config_path: String,
    pub json_output: bool,
    pub out_dir: Option<String>,
}

pub fn read_args() -> CliConfig {
    let args = Args::parse();

    let verbosity = match (args.verbose, args.quiet) {
        (true, false) => Verbosity::Verbose,
        (false, true) => Verbosity::Quiet,
        _ => Verbosity::Default,
    };

    CliConfig {
        sources: args.src,
        verbosity,
        config_path: args.config,
        json_output: args.json,
        out_dir: args.out_dir,
    }
}