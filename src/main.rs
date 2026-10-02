fn main() {
    let config = rust_web_sanitizer::read_args();

    if let Err(e) = rust_web_sanitizer::run_sanitizer(&config) {
        eprintln!("Errore: {}", e);
        std::process::exit(1);
    }
}
