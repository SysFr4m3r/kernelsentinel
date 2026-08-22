
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};

use kernelsentinel::clock::BootClock;
use kernelsentinel::event::{EventType, RawEvent};
use kernelsentinel::{doctor, sensors};

#[derive(Parser)]
#[command(
    name = "kernelsentinel",
    about = "Runtime detection engine for Linux post-exploitation behavior",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Attach the sensors and stream events.
    Run,
    /// Report whether this kernel can run the sensors.
    Doctor,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Doctor => {
            let report = doctor::run();
            report.print();
            if report.fatal() {
                std::process::exit(1);
            }
            Ok(())
        }
        Command::Run => run(),
    }
}

fn run() -> Result<()> {
    let report = doctor::run();
    if report.fatal() {
        report.print();
        anyhow::bail!("preflight checks failed");
    }

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc_handler(move || stop.store(true, Ordering::Relaxed))?;
    }

    let bootclock = BootClock::new();
    let self_pid = std::process::id();

    eprintln!("kernelsentinel: sensors attached, streaming events (ctrl-c to stop)\n");
    println!(
        "{:<12} {:<7} {:<7} {:<6} {:<16} {}",
        "TIME(UTC)", "PID", "PPID", "UID", "COMM", "EVENT"
    );

    let stats = sensors::run(stop, |ev: RawEvent| {
        if ev.tgid == self_pid {
            return;
        }
        print_event(&bootclock, &ev);
    })?;

    eprintln!(
        "\nkernelsentinel: {} events emitted, {} ring buffer drops",
        stats.emitted, stats.drops
    );
    if stats.drops > 0 {
        eprintln!("kernelsentinel: WARNING — dropped events mean blind spots");
    }
    Ok(())
}

fn print_event(clock: &BootClock, ev: &RawEvent) {
    let detail = match ev.event_type() {
        EventType::Exec => {
            let filename = ev.filename();
            let argv = ev.argv();
            // argv[0] is conventionally the program name and is already shown
            // as the filename. For shebang scripts the kernel also inserts the
            // script path as argv[1], so drop that repeat too.
            let mut args: &[String] = argv.get(1..).unwrap_or(&[]);
            if args.first().map(String::as_str) == Some(filename.as_str()) {
                args = &args[1..];
            }
            let trunc = if ev.truncated() { " …" } else { "" };
            format!("exec {} {}{}", filename, args.join(" "), trunc)
        }
        EventType::Exit => format!("exit code={}", ev.exit_code),
        EventType::Fork => "fork".to_string(),
        EventType::Unknown(t) => format!("unknown type={t}"),
    };

    println!(
        "{:<12} {:<7} {:<7} {:<6} {:<16} {}",
        clock.format(ev.ts_ns),
        ev.tgid,
        ev.ppid,
        ev.uid,
        ev.comm(),
        detail.trim_end()
    );
}

/// Minimal SIGINT/SIGTERM handling without pulling in a signal crate.
fn ctrlc_handler<F>(f: F) -> Result<()>
where
    F: FnMut() + Send + 'static,
{
    use std::sync::Mutex;
    static HANDLER: Mutex<Option<Box<dyn FnMut() + Send>>> = Mutex::new(None);

    extern "C" fn on_signal(_: libc::c_int) {
        if let Ok(mut guard) = HANDLER.lock() {
            if let Some(f) = guard.as_mut() {
                f();
            }
        }
    }

    *HANDLER.lock().unwrap() = Some(Box::new(f));
    // SAFETY: on_signal only touches a Mutex-guarded closure that sets an
    // AtomicBool; the poll loop checks the flag between iterations.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
    Ok(())
}
