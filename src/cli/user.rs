//! `core-pulse user ...`: dashboard accounts are managed on the server only.
//! There is no sign-up page.

use std::io::{BufRead, Write};

use anyhow::{Result, bail, ensure};
use chrono::{Local, TimeZone};
use clap::Subcommand;
use data_encoding::BASE32_NOPAD;
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

use crate::auth::{self, password, totp};
use crate::clock;
use crate::store::Store;

#[derive(Subcommand)]
pub enum UserCommand {
    /// Add a user: asks for a password and sets up two-factor login
    Add { name: String },
    /// List users
    List,
    /// Set a new password (signs the user out everywhere)
    Password { name: String },
    /// Set up two-factor login again, for example on a new phone
    #[command(name = "reset-2fa")]
    Reset2fa { name: String },
    /// Clear a lockout after too many failed logins
    Unlock { name: String },
    /// Remove a user
    Remove { name: String },
}

pub fn run(command: UserCommand, store: &mut Store) -> Result<()> {
    match command {
        UserCommand::Add { name } => {
            auth::validate_username(&name)?;
            ensure!(store.user(&name)?.is_none(), "user {name} already exists");
            let hash = password::hash(&ask_new_password()?)?;
            let secret = enroll_totp(&name)?;
            store.add_user(&name, &hash, &secret, clock::now())?;
            println!("User {name} added.");
        }
        UserCommand::List => list(store)?,
        UserCommand::Password { name } => {
            ensure!(store.user(&name)?.is_some(), "no user named {name}");
            store.set_password(&name, &password::hash(&ask_new_password()?)?)?;
            println!("Password changed. {name} is signed out everywhere.");
        }
        UserCommand::Reset2fa { name } => {
            ensure!(store.user(&name)?.is_some(), "no user named {name}");
            store.set_totp_secret(&name, &enroll_totp(&name)?)?;
            println!("Two-factor login reset. {name} is signed out everywhere.");
        }
        UserCommand::Unlock { name } => {
            store.unlock_user(&name)?;
            println!("{name} is unlocked.");
        }
        UserCommand::Remove { name } => {
            store.remove_user(&name)?;
            println!("User {name} removed.");
        }
    }
    Ok(())
}

fn list(store: &Store) -> Result<()> {
    let users = store.users()?;
    if users.is_empty() {
        println!("No users yet. Add one with: core-pulse user add <name>");
    }
    let now = clock::now();
    for user in users {
        let state = match user.locked_until {
            Some(until) if until > now => {
                let time = Local
                    .timestamp_opt(until, 0)
                    .single()
                    .map(|t| t.format("%H:%M").to_string());
                format!("locked until {}", time.unwrap_or_default())
            }
            _ if user.failed_logins > 0 => format!("{} failed logins", user.failed_logins),
            _ => "ok".to_string(),
        };
        println!("{:<32} {state}", user.username);
    }
    Ok(())
}

fn ask_new_password() -> Result<String> {
    for _ in 0..3 {
        let first = rpassword::prompt_password("New password: ")?;
        if first.chars().count() < password::MIN_LENGTH {
            eprintln!("Use at least {} characters.", password::MIN_LENGTH);
            continue;
        }
        if rpassword::prompt_password("Repeat it: ")? == first {
            return Ok(first);
        }
        eprintln!("The two passwords differ.");
    }
    bail!("no password set")
}

/// Shows a new secret as a QR code and keeps it only once the app proves
/// it can make codes from it.
fn enroll_totp(name: &str) -> Result<Vec<u8>> {
    let secret = auth::random_bytes::<20>()?.to_vec();
    let encoded = BASE32_NOPAD.encode(&secret);
    let qr = QrCode::new(totp::provisioning_uri(&encoded, name))?
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build();

    println!("\nScan this with your authenticator app:\n\n{qr}\n");
    println!("Or type the key in by hand: {encoded}\n");
    for _ in 0..3 {
        let code = prompt("Code shown in the app: ")?;
        if totp::verify(&secret, &code, clock::now(), None).is_some() {
            return Ok(secret);
        }
        eprintln!("That code does not match. Check that the phone's clock is right.");
    }
    bail!("two-factor login was not confirmed, nothing changed")
}

fn prompt(text: &str) -> Result<String> {
    print!("{text}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}
