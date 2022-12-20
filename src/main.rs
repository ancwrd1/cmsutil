use std::{
    error::Error,
    fs,
    io::{self, Read, Write},
    ops::Deref,
    path::PathBuf,
};

use clap::Parser;
use log::debug;
use wincms::{
    cert::{CertContext, CertStore, CertStoreType},
    cms::CmsContent,
};

#[derive(Parser)]
#[clap(
    about = "CMS encoding utility to sign/encrypt or decrypt/verify a CMS-encoded message",
    name = "cmsutil"
)]
struct AppParams {
    #[clap(
        short = 'p',
        long = "password",
        global = true,
        help = "Smart card pin or PFX password"
    )]
    pin: Option<String>,

    #[clap(short = 'q', long = "quiet", help = "Disable Windows CSP UI prompts")]
    silent: bool,

    #[clap(
        short = 't',
        long = "store-type",
        global = true,
        help = "Certificate store type, one of: machine, user, service"
    )]
    store_type: Option<CertStoreType>,

    #[clap(
        short = 'f',
        long = "pfx",
        global = true,
        help = "Use PFX/PKCS12 file as a certificate store"
    )]
    pfx_file: Option<PathBuf>,

    #[clap(
        short = 'i',
        long = "in",
        global = true,
        help = "Input file [default: stdin]"
    )]
    input_file: Option<PathBuf>,

    #[clap(
        short = 'o',
        long = "out",
        global = true,
        help = "Output file [default: stfdout]"
    )]
    output_file: Option<PathBuf>,

    #[clap(subcommand)]
    command: CmsCommand,
}

#[derive(Parser)]
enum CmsCommand {
    #[clap(name = "encode", about = "Sign and encrypt data")]
    Encode(CmsEncodeCmd),
    #[clap(name = "decode", about = "Decrypt and verify data")]
    Decode(CmsDecodeCmd),
}

#[derive(Parser)]
struct CmsEncodeCmd {
    #[clap(short = 's', long = "signer", help = "Signer certificate ID")]
    signer: String,

    #[clap(
        index = 1,
        required = true,
        help = "One or more recipient certificate IDs"
    )]
    recipients: Vec<String>,
}

#[derive(Parser)]
struct CmsDecodeCmd {
    #[clap(index = 1, required = true, help = "Recipient certificate ID")]
    recipient: String,
}

enum MessageSource {
    File(memmap::Mmap),
    Stdin(Vec<u8>),
}

impl Deref for MessageSource {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            MessageSource::File(mmap) => mmap,
            MessageSource::Stdin(data) => data,
        }
    }
}

fn get_cert_with_key(certs: &mut [CertContext], silent: bool) -> Option<CertContext> {
    certs
        .iter_mut()
        .find_map(|cert| cert.acquire_key(silent).map(|_| cert.clone()).ok())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: AppParams = AppParams::parse();

    env_logger::init();

    let source = if let Some(input_file) = args.input_file {
        let input_file = fs::File::open(input_file)?;
        let mmap = unsafe { memmap::MmapOptions::new().map(&input_file)? };
        MessageSource::File(mmap)
    } else {
        let mut data = Vec::new();
        io::stdin().read_to_end(&mut data)?;
        MessageSource::Stdin(data)
    };

    let store = if let Some(ref path) = args.pfx_file {
        let pfx_data = fs::read(path)?;
        CertStore::from_pkcs12(
            &pfx_data,
            args.pin.as_ref().map(AsRef::as_ref).unwrap_or(""),
        )?
    } else {
        let store_type = args.store_type.unwrap_or(CertStoreType::CurrentUser);
        CertStore::open(store_type, "my")?
    };

    match args.command {
        CmsCommand::Encode(ref cmd) => {
            let mut signers = store.find_cert_by_subject_str(&cmd.signer)?;

            if let Some(signer) = get_cert_with_key(&mut signers, args.silent) {
                debug!("Acquired signer certificate for {}", cmd.signer);

                let mut recipients = Vec::new();
                for rcpt in &cmd.recipients {
                    recipients.extend(store.find_cert_by_subject_str(rcpt)?.into_iter());
                }
                debug!("Acquired {} recipient certificate(s)", recipients.len());

                let key = signer.key().unwrap();
                let key_prov = key.get_provider_name()?;
                let key_name = key.get_name()?;
                debug!("Acquired private key: {}: {}", key_prov, key_name);

                if args.pfx_file.is_none() {
                    if let Some(pin) = args.pin {
                        key.set_pin(&pin)?;
                        debug!("Pin code set");
                    }
                }

                let content = CmsContent::builder()
                    .signer(signer)
                    .recipients(recipients)
                    .build();

                let data = content.sign_and_encrypt(&source)?;

                if let Some(output_file) = args.output_file {
                    fs::write(output_file, &data)?;
                } else {
                    io::stdout().write_all(&data)?;
                }
            } else {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Cannot find signer certificate for {}", cmd.signer),
                )));
            }
        }
        CmsCommand::Decode(ref cmd) => {
            let mut recipients = store.find_cert_by_subject_str(&cmd.recipient)?;
            if let Some(cert) = get_cert_with_key(&mut recipients, args.silent) {
                debug!("Acquired recipient certificate for {}", cmd.recipient);

                let key = cert.key().unwrap();
                let key_prov = key.get_provider_name()?;
                let key_name = key.get_name()?;
                debug!("Acquired private key: {}: {}", key_prov, key_name);

                if args.pfx_file.is_none() {
                    if let Some(pin) = args.pin {
                        key.set_pin(&pin)?;
                        debug!("Pin code set");
                    }
                }

                let data = CmsContent::decrypt_and_verify(&store, &source)?;

                if let Some(output_file) = args.output_file {
                    fs::write(output_file, &data)?;
                } else {
                    io::stdout().write_all(&data)?;
                }
            } else {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Cannot find recipient certificate for {}", cmd.recipient),
                )));
            }
        }
    }
    Ok(())
}
