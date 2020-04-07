use std::{
    error::Error,
    fs,
    io::{self, Read, Write},
    ops::Deref,
    path::PathBuf,
};

use log::debug;
use structopt::StructOpt;

use wincms::{
    cms::CmsContent,
    cng::{CertStore, CertStoreType},
};

#[derive(StructOpt)]
#[structopt(
    about = "CMS encoding utility",
    name = "cmsutil",
    author = "Dmitry Pankratov"
)]
struct AppParams {
    #[structopt(
        short = "p",
        long = "password",
        help = "Smart card pin or PFX password"
    )]
    pin: Option<String>,

    #[structopt(short = "q", long = "quiet", help = "Disable Windows CSP UI prompts")]
    silent: bool,

    #[structopt(
        short = "t",
        long = "store-type",
        help = "Certificate store type, one of: machine, user, service"
    )]
    store_type: Option<CertStoreType>,

    #[structopt(
        short = "f",
        long = "pfx",
        help = "Use PFX/PKCS12 file as a certificate store"
    )]
    pfx_file: Option<PathBuf>,

    #[structopt(short = "i", long = "in", help = "Input file")]
    input_file: Option<PathBuf>,

    #[structopt(short = "o", long = "out", help = "Output file")]
    output_file: Option<PathBuf>,

    #[structopt(short = "s", long = "signer", help = "Signer certificate ID")]
    signer: String,

    #[structopt(
        index = 1,
        required = true,
        help = "One or more recipient certificate IDs"
    )]
    recipients: Vec<String>,
}

enum MessageSource {
    File(memmap::Mmap),
    Stdin(Vec<u8>),
}

impl Deref for MessageSource {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            MessageSource::File(mmap) => &mmap,
            MessageSource::Stdin(data) => &data,
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: AppParams = AppParams::from_args();

    env_logger::init();

    let source = if let Some(input_file) = args.input_file {
        let input_file = fs::File::open(&input_file)?;
        let mmap = unsafe { memmap::MmapOptions::new().map(&input_file)? };
        MessageSource::File(mmap)
    } else {
        let mut data = Vec::new();
        io::stdin().read_to_end(&mut data)?;
        MessageSource::Stdin(data)
    };

    let store = if let Some(ref path) = args.pfx_file {
        let pfx_data = fs::read(path)?;
        CertStore::from_pfx(
            &pfx_data,
            args.pin.as_ref().map(AsRef::as_ref).unwrap_or(""),
        )?
    } else {
        let store_type = args.store_type.unwrap_or(CertStoreType::CurrentUser);
        CertStore::open(store_type, "my")?
    };

    let mut signer = store.find_cert_by_subject_str(&args.signer)?;
    debug!("Acquired signer certificate for {}", args.signer);

    let mut recipients = Vec::new();
    for rcpt in &args.recipients {
        recipients.push(store.find_cert_by_subject_str(rcpt)?);
        debug!("Acquired recipient certificate for {}", rcpt);
    }

    let key = signer.acquire_key(args.silent)?;
    let key_prov = key.get_provider()?;
    let key_name = key.get_name()?;
    debug!("Acquired private key: {}: {}", key_prov, key_name);

    // TESTTEST
    // let raw_cert = signer.get_data();
    // let raw_key = NCryptKey::open(&key_prov, &key_name)?;
    // CertStore::open(CertStoreType::LocalMachine, "my")?.add_cert(&raw_cert, Some(raw_key))?;

    let builder = CmsContent::builder().signer(signer).recipients(recipients);

    if args.pfx_file.is_none() {
        if let Some(pin) = args.pin {
            key.set_pin(&pin)?;
            debug!("Pin code set");
        }
    }

    let content = builder.build()?;
    let data = content.sign_and_encrypt(&source)?;

    if let Some(output_file) = args.output_file {
        fs::write(output_file, &data)?;
    } else {
        io::stdout().write_all(&data)?;
    }

    Ok(())
}
