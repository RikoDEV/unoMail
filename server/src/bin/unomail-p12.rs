//! Disposable, resource-constrained PKCS #12 parser. Secrets travel over pipes only.
use std::io::{Read, Write};
use base64::Engine;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        rlimit::Resource::AS.set(512 * 1024 * 1024, 512 * 1024 * 1024)?;
        rlimit::Resource::CPU.set(15, 15)?;
        rlimit::Resource::CORE.set(0, 0)?;
    }
    let mut input = Vec::new();
    std::io::stdin().take(100_001).read_to_end(&mut input)?;
    if input.len() > 100_000 { return Err("input too large".into()); }
    let (encoded, password): (String, String) = serde_json::from_slice(&input)?;
    let data = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let result = if data.len() <= 64 * 1024 && password.len() <= 256 {
        unomail::smime::import_p12(&data, &password)
    } else {
        Err("certificate or password is too large".into())
    };
    std::io::stdout().write_all(&serde_json::to_vec(&result)?)?;
    Ok(())
}
