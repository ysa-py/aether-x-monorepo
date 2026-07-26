//! Minimal, panic-free TLS ClientHello extension scanner.
//!
//! Extracts the Outer SNI hostname and detects the ECH (Encrypted Client Hello)
//! extension (type `0xfe0d`, draft-ietf-tls-esni) from a raw extension block.
//! Every byte access is bounds-checked; malformed/truncated input returns
//! [`TlsParseError`] — never panics. This is the kind of code that processes
//! untrusted network bytes and benefits from coverage-guided fuzzing.

/// Errors from parsing a malformed extension block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsParseError {
    /// Input ended before a complete field could be read.
    Truncated,
    /// A length field pointed past the buffer boundary.
    InvalidLength,
    /// SNI hostname contained invalid UTF-8.
    InvalidUtf8,
}

/// Extracted ClientHello metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// The Outer SNI hostname (from extension type 0x0000), if present.
    pub sni: Option<String>,
    /// Whether the ECH extension (0xfe0d) is present.
    pub ech_present: bool,
}

/// SNI extension type.
const EXT_SNI: u16 = 0x0000;
/// ECH extension type (draft-ietf-tls-esni).
const EXT_ECH: u16 = 0xfe0d;

/// Parse a raw extension block (`data`) and extract SNI + ECH presence.
///
/// The block format is a sequence of: extension_type (u16 BE), extension_length
/// (u16 BE), extension_data (extension_length bytes).
pub fn parse_extensions(data: &[u8]) -> Result<ClientHelloInfo, TlsParseError> {
    let mut info = ClientHelloInfo::default();
    let mut pos = 0;

    while pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos
            .checked_add(ext_len)
            .map_or(true, |end| end > data.len())
        {
            return Err(TlsParseError::Truncated);
        }
        let ext_data = &data[pos..pos + ext_len];
        pos = pos.saturating_add(ext_len);

        match ext_type {
            EXT_SNI => info.sni = parse_sni(ext_data)?,
            EXT_ECH => info.ech_present = true,
            _ => {}
        }
    }

    Ok(info)
}

/// Parse the SNI extension body and extract the first `host_name` entry.
fn parse_sni(data: &[u8]) -> Result<Option<String>, TlsParseError> {
    if data.len() < 2 {
        return Err(TlsParseError::Truncated);
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list_end = 2_usize
        .checked_add(list_len)
        .ok_or(TlsParseError::InvalidLength)?;
    if list_end > data.len() {
        return Err(TlsParseError::Truncated);
    }

    let mut pos = 2;
    while pos + 3 <= list_end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;

        let name_end = pos
            .checked_add(name_len)
            .ok_or(TlsParseError::InvalidLength)?;
        if name_end > list_end {
            return Err(TlsParseError::Truncated);
        }

        if name_type == 0 {
            // host_name type: UTF-8 DNS name.
            let raw = &data[pos..name_end];
            let name = std::str::from_utf8(raw)
                .map_err(|_| TlsParseError::InvalidUtf8)?
                .to_owned();
            return Ok(Some(name));
        }
        pos = name_end;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(ty: u16, body: &[u8]) -> Vec<u8> {
        let mut v = ty.to_be_bytes().to_vec();
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn parses_sni_and_ech() {
        // SNI: list_len=8, name_type=0, name_len=4, "test"
        let mut sni_body = vec![];
        sni_body.extend_from_slice(&7u16.to_be_bytes()); // entry: type(1)+len(2)+name(4)=7
        sni_body.push(0); // host_name
        sni_body.extend_from_slice(&4u16.to_be_bytes());
        sni_body.extend_from_slice(b"test");

        let block = [ext(EXT_SNI, &sni_body), ext(EXT_ECH, &[])].concat();
        let info = parse_extensions(&block).unwrap();
        assert_eq!(info.sni.as_deref(), Some("test"));
        assert!(info.ech_present);
    }

    #[test]
    fn rejects_truncated_extension() {
        // ext_type + ext_len but no body.
        let block = [0x00, 0x00, 0x00, 0x10]; // claims 16 bytes body, none present
        assert_eq!(parse_extensions(&block), Err(TlsParseError::Truncated));
    }

    #[test]
    fn empty_block_is_ok() {
        let info = parse_extensions(&[]).unwrap();
        assert!(info.sni.is_none());
        assert!(!info.ech_present);
    }

    #[test]
    fn rejects_invalid_utf8_sni() {
        let mut sni_body = vec![];
        sni_body.extend_from_slice(&5u16.to_be_bytes());
        sni_body.push(0);
        sni_body.extend_from_slice(&2u16.to_be_bytes());
        sni_body.extend_from_slice(&[0xff, 0xfe]); // invalid UTF-8
        let block = ext(EXT_SNI, &sni_body);
        assert_eq!(parse_extensions(&block), Err(TlsParseError::InvalidUtf8));
    }

    #[test]
    fn ignores_unknown_extensions() {
        let block = ext(0x1234, &[0xab, 0xcd]);
        let info = parse_extensions(&block).unwrap();
        assert!(info.sni.is_none());
        assert!(!info.ech_present);
    }
}
