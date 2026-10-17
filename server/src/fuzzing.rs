//! Randomized hostile inputs for parser robustness tests (no panics, bounded work). Not a
//! replacement for coverage-guided fuzzing, but run with every `cargo test`.

use rand::{Rng, SeedableRng, rngs::StdRng};

/// Fragments that parsers treat specially: line ends, delimiters, quoting, escapes, NUL and
/// invalid UTF-8.
const PIECES: &[&[u8]] = &[
    b"\r\n", b"\n", b"\r", b"\0", b":", b";", b",", b"<", b">", b"{", b"}", b"{5+}", b"{4294967296}", b"\"", b"\\", b"--", b"=", b"+", b"+2B", b"(", b")", b" ",
    b"\t", b"\xff\xfe", b"\xc3\x28", b"@", b".", b"..", b"\r\n.\r\n", b"Content-Type: multipart/signed; boundary=\"b\"\r\n", b"Content-Type: application/pkcs7-mime\r\n",
    b"From: a@b.example\r\n", b"Subject: x\r\n", b"\r\n\r\n", b"0", b"18446744073709551615", b"-1", b"NOTIFY=", b"ORCPT=rfc822;", b"RET=FULL", b"\x30\x82\xff\xff", b"\x30\x80",
    b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02", b"BDAT ", b"LAST", b"LIST-ID", b"subscribe",
];

/// `count` random inputs, reproducible from `seed`, up to `max_len` pieces long.
pub fn inputs(seed: u64, count: usize, max_len: usize) -> Vec<Vec<u8>> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..count)
        .map(|_| {
            let mut out = Vec::new();
            for _ in 0..rng.gen_range(0..=max_len) {
                if rng.gen_bool(0.3) {
                    let len = rng.gen_range(1..40);
                    out.extend((0..len).map(|_| rng.r#gen::<u8>()));
                } else {
                    out.extend_from_slice(PIECES[rng.gen_range(0..PIECES.len())]);
                }
            }
            out
        })
        .collect()
}

/// The same inputs as text (lossy), for parsers that take `&str`.
pub fn texts(seed: u64, count: usize, max_len: usize) -> Vec<String> {
    inputs(seed, count, max_len).into_iter().map(|bytes| String::from_utf8_lossy(&bytes).into_owned()).collect()
}
