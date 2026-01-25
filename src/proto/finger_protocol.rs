#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct FingerRequest {
    long: bool,
    name: String,
}

impl FingerRequest {
    pub fn new(long: bool, name: String) -> Self {
        Self { long, name }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        if self.long {
            result.extend(b"/W ");
        }

        result.extend(self.name.as_bytes());
        result.extend(b"\r\n");

        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let (long, name) = if &bytes[..3] == b"/W " {
            (true, &bytes[3..])
        } else {
            (false, bytes)
        };

        let name = match name.strip_suffix(b"\r\n") {
            Some(new_name) => new_name,
            None => name,
        };

        Self::new(long, String::from_utf8_lossy(name).to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerResponse(String);

impl FingerResponse {
    pub fn new(content: String) -> Self {
        Self(content)
    }

    pub fn get_inner(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self(String::new());
        }

        fn normalize(c: u8) -> u8 {
            if c == (b'\r' | 0x80) || c == (b'\n' | 0x80) {
                c & 0x7f
            } else {
                c
            }
        }

        let normalized: Vec<u8> = bytes
            .iter()
            .copied()
            .map(normalize)
            .chain(std::iter::once(normalize(*bytes.last().unwrap())))
            .map_windows(|[a, b]| {
                if *a == b'\r' && *b == b'\n' {
                    None
                } else {
                    Some(*a)
                }
            })
            .flatten()
            .collect();

        let result = String::from_utf8_lossy(&normalized).to_string();

        Self(result)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() + 2);

        for &b in self.0.as_bytes() {
            if b == b'\n' {
                out.extend_from_slice(b"\r\n");
            } else {
                out.push(b);
            }
        }

        if !self.0.ends_with('\n') {
            out.extend_from_slice(b"\r\n");
        }

        out
    }
}
