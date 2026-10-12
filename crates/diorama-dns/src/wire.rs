#![allow(
    clippy::struct_excessive_bools,
    clippy::cast_possible_truncation,
    clippy::similar_names
)]

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{DnsError, Result};

/// DNS Record Types supported by the cluster DNS probe engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsRecordType {
    A = 1,
    CNAME = 5,
    PTR = 12,
    AAAA = 28,
    Other(u16),
}

impl DnsRecordType {
    #[must_use]
    pub const fn from_u16(val: u16) -> Self {
        match val {
            1 => Self::A,
            5 => Self::CNAME,
            12 => Self::PTR,
            28 => Self::AAAA,
            other => Self::Other(other),
        }
    }

    #[must_use]
    pub const fn as_u16(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::CNAME => 5,
            Self::PTR => 12,
            Self::AAAA => 28,
            Self::Other(val) => *val,
        }
    }
}

/// DNS Response Codes (RCODE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DnsRcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
    Other(u8),
}

impl DnsRcode {
    #[must_use]
    pub const fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NXDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            other => Self::Other(other),
        }
    }

    #[must_use]
    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NXDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::Other(val) => *val,
        }
    }
}

/// Standard 12-byte DNS message header (RFC 1035 section 4.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rcode: DnsRcode,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    #[must_use]
    pub fn new_query(id: u16, rd: bool) -> Self {
        Self {
            id,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd,
            ra: false,
            rcode: DnsRcode::NoError,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    #[must_use]
    pub fn new_response(id: u16, rcode: DnsRcode, aa: bool, rd: bool, ra: bool) -> Self {
        Self {
            id,
            qr: true,
            opcode: 0,
            aa,
            tc: false,
            rd,
            ra,
            rcode,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.id.to_be_bytes());

        let mut flags: u16 = 0;
        if self.qr {
            flags |= 0x8000;
        }
        flags |= u16::from(self.opcode & 0x0F) << 11;
        if self.aa {
            flags |= 0x0400;
        }
        if self.tc {
            flags |= 0x0200;
        }
        if self.rd {
            flags |= 0x0100;
        }
        if self.ra {
            flags |= 0x0080;
        }
        flags |= u16::from(self.rcode.as_u8() & 0x0F);

        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&self.qdcount.to_be_bytes());
        buf.extend_from_slice(&self.ancount.to_be_bytes());
        buf.extend_from_slice(&self.nscount.to_be_bytes());
        buf.extend_from_slice(&self.arcount.to_be_bytes());
    }

    pub fn read_from(buf: &[u8]) -> Result<Self> {
        if buf.len() < 12 {
            return Err(DnsError::Wire("DNS header too short (< 12 bytes)".into()));
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        let nscount = u16::from_be_bytes([buf[8], buf[9]]);
        let arcount = u16::from_be_bytes([buf[10], buf[11]]);

        let qr = (flags & 0x8000) != 0;
        let opcode = ((flags >> 11) & 0x0F) as u8;
        let aa = (flags & 0x0400) != 0;
        let tc = (flags & 0x0200) != 0;
        let rd = (flags & 0x0100) != 0;
        let ra = (flags & 0x0080) != 0;
        let rcode = DnsRcode::from_u8((flags & 0x0F) as u8);

        Ok(Self {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }
}

/// DNS Question (RFC 1035 section 4.1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: DnsRecordType,
    pub qclass: u16,
}

impl DnsQuestion {
    #[must_use]
    pub fn new(name: impl Into<String>, qtype: DnsRecordType) -> Self {
        Self {
            name: name.into(),
            qtype,
            qclass: 1, // IN
        }
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        encode_domain_name(&self.name, buf);
        buf.extend_from_slice(&self.qtype.as_u16().to_be_bytes());
        buf.extend_from_slice(&self.qclass.to_be_bytes());
    }
}

/// Payload of a DNS Answer Resource Record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsRecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    PTR(String),
    Raw(Vec<u8>),
}

/// DNS Answer Resource Record (RFC 1035 section 4.1.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: DnsRecordType,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: DnsRecordData,
}

impl DnsAnswer {
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        encode_domain_name(&self.name, buf);
        buf.extend_from_slice(&self.rtype.as_u16().to_be_bytes());
        buf.extend_from_slice(&self.rclass.to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());

        match &self.rdata {
            DnsRecordData::A(ip) => {
                buf.extend_from_slice(&4u16.to_be_bytes());
                buf.extend_from_slice(&ip.octets());
            },
            DnsRecordData::AAAA(ip) => {
                buf.extend_from_slice(&16u16.to_be_bytes());
                buf.extend_from_slice(&ip.octets());
            },
            DnsRecordData::CNAME(cname) => {
                let mut data = Vec::new();
                encode_domain_name(cname, &mut data);
                let len = data.len() as u16;
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(&data);
            },
            DnsRecordData::PTR(target) => {
                let mut data = Vec::new();
                encode_domain_name(target, &mut data);
                let len = data.len() as u16;
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(&data);
            },
            DnsRecordData::Raw(bytes) => {
                let len = bytes.len() as u16;
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(bytes);
            },
        }
    }
}

/// Full DNS wire-format Message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
}

impl DnsMessage {
    #[must_use]
    pub fn new_query(id: u16, domain: &str, qtype: DnsRecordType) -> Self {
        Self {
            header: DnsHeader::new_query(id, true),
            questions: vec![DnsQuestion::new(domain, qtype)],
            answers: Vec::new(),
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        let mut header = self.header;
        header.qdcount = self.questions.len() as u16;
        header.ancount = self.answers.len() as u16;
        header.nscount = 0;
        header.arcount = 0;
        header.write_to(&mut buf);

        for q in &self.questions {
            q.write_to(&mut buf);
        }
        for a in &self.answers {
            a.write_to(&mut buf);
        }
        buf
    }

    #[must_use]
    pub fn to_tcp_bytes(&self) -> Vec<u8> {
        let payload = self.to_bytes();
        let len = payload.len() as u16;
        let mut buf = Vec::with_capacity(payload.len() + 2);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        let header = DnsHeader::read_from(raw)?;
        let mut cursor = 12;

        let qd_cap = (header.qdcount as usize).min(raw.len() / 5);
        let mut questions = Vec::with_capacity(qd_cap);
        for _ in 0..header.qdcount {
            let (name, next_cursor) = decode_domain_name(raw, cursor)?;
            cursor = next_cursor;
            if cursor + 4 > raw.len() {
                return Err(DnsError::Wire("unexpected EOF in DNS question".into()));
            }
            let qtype = DnsRecordType::from_u16(u16::from_be_bytes([raw[cursor], raw[cursor + 1]]));
            let qclass = u16::from_be_bytes([raw[cursor + 2], raw[cursor + 3]]);
            cursor += 4;
            questions.push(DnsQuestion {
                name,
                qtype,
                qclass,
            });
        }

        let an_cap = (header.ancount as usize).min(raw.len() / 11);
        let mut answers = Vec::with_capacity(an_cap);
        for _ in 0..header.ancount {
            let (name, next_cursor) = decode_domain_name(raw, cursor)?;
            cursor = next_cursor;
            if cursor + 10 > raw.len() {
                return Err(DnsError::Wire(
                    "unexpected EOF in DNS answer record header".into(),
                ));
            }
            let rtype = DnsRecordType::from_u16(u16::from_be_bytes([raw[cursor], raw[cursor + 1]]));
            let rclass = u16::from_be_bytes([raw[cursor + 2], raw[cursor + 3]]);
            let ttl = u32::from_be_bytes([
                raw[cursor + 4],
                raw[cursor + 5],
                raw[cursor + 6],
                raw[cursor + 7],
            ]);
            let rdlength = u16::from_be_bytes([raw[cursor + 8], raw[cursor + 9]]) as usize;
            cursor += 10;

            if cursor + rdlength > raw.len() {
                return Err(DnsError::Wire("unexpected EOF in DNS RDATA".into()));
            }
            let rdata_bytes = &raw[cursor..cursor + rdlength];

            let rdata = match rtype {
                DnsRecordType::A => {
                    if rdlength != 4 {
                        return Err(DnsError::Wire("invalid A record length".into()));
                    }
                    DnsRecordData::A(Ipv4Addr::new(
                        rdata_bytes[0],
                        rdata_bytes[1],
                        rdata_bytes[2],
                        rdata_bytes[3],
                    ))
                },
                DnsRecordType::AAAA => {
                    if rdlength != 16 {
                        return Err(DnsError::Wire("invalid AAAA record length".into()));
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(rdata_bytes);
                    DnsRecordData::AAAA(Ipv6Addr::from(octets))
                },
                DnsRecordType::CNAME => {
                    let (cname, _) = decode_domain_name(raw, cursor)?;
                    DnsRecordData::CNAME(cname)
                },
                DnsRecordType::PTR => {
                    let (ptr, _) = decode_domain_name(raw, cursor)?;
                    DnsRecordData::PTR(ptr)
                },
                DnsRecordType::Other(_) => DnsRecordData::Raw(rdata_bytes.to_vec()),
            };

            cursor += rdlength;
            answers.push(DnsAnswer {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            });
        }

        Ok(Self {
            header,
            questions,
            answers,
        })
    }
}

/// Encoders for RFC 1035 labels.
pub fn encode_domain_name(domain: &str, buf: &mut Vec<u8>) {
    let clean = domain.trim_end_matches('.');
    if clean.is_empty() {
        buf.push(0);
        return;
    }
    for label in clean.split('.') {
        let bytes = label.as_bytes();
        let len = bytes.len().min(63) as u8;
        buf.push(len);
        buf.extend_from_slice(&bytes[..len as usize]);
    }
    buf.push(0);
}

/// Decodes an RFC 1035 domain name taking into account pointer compression (0xC0).
pub fn decode_domain_name(raw: &[u8], mut cursor: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_cursor = cursor;
    let mut hops = 0;

    loop {
        if cursor >= raw.len() {
            return Err(DnsError::Wire("EOF reading domain name label".into()));
        }
        let len_byte = raw[cursor];

        if len_byte == 0 {
            if !jumped {
                next_cursor = cursor + 1;
            }
            break;
        }

        // Pointer compression: 0b11xxxxxx
        if (len_byte & 0xC0) == 0xC0 {
            if cursor + 1 >= raw.len() {
                return Err(DnsError::Wire("EOF reading pointer compression".into()));
            }
            let pointer_offset = (((len_byte & 0x3F) as usize) << 8) | (raw[cursor + 1] as usize);
            if !jumped {
                next_cursor = cursor + 2;
                jumped = true;
            }
            cursor = pointer_offset;
            hops += 1;
            if hops > 15 {
                return Err(DnsError::Wire("too many compression pointer hops".into()));
            }
            continue;
        }

        let label_len = len_byte as usize;
        cursor += 1;
        if cursor + label_len > raw.len() {
            return Err(DnsError::Wire(
                "EOF reading domain name label content".into(),
            ));
        }
        let label = std::str::from_utf8(&raw[cursor..cursor + label_len])
            .map_err(|e| DnsError::Wire(format!("invalid UTF-8 label: {e}")))?;
        labels.push(label);
        cursor += label_len;

        if !jumped {
            next_cursor = cursor;
        }
    }

    Ok((labels.join("."), next_cursor))
}
