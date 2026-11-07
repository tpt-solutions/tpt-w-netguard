// SPDX-License-Identifier: MIT OR Apache-2.0
//! Per-socket TCP byte counters from the kernel's `sock_diag` netlink interface.
//!
//! `/proc/net` carries no byte totals, but `INET_DIAG_INFO` (requested with `sock_diag`) returns
//! the kernel's `struct tcp_info` for every socket, including `tcpi_bytes_acked` (bytes the peer
//! has acknowledged, i.e. sent) and `tcpi_bytes_received`. The socket inode in each reply is the
//! same one `/proc/[pid]/fd` shows, so the monitor attributes counters to processes the same way
//! it attributes connections.
//!
//! The parser is pure and is tested on every host. The live query is Linux only. UDP has no
//! equivalent counters in `tcp_info`, so only TCP is reported, as on Windows.

use std::fmt;

/// `NETLINK_SOCK_DIAG` from `<linux/netlink.h>`.
pub const NETLINK_SOCK_DIAG: i32 = 4;
/// `SOCK_DIAG_BY_FAMILY` message type from `<linux/sock_diag.h>`.
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_HDR_LEN: usize = 16;
/// `struct inet_diag_req_v2`.
const REQ_LEN: usize = 56;
/// `struct inet_diag_msg` (the fixed part of each reply, before the attributes).
const MSG_LEN: usize = 72;
/// `INET_DIAG_INFO` attribute, carrying `struct tcp_info`.
const INET_DIAG_INFO: u16 = 2;
/// Extension bit that asks for `INET_DIAG_INFO`: `1 << (INET_DIAG_INFO - 1)`.
const EXT_INFO: u8 = 1 << (INET_DIAG_INFO - 1);
const IPPROTO_TCP: u8 = 6;
const ALL_TCP_STATES: u32 = 0xffff_ffff;
/// Offsets inside `struct tcp_info` (uapi `<linux/tcp.h>`, stable since Linux 4.1).
const TCPI_BYTES_ACKED: usize = 120;
const TCPI_BYTES_RECEIVED: usize = 128;
const TCPI_MIN_LEN: usize = 136;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// Byte totals for one TCP socket, as reported by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpCounters {
    /// Kernel socket cookie: unique for the life of a socket, so it keys delta tracking.
    pub cookie: u64,
    /// Socket inode, shared with `/proc/[pid]/fd/*` for attribution.
    pub inode: u64,
    /// Bytes the peer has acknowledged, i.e. bytes this host sent.
    pub bytes_sent: u64,
    /// Bytes this host received.
    pub bytes_received: u64,
}

/// Why a dump could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DumpError {
    /// A message header or length points outside the buffer.
    Truncated,
    /// The kernel answered with an `NLMSG_ERROR`, carrying a positive errno.
    Kernel(i32),
}

impl fmt::Display for DumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DumpError::Truncated => write!(f, "malformed sock_diag reply"),
            DumpError::Kernel(errno) => write!(f, "sock_diag refused the request (errno {errno})"),
        }
    }
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Builds one `SOCK_DIAG_BY_FAMILY` dump request for all TCP states of `family` (`AF_INET` or
/// `AF_INET6`), asking for `INET_DIAG_INFO`.
pub fn dump_request(family: u8, seq: u32) -> Vec<u8> {
    let total = NLMSG_HDR_LEN + REQ_LEN;
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&(total as u32).to_ne_bytes());
    buf.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.push(family);
    buf.push(IPPROTO_TCP);
    buf.push(EXT_INFO);
    buf.push(0);
    buf.extend_from_slice(&ALL_TCP_STATES.to_ne_bytes());
    // Empty `inet_diag_sockid`: no address or port filter.
    buf.extend_from_slice(&[0u8; 48]);
    buf
}

/// Dump request for IPv4 and IPv6 TCP sockets.
pub fn tcp_dump_requests() -> Vec<Vec<u8>> {
    vec![dump_request(AF_INET, 1), dump_request(AF_INET6, 2)]
}

fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(buf.get(at..at + 2)?.try_into().ok()?))
}

fn read_u32(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(buf.get(at..at + 4)?.try_into().ok()?))
}

fn read_u64(buf: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(buf.get(at..at + 8)?.try_into().ok()?))
}

/// Parses one datagram of a dump reply. Returns the counters found and `true` once the kernel
/// has sent `NLMSG_DONE`, which ends the dump.
///
/// Sockets whose reply has no `INET_DIAG_INFO` (or a `tcp_info` too short to hold the counters)
/// are skipped rather than reported as zero, so they do not hide real traffic.
pub fn parse_dump(buf: &[u8]) -> Result<(Vec<TcpCounters>, bool), DumpError> {
    let mut rows = Vec::new();
    let mut offset = 0usize;
    while offset < buf.len() {
        let len = read_u32(buf, offset).ok_or(DumpError::Truncated)? as usize;
        let kind = read_u16(buf, offset + 4).ok_or(DumpError::Truncated)?;
        if len < NLMSG_HDR_LEN || offset + len > buf.len() {
            return Err(DumpError::Truncated);
        }
        let payload = offset + NLMSG_HDR_LEN;
        let end = offset + len;
        match kind {
            NLMSG_DONE => return Ok((rows, true)),
            NLMSG_ERROR => {
                let errno = read_u32(buf, payload).ok_or(DumpError::Truncated)? as i32;
                // The kernel reports success as errno 0 (an ACK); anything else is a failure.
                if errno != 0 {
                    return Err(DumpError::Kernel(-errno));
                }
            }
            SOCK_DIAG_BY_FAMILY => {
                if let Some(row) = parse_message(&buf[payload..end])? {
                    rows.push(row);
                }
            }
            _ => {}
        }
        offset = align4(offset + len);
    }
    Ok((rows, false))
}

/// Parses one `inet_diag_msg` and its attributes. `Ok(None)` when no usable `tcp_info` exists.
fn parse_message(msg: &[u8]) -> Result<Option<TcpCounters>, DumpError> {
    if msg.len() < MSG_LEN {
        return Err(DumpError::Truncated);
    }
    let inode = read_u32(msg, 68).ok_or(DumpError::Truncated)? as u64;
    let cookie = read_u64(msg, 4 + 40).ok_or(DumpError::Truncated)?;

    let mut at = MSG_LEN;
    while at + 4 <= msg.len() {
        let attr_len = read_u16(msg, at).ok_or(DumpError::Truncated)? as usize;
        let attr_kind = read_u16(msg, at + 2).ok_or(DumpError::Truncated)?;
        if attr_len < 4 || at + attr_len > msg.len() {
            return Err(DumpError::Truncated);
        }
        if attr_kind == INET_DIAG_INFO {
            let info = &msg[at + 4..at + attr_len];
            if info.len() < TCPI_MIN_LEN {
                return Ok(None);
            }
            return Ok(Some(TcpCounters {
                cookie,
                inode,
                bytes_sent: read_u64(info, TCPI_BYTES_ACKED).ok_or(DumpError::Truncated)?,
                bytes_received: read_u64(info, TCPI_BYTES_RECEIVED).ok_or(DumpError::Truncated)?,
            }));
        }
        at += align4(attr_len);
    }
    Ok(None)
}

/// Live query: every IPv4 and IPv6 TCP socket visible to this user.
#[cfg(target_os = "linux")]
pub fn query_tcp() -> std::io::Result<Vec<TcpCounters>> {
    use std::io;

    struct Socket(libc::c_int);
    impl Drop for Socket {
        fn drop(&mut self) {
            // SAFETY: the descriptor was returned by `socket` and is closed exactly once here.
            unsafe { libc::close(self.0) };
        }
    }

    // SAFETY: plain syscall with constant arguments; the result is checked below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = Socket(fd);

    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: `timeval` is a valid option value of the stated size.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // Netlink sockets are addressed by port; port 0 with the kernel as destination is the default.
    // SAFETY: sockaddr_nl is plain old data; all-zero is a valid value (port 0, groups 0).
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: `addr` is a fully initialised sockaddr_nl of the size passed.
    let bound = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut all = Vec::new();
    let mut buf = vec![0u8; 256 * 1024];
    for request in tcp_dump_requests() {
        // SAFETY: the request buffer is valid for its length for the duration of the call.
        let sent = unsafe {
            libc::send(
                fd,
                request.as_ptr() as *const libc::c_void,
                request.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        loop {
            // SAFETY: `buf` is valid for `buf.len()` bytes.
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let (rows, done) =
                parse_dump(&buf[..n as usize]).map_err(|e| io::Error::other(e.to_string()))?;
            all.extend(rows);
            if done {
                break;
            }
        }
    }
    drop(socket);
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a `tcp_info` buffer with the two byte counters set.
    fn tcp_info(sent: u64, received: u64) -> Vec<u8> {
        let mut info = vec![0u8; TCPI_MIN_LEN];
        info[TCPI_BYTES_ACKED..TCPI_BYTES_ACKED + 8].copy_from_slice(&sent.to_ne_bytes());
        info[TCPI_BYTES_RECEIVED..TCPI_BYTES_RECEIVED + 8].copy_from_slice(&received.to_ne_bytes());
        info
    }

    fn attr(kind: u16, data: &[u8]) -> Vec<u8> {
        let len = 4 + data.len();
        let mut out = Vec::new();
        out.extend_from_slice(&(len as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(data);
        out.resize(align4(out.len()), 0);
        out
    }

    /// One `SOCK_DIAG_BY_FAMILY` message with the given inode, cookie and attributes.
    fn message(inode: u32, cookie: u64, attrs: &[u8]) -> Vec<u8> {
        let mut msg = vec![0u8; MSG_LEN];
        msg[0] = AF_INET;
        msg[4 + 40..4 + 48].copy_from_slice(&cookie.to_ne_bytes());
        msg[68..72].copy_from_slice(&inode.to_ne_bytes());
        msg.extend_from_slice(attrs);
        frame(SOCK_DIAG_BY_FAMILY, &msg)
    }

    fn frame(kind: u16, payload: &[u8]) -> Vec<u8> {
        let len = NLMSG_HDR_LEN + payload.len();
        let mut out = Vec::new();
        out.extend_from_slice(&(len as u32).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&0u16.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn done() -> Vec<u8> {
        frame(NLMSG_DONE, &[0u8; 4])
    }

    #[test]
    fn request_asks_for_tcp_with_info_extension() {
        let req = dump_request(AF_INET6, 7);
        assert_eq!(req.len(), NLMSG_HDR_LEN + REQ_LEN);
        assert_eq!(read_u16(&req, 4), Some(SOCK_DIAG_BY_FAMILY));
        assert_eq!(read_u16(&req, 6), Some(NLM_F_REQUEST | NLM_F_DUMP));
        let body = &req[NLMSG_HDR_LEN..];
        assert_eq!(body[0], AF_INET6);
        assert_eq!(body[1], IPPROTO_TCP);
        assert_eq!(body[2], EXT_INFO);
        assert_eq!(read_u32(body, 4), Some(ALL_TCP_STATES));
        assert_eq!(tcp_dump_requests().len(), 2);
    }

    #[test]
    fn reads_byte_counters_and_attributes_inode() {
        let attrs = attr(INET_DIAG_INFO, &tcp_info(1_000, 4_000));
        let mut buf = message(4242, 99, &attrs);
        buf.extend(done());
        let (rows, finished) = parse_dump(&buf).unwrap();
        assert!(finished);
        assert_eq!(
            rows,
            vec![TcpCounters {
                cookie: 99,
                inode: 4242,
                bytes_sent: 1_000,
                bytes_received: 4_000,
            }]
        );
    }

    #[test]
    fn skips_sockets_without_info_and_keeps_going() {
        let mut buf = message(1, 1, &attr(5, &[1, 2, 3, 4])); // some other attribute only
        buf.extend(message(2, 2, &attr(INET_DIAG_INFO, &tcp_info(8, 9))));
        buf.extend(message(3, 3, &attr(INET_DIAG_INFO, &[0u8; 16]))); // tcp_info too short
        buf.extend(done());
        let (rows, finished) = parse_dump(&buf).unwrap();
        assert!(finished);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].inode, 2);
    }

    #[test]
    fn multipart_replies_without_done_are_not_finished() {
        let buf = message(1, 1, &attr(INET_DIAG_INFO, &tcp_info(1, 2)));
        let (rows, finished) = parse_dump(&buf).unwrap();
        assert!(!finished);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn kernel_error_is_reported_with_errno() {
        let mut payload = (-13i32).to_ne_bytes().to_vec(); // -EACCES
        payload.extend_from_slice(&[0u8; 16]);
        let err = parse_dump(&frame(NLMSG_ERROR, &payload)).unwrap_err();
        assert_eq!(err, DumpError::Kernel(13));
        assert!(err.to_string().contains("13"));
    }

    #[test]
    fn ack_is_not_an_error() {
        let mut payload = 0i32.to_ne_bytes().to_vec();
        payload.extend_from_slice(&[0u8; 16]);
        let (rows, finished) = parse_dump(&frame(NLMSG_ERROR, &payload)).unwrap();
        assert!(rows.is_empty());
        assert!(!finished);
    }

    #[test]
    fn truncated_or_lying_lengths_are_rejected() {
        let mut buf = message(1, 1, &attr(INET_DIAG_INFO, &tcp_info(1, 2)));
        buf.truncate(buf.len() - 3);
        assert_eq!(parse_dump(&buf).unwrap_err(), DumpError::Truncated);
        assert_eq!(parse_dump(&[1, 2]).unwrap_err(), DumpError::Truncated);
        // A header claiming less than its own size.
        let mut short = frame(SOCK_DIAG_BY_FAMILY, &[0u8; 8]);
        short[0..4].copy_from_slice(&4u32.to_ne_bytes());
        assert_eq!(parse_dump(&short).unwrap_err(), DumpError::Truncated);
    }

    #[test]
    fn empty_buffer_is_an_empty_unfinished_reply() {
        assert_eq!(parse_dump(&[]).unwrap(), (Vec::new(), false));
    }
}
