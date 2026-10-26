//! Forward an accepted query to Cloudflare, Google, or any other resolver.
//!
//! A server string is either a DoH URL (`https://cloudflare-dns.com/dns-query`)
//! or a UDP/TCP address (`1.1.1.1:53`, `[2606:4700:4700::1111]:53`).

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub enum Upstream {
    Doh(String),
    Udp(SocketAddr),
}

pub fn parse_upstream(raw: &str) -> anyhow::Result<Upstream> {
    let raw = raw.trim();
    if raw.starts_with("https://") || raw.starts_with("http://") {
        return Ok(Upstream::Doh(raw.to_string()));
    }
    let addr = raw
        .parse::<SocketAddr>()
        .map_err(|e| anyhow::anyhow!("upstream `{raw}` is not a URL or ip:port: {e}"))?;
    Ok(Upstream::Udp(addr))
}

pub async fn forward(
    http: &reqwest::Client,
    servers: &[String],
    query: &[u8],
    timeout_ms: u64,
) -> anyhow::Result<Vec<u8>> {
    if servers.is_empty() {
        anyhow::bail!("no upstream servers");
    }
    let budget = Duration::from_millis(timeout_ms.max(200));
    let mut last = String::from("no upstream attempted");
    for server in servers {
        let parsed = match parse_upstream(server) {
            Ok(v) => v,
            Err(e) => {
                last = e.to_string();
                continue;
            }
        };
        match forward_one(http, &parsed, query, budget).await {
            Ok(bytes) if !bytes.is_empty() => return Ok(bytes),
            Ok(_) => last = format!("{server} returned an empty response"),
            Err(e) => last = format!("{server}: {e}"),
        }
    }
    anyhow::bail!(last)
}

async fn forward_one(
    http: &reqwest::Client,
    server: &Upstream,
    query: &[u8],
    budget: Duration,
) -> anyhow::Result<Vec<u8>> {
    match server {
        Upstream::Doh(url) => doh(http, url, query, budget).await,
        Upstream::Udp(addr) => {
            let udp = udp_query(*addr, query, budget).await?;
            if tc_bit(&udp) {
                return tcp_query(*addr, query, budget).await;
            }
            Ok(udp)
        }
    }
}

async fn doh(
    http: &reqwest::Client,
    url: &str,
    query: &[u8],
    budget: Duration,
) -> anyhow::Result<Vec<u8>> {
    let response = http
        .post(url)
        .timeout(budget)
        .header("accept", "application/dns-message")
        .header("content-type", "application/dns-message")
        .header("user-agent", format!("decisionns/{}", crate::VERSION))
        .body(query.to_vec())
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("doh: {e}"))?;
    if !response.status().is_success() {
        anyhow::bail!("doh HTTP {}", response.status());
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| anyhow::anyhow!("doh body: {e}"))?;
    Ok(bytes.to_vec())
}

async fn udp_query(addr: SocketAddr, query: &[u8], budget: Duration) -> anyhow::Result<Vec<u8>> {
    let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;
    timeout(budget, sock.send(query))
        .await
        .map_err(|_| anyhow::anyhow!("udp send timed out"))??;
    let mut buf = vec![0u8; 4096];
    let n = timeout(budget, sock.recv(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("udp recv timed out"))??;
    buf.truncate(n);
    Ok(buf)
}

async fn tcp_query(addr: SocketAddr, query: &[u8], budget: Duration) -> anyhow::Result<Vec<u8>> {
    let mut stream = timeout(budget, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("tcp connect timed out"))??;
    let len = u16::try_from(query.len()).map_err(|_| anyhow::anyhow!("query too large"))?;
    timeout(budget, stream.write_all(&len.to_be_bytes()))
        .await
        .map_err(|_| anyhow::anyhow!("tcp write timed out"))??;
    timeout(budget, stream.write_all(query))
        .await
        .map_err(|_| anyhow::anyhow!("tcp write timed out"))??;
    let mut len_buf = [0u8; 2];
    timeout(budget, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| anyhow::anyhow!("tcp read timed out"))??;
    let n = u16::from_be_bytes(len_buf) as usize;
    if n > 65_535 {
        anyhow::bail!("tcp response length {n}");
    }
    let mut buf = vec![0u8; n];
    timeout(budget, stream.read_exact(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("tcp read timed out"))??;
    Ok(buf)
}

fn tc_bit(message: &[u8]) -> bool {
    message.len() >= 3 && message[2] & 0x02 != 0
}
