//! UDP and TCP DNS listeners. This is a filtering forwarder, not a
//! recursive resolver: accepted names are sent upstream unchanged.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{watch, Semaphore};

use crate::app::App;
use crate::model::{now_ms, BlockMode, FailMode, QueryEvent}; // FailMode used below
use crate::names::normalize_name;
use crate::policy::{self, QueryContext, Step};

const MAX_IN_FLIGHT: usize = 256;

pub async fn serve_udp(socket: UdpSocket, app: App, mut shutdown: watch::Receiver<bool>) {
    let socket = Arc::new(socket);
    let sem = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut buf = [0u8; 4096];
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            rec = socket.recv_from(&mut buf) => {
                let (n, peer) = match rec {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "udp recv failed");
                        continue;
                    }
                };
                let packet = buf[..n].to_vec();
                let permit = match sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let app = app.clone();
                let socket = socket.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(response) = app.handle_dns(peer.ip(), &packet, true).await {
                        if let Err(e) = socket.send_to(&response, peer).await {
                            tracing::debug!(error = %e, "udp send failed");
                        }
                    }
                });
            }
        }
    }
}

pub async fn serve_tcp(listener: TcpListener, app: App, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            acc = listener.accept() => {
                let (mut sock, peer) = match acc {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "tcp accept failed");
                        continue;
                    }
                };
                let app = app.clone();
                tokio::spawn(async move {
                    let _ = sock.set_nodelay(true);
                    for _ in 0..8 {
                        let mut len_buf = [0u8; 2];
                        if sock.read_exact(&mut len_buf).await.is_err() {
                            return;
                        }
                        let len = u16::from_be_bytes(len_buf) as usize;
                        if len == 0 || len > 65_535 {
                            return;
                        }
                        let mut packet = vec![0u8; len];
                        if sock.read_exact(&mut packet).await.is_err() {
                            return;
                        }
                        let Some(response) = app.handle_dns(peer.ip(), &packet, false).await else {
                            return;
                        };
                        let n = response.len() as u16;
                        if sock.write_all(&n.to_be_bytes()).await.is_err()
                            || sock.write_all(&response).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        }
    }
}

impl App {
    /// Returns `None` when the packet should be dropped (malformed, or a
    /// public client on a resolver that is not open to the internet).
    pub async fn handle_dns(&self, peer: IpAddr, packet: &[u8], udp: bool) -> Option<Vec<u8>> {
        let peer = canonical_ip(peer);
        let started = Instant::now();
        match self.handle_inner(peer, packet, udp, started).await {
            Ok(bytes) => Some(bytes),
            Err(HandleErr::Ignore) => None,
        }
    }

    async fn handle_inner(
        &self,
        peer: IpAddr,
        packet: &[u8],
        udp: bool,
        started: Instant,
    ) -> Result<Vec<u8>, HandleErr> {
        let request = Message::from_vec(packet).map_err(|_| HandleErr::Ignore)?;
        if request.metadata.message_type != MessageType::Query {
            return Err(HandleErr::Ignore);
        }
        let snap = self.snapshot();
        if !snap.settings.dns_allow_public && !is_lan(peer) {
            tracing::warn!(%peer, "dropped query from non-private address");
            return Err(HandleErr::Ignore);
        }
        if request.metadata.op_code != OpCode::Query || request.queries.is_empty() {
            return Ok(error_response(&request, ResponseCode::NotImp));
        }
        let query = request.queries[0].clone();
        let qname_raw = query.name().to_string();
        let domain = normalize_name(&qname_raw);
        let qtype = query.query_type().to_string();
        let device_ip = peer.to_string();
        let profile = snap
            .device_by_ip(&device_ip)
            .map(|d| d.profile.clone())
            .unwrap_or_else(|| "standard".into());
        let ctx = QueryContext::new(&domain, &qtype, &device_ip, &profile);

        let step = policy::classify(&snap, &ctx);
        let mut rule_id = None;
        let mut decision_json = None;
        let mut decided = false;
        let (action, reason, response) = match step {
            Step::Allow { reason } => {
                match self.forward(&snap, packet).await {
                    Ok(bytes) => ("allow".to_string(), reason, fit(bytes, &request, udp)),
                    Err(e) => {
                        tracing::warn!(domain = %domain, error = %e, "upstream failed");
                        (
                            "error".to_string(),
                            format!("upstream error"),
                            error_response(&request, ResponseCode::ServFail),
                        )
                    }
                }
            }
            Step::Block { reason, rule_id: id } => {
                rule_id = id;
                (
                    "block".to_string(),
                    reason,
                    blocked_response(&request, &query, snap.settings.block_mode, snap.settings.block_ttl),
                )
            }
            Step::Decide { rule } => {
                decided = true;
                rule_id = Some(rule.rule.id);
                let service = snap.service(rule.rule.service_id.unwrap_or(0)).cloned();
                match service {
                    None => {
                        self.finish_allow_or_block(
                            &snap,
                            packet,
                            &request,
                            udp,
                            rule.rule.on_error,
                            "decision service missing",
                        )
                        .await
                    }
                    Some(service) => {
                        let ttl = std::time::Duration::from_secs(snap.settings.decision_cache_ttl_secs);
                        match self.decider().evaluate(&service, &rule.rule, &ctx, ttl).await {
                            Ok(decision) => {
                                decision_json = Some(truncate_json(&decision.answers));
                                let reason = format!(
                                    "rule {}: {}{}",
                                    rule.rule.name,
                                    decision.verdict.reason,
                                    if decision.cached { " (cached)" } else { "" }
                                );
                                if decision.verdict.block {
                                    (
                                        "block".to_string(),
                                        reason,
                                        blocked_response(
                                            &request,
                                            &query,
                                            snap.settings.block_mode,
                                            snap.settings.block_ttl,
                                        ),
                                    )
                                } else {
                                    match self.forward(&snap, packet).await {
                                        Ok(bytes) => ("allow".to_string(), reason, fit(bytes, &request, udp)),
                                        Err(e) => {
                                            tracing::warn!(domain = %domain, error = %e, "upstream failed");
                                            (
                                                "error".to_string(),
                                                "upstream error".into(),
                                                error_response(&request, ResponseCode::ServFail),
                                            )
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(domain = %domain, error = %e, rule = %rule.rule.name, "decision failed");
                                let reason = format!("decision error ({})", rule.rule.on_error.as_str());
                                self.finish_allow_or_block(
                                    &snap,
                                    packet,
                                    &request,
                                    udp,
                                    rule.rule.on_error,
                                    &reason,
                                )
                                .await
                            }
                        }
                    }
                }
            }
        };

        let latency_ms = started.elapsed().as_millis() as i64;
        if action == "block" {
            tracing::info!(%peer, %domain, %qtype, %reason, "blocked");
        } else {
            tracing::debug!(%peer, %domain, %qtype, %action, %reason, latency_ms, "query");
        }
        self.log(QueryEvent {
            ts: now_ms(),
            device_ip,
            qname: domain,
            qtype,
            action: action.clone(),
            reason,
            rule_id,
            decision_json,
            latency_ms,
            decided,
        });
        Ok(response)
    }

    async fn finish_allow_or_block(
        &self,
        snap: &crate::model::Snapshot,
        packet: &[u8],
        request: &Message,
        udp: bool,
        mode: FailMode,
        reason: &str,
    ) -> (String, String, Vec<u8>) {
        if mode == FailMode::Block {
            let query = request.queries[0].clone();
            return (
                "block".into(),
                reason.into(),
                blocked_response(request, &query, snap.settings.block_mode, snap.settings.block_ttl),
            );
        }
        match self.forward(snap, packet).await {
            Ok(bytes) => ("allow".into(), reason.into(), fit(bytes, request, udp)),
            Err(_) => (
                "error".into(),
                "upstream error".into(),
                error_response(request, ResponseCode::ServFail),
            ),
        }
    }

    async fn forward(&self, snap: &crate::model::Snapshot, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        crate::upstream::forward(
            self.http(),
            &snap.settings.upstream_servers,
            packet,
            snap.settings.upstream_timeout_ms,
        )
        .await
    }
}

enum HandleErr {
    Ignore,
}

pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

pub fn is_lan(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || is_cgnat(v4),
        IpAddr::V6(v6) => v6.is_loopback() || is_ula(v6) || is_link_local_v6(v6),
    }
}

fn is_cgnat(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (64..128).contains(&o[1])
}

fn is_ula(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

fn is_link_local_v6(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

fn error_response(request: &Message, code: ResponseCode) -> Vec<u8> {
    let mut msg = Message::error_msg(request.metadata.id, request.metadata.op_code, code);
    msg.metadata.recursion_desired = request.metadata.recursion_desired;
    msg.metadata.recursion_available = true;
    if let Some(query) = request.queries.first() {
        msg.add_query(query.clone());
    }
    msg.to_vec().unwrap_or_default()
}

fn blocked_response(
    request: &Message,
    query: &hickory_proto::op::Query,
    mode: BlockMode,
    ttl: u32,
) -> Vec<u8> {
    let mut msg = Message::response(request.metadata.id, request.metadata.op_code);
    msg.metadata.recursion_desired = request.metadata.recursion_desired;
    msg.metadata.recursion_available = true;
    msg.add_query(query.clone());
    match mode {
        BlockMode::Refused => {
            msg.metadata.response_code = ResponseCode::Refused;
        }
        BlockMode::Nxdomain => {
            msg.metadata.response_code = ResponseCode::NXDomain;
        }
        BlockMode::Sinkhole => match sinkhole(query.name().clone(), query.query_type(), ttl) {
            Some(record) => {
                msg.metadata.response_code = ResponseCode::NoError;
                msg.add_answer(record);
            }
            None => {
                msg.metadata.response_code = ResponseCode::NXDomain;
            }
        },
    }
    msg.to_vec().unwrap_or_else(|_| error_response(request, ResponseCode::ServFail))
}

fn sinkhole(name: Name, qtype: RecordType, ttl: u32) -> Option<Record> {
    match qtype {
        RecordType::A => Some(Record::from_rdata(name, ttl, RData::A(A(Ipv4Addr::UNSPECIFIED)))),
        RecordType::AAAA => Some(Record::from_rdata(
            name,
            ttl,
            RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
        )),
        _ => None,
    }
}

fn fit(mut bytes: Vec<u8>, request: &Message, udp: bool) -> Vec<u8> {
    if bytes.len() >= 2 {
        let id = request.metadata.id.to_be_bytes();
        bytes[0] = id[0];
        bytes[1] = id[1];
    }
    if !udp {
        return bytes;
    }
    let max = udp_max(request);
    if bytes.len() <= max {
        return bytes;
    }
    match Message::from_vec(&bytes) {
        Ok(mut msg) => {
            msg.metadata.truncation = true;
            msg.answers.clear();
            msg.authorities.clear();
            msg.additionals.clear();
            msg.edns = request.edns.clone();
            msg.to_vec().unwrap_or(bytes)
        }
        Err(_) => bytes,
    }
}

fn udp_max(request: &Message) -> usize {
    if request.edns.is_some() {
        (request.max_payload() as usize).clamp(512, 4096)
    } else {
        512
    }
}

fn truncate_json(value: &serde_json::Value) -> String {
    let text = value.to_string();
    if text.len() <= 4000 {
        text
    } else {
        format!("{{\"truncated\":true,\"len\":{}}}", text.len())
    }
}

pub fn encode_query(name: &str, id: u16) -> anyhow::Result<Vec<u8>> {
    let name = Name::from_utf8(format!("{}.", name.trim_end_matches('.')))?;
    let mut msg = Message::query();
    msg.metadata.id = id;
    msg.metadata.recursion_desired = true;
    msg.add_query(hickory_proto::op::Query::query(name, RecordType::A));
    Ok(msg.to_vec()?)
}
