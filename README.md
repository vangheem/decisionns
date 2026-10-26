# DecisionNS

DecisionNS is a DNS server for a home network. Clients ask it for names. It applies allow and block lists, then optional decision-model rules, and only then forwards the lookup to Cloudflare, Google, or another resolver you configure.

The decision step speaks the [SystemOne](https://docs.typesafe.ai/introduction) API. That is the same request shape used by [Jev](https://docs.typesafe.ai/introduction/quickstart) and by [Cloudflare Clef](https://huggingface.co/Cloudflare/clef). You send the domain as state and a set of typed questions. The model returns probabilities, not free text. DecisionNS turns those answers into allow or block using thresholds you set.

The model sees the domain name, not the page. Unfamiliar CDN and API names are normal. Rules should block when the name itself indicates the category, and an allowlist is the escape hatch when a decision is wrong.

## What happens to a lookup

1. Drop the query if it came from a public address. This is not an open resolver unless you turn that on.
2. Allowlist match: forward.
3. Blocklist match: answer with a sinkhole (`0.0.0.0` / `::`), `NXDOMAIN`, or `REFUSED`.
4. Infrastructure names (reverse DNS, `.local`, `.lan`, single-label names) are forwarded and are not sent to a model.
5. Rules run in priority order. The lowest number wins. A rule can allow, block, or decide.
6. A decide rule calls the configured service once per name, then caches the verdict. Later lookups for that name, including `AAAA` after `A`, reuse the cache.
7. If nothing matches, the name is forwarded.

A new device is recorded as `standard`. The seeded child-safety rule applies only to devices you mark `child`. Until a decision service is enabled, that rule is skipped and the lookup is forwarded. The admin overview says so.

## Run it

```bash
cd decisionns
cargo run --release
```

With no `config.toml`, DNS listens on port 5353 and the admin UI on port 8080, so you can try it without root. The first start prints an admin password and writes it to `data/initial-admin-password.txt`. Change it in the UI; that file is deleted when you do.

For the router, copy the example and bind port 53:

```bash
cp config.example.toml config.toml
# edit listen addresses if needed
cargo build --release
sudo ./target/release/decisionns --config config.toml
```

Port 53 needs root, or `sudo setcap cap_net_bind_service=+ep ./target/release/decisionns`. On a Mac, port 53 is often taken by mDNSResponder; a Pi or other always-on Linux host is the usual place to run this.

Reset a forgotten admin password with `--reset-admin-password`. If `DECISIONNS_ADMIN_PASSWORD` or `admin.password` is set, that value is used. Otherwise a new password is printed.

## Point the router at it

Give the DecisionNS host a DHCP reservation so its LAN address does not move.

In the router, set the DNS server advertised to LAN clients to that address. The setting is usually under LAN or DHCP, not the WAN DNS page. Clients should query DecisionNS themselves. If the router proxies DNS, every device shows up as the router and per-device profiles cannot work. Filtering still works; you can mark the router's IP as `child` if that is the only view you have.

Renew DHCP on clients after the change. Some phones and browsers use their own DNS-over-HTTPS and will ignore the router. Settings has a button that blocklists common DoH endpoints. That does not break DecisionNS itself: upstream DoH is opened by this process, not by clients. Firefox and Chrome can also have "secure DNS" turned off.

Do not port-forward the admin UI. It is limited to private addresses, loopback, and Tailscale (`100.64.0.0/10`) unless `admin.allow_public` is set.

## Decision services

Open the admin UI, then Services.

**Jev.** Kind `jev`, base URL `https://api.typesafe.ai`, model `jev-latest`. Create a key at [console.typesafe.ai](https://console.typesafe.ai/keys), paste it, enable the service, and use Test with a domain name. The seeded Child safety rule already points at this service.

**Clef.** Kind `clef`, model `clef`, base URL of a process that implements `POST /v1/systemone`. Clef is a local model. The Hugging Face card's `systemone()` helper returns the same JSON this server expects. A small wrapper is enough:

```python
from flask import Flask, request, jsonify
from joint_schema_model import systemone, load_release_model

app = Flask(__name__)
model, processor = load_release_model("/path/to/clef", device="cuda")

@app.post("/v1/systemone")
def decide():
    return jsonify(systemone(model, processor, request.get_json()))
```

An empty API key is fine for a local Clef. Enable the service, then point a rule at it.

Both services accept the same questions. A question is a noul (yes/no probability), a choice (one option plus a distribution), or a score. DecisionNS blocks when:

- a choice question lands on a value listed in the rule, and confidence is at least the minimum, or
- a score is at least its threshold, with the same confidence check, or
- the named noul is at least its threshold (the noul value is already a probability).

Low confidence follows the rule's "if uncertain" action. A timeout or HTTP error follows "if the model errors". Both default to allow, so a dead API does not take the house offline. Set them to block on a child rule if you would rather fail closed. The first lookup of a new name waits on the model (often a few hundred milliseconds for Jev or Clef). After that, the cache answers immediately.

The seeded questions ask whether a name is unsafe for a child, and which category it looks like. `unknown` is not a blocking category. Raise the noul threshold if you see false blocks; lower it if obvious names get through. Clear the decision cache after you change a threshold, or wait for the TTL.

## Admin

The UI is served by the same process. From it you can:

- see queries, blocks, and per-device totals over 24 hours, 7 days, or 30 days
- name devices and set a profile (`unrestricted`, `standard`, `child`)
- edit rules, including a time window (local time on this host; an end hour before the start hour wraps past midnight)
- maintain allow and block lists, or paste a hosts file
- add and test decision services
- simulate a lookup without waiting for a client
- change upstreams, block style, cache TTL, log retention, and the admin password

Hourly counts are kept longer than the query log. Set query log retention to 0 if you want counts without storing names. The log is a record of what the house looked up. Keep the admin password to yourself.

## Config

`config.example.toml` is the production shape. Listen addresses and the initial admin username are read at startup. Upstream servers in that file only seed a new database. After the first run, change upstreams in the admin UI.

`dns.allow_public` defaults to false. Leave it that way. An open resolver on port 53 is a reflection amplifier.

## Limits

- This is a forwarder, not a recursive resolver. It needs an upstream.
- Safety decisions are about the name, not the content of the site. A harmless name on a bad host will be allowed. A rude name on a harmless host may be blocked. Lists exist for both cases.
- HTTPS clients cannot be shown a block page. A sinkhole makes the connection fail. The reason is in the query log.
- Browsers using DoH, and devices with a hardcoded resolver, bypass this server until those paths are closed.
- DecisionNS does not inspect traffic after the lookup. It only decides whether the name may be resolved.

## Development

```bash
cargo test
```

Unit tests cover pattern matching, rule priority, and how SystemOne answers become a verdict. The integration test starts a local upstream and checks that a blocklisted name is sinkholed while another name is forwarded.
