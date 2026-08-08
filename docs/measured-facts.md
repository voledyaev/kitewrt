# Measured facts, known limits, and what is still open

Everything here that says "measured" was measured, on a real kernel — most of it
on the QEMU lab (5.4.238, fw3 + iptables-legacy, matching the GL-MT6000) or on
stock OpenWrt VMs from 21.02 through 24.10. Everything that says "unverified"
was not, and is marked so deliberately.

This is a reference, not a changelog. It exists so the next person does not
re-derive an answer that already cost a day of measurement — and so the things
that are *still* wrong are written down rather than remembered. Where an entry
explains a decision, the reasoning also lives in a comment next to the code it
governs; this file is the index, not the only copy.

Six agents ran against the QEMU lab (kernel 5.4.238, fw3 + iptables-legacy,
matching the GL-MT6000) and a stock OpenWrt 21.02.7 x86-64 VM. Everything below
that says "measured" was measured; everything that says "unconfirmed" was not.

Fixed items are listed with their commit so the reasoning is findable. Open
items are ordered by value, and each says what the fix is and what evidence
justifies it — the point is that the next person does not have to re-derive it.

**Status: the ranked queue below has been worked through.** What each item
turned into is recorded in the "Fixed" table at the bottom, with its commit.
The open list that remains is at the very end, under "Still open".

---

## The audit that produced most of this, and what each item turned out to be

### 1. The capture rebuild leaks ~1.6 s of plaintext, and it can be made hitless

**Measured**, continuous 2000 pps from a LAN client, escaped packets counted in
`filter/FORWARD` (captured packets never traverse FORWARD, so the count is
exact) and corroborated at the far-end sink:

> **The first row's numbers are superseded.** A larger sample put the in-place
> rebuild at 2,060–2,280 packets over 1.06–1.17 s — same conclusion, ~30%
> smaller. See "Lab verification of the hitless swap" below; the table is left
> as it was recorded.

| strategy | escaped per rebuild | window |
|---|---|---|
| current (`_remove_locked` then rebuild), 8639-net bypass | 3070–3463 (8/8 cycles) | **1.54–1.73 s** |
| current, no bypass list | 2278–2457 (5/5) | 1.14–1.23 s |
| build second chain, `-I PREROUTING 1 -j new` then `-D … -j old` | **0 (10 repoints)** | **0** |
| build second chain, `-R PREROUTING <n> -j new` | **0 (16 repoints)** | **0** |

The sink recorded **9736 datagrams carrying the LAN client's own source
address** delivered in the clear under the current strategy.

**Fix:** build a fully-populated second chain, then repoint the hook. Prefer
`-I` + `-D` over `-R`: both measured hitless, but `-R` needs a rule index, and
an fw3 insert between reading the index and replacing it would clobber someone
else's rule. Costs nothing — the same ~0.7–0.9 s of iptables calls, done off to
the side.

**Scope, important:** an ordinary apply does **not** leak (5 applies + 70 s of
watchdog ticks → 0 escaped packets; `install()`'s early return works). This
fires only on real rebuilds: `firewall restart`, a bypass-list change, an uplink
change, any `_matches` mismatch.

Note `_remove_locked` and `sweep()` must learn about the temporary chain name,
or a crash mid-swap leaves a hooked chain nothing cleans up.

### 2. README — a stranger cannot finish, and the uninstall command does not exist

From the clean-room install on stock OpenWrt. Full proposed text is in the agent
report; the load-bearing ones:

- `kitewrt --uninstall root@…` → `sh: kitewrt: command not found`. Step 2
  installs into a uv venv; every other invocation says `uv run kitewrt`. Same
  bug in `installer/artifacts/README.md` (`kitewrt --probe`).
- The "what happens, in order" table still describes `pip install` of a
  hand-listed package set. Reality: uv is downloaded to the router (SHA-256
  pinned) and installs from the hashed `installer/resources/requirements.txt`.
- The offline escape hatch omits the **uv** artifact, so someone behind a
  GitHub block pre-places only sing-box and still fails.
- Uninstall is documented as leaving the pip deps; it removes `/usr/lib/kitewrt`
  including `vendor/`. Measured re-install: 56 s, not the promised ~30 s.
- Uninstall deletes `/etc/kitewrt` — **subscriptions and credentials** — and the
  End-state list does not say so, while the install section boasts that
  `/etc/kitewrt` survives a firmware upgrade. The natural inference is wrong.
- The installer switches the router's TCP congestion control to **BBR
  system-wide**; BBR is mentioned only in the uninstall section.
- No prerequisites block (uv on the admin machine is a link, not an
  instruction), no troubleshooting section, every example uses `192.168.8.1`
  without saying to substitute.
- Two bullets still describe the tun architecture the same file says was
  replaced. Test count says ~440; actual 574 at the time of the audit. (The
  README no longer quotes a count — 726 as of this pass — precisely because it
  is a number that drifts every commit and nobody re-checks.)

### 3. Rules documents can inject arbitrary sing-box route-rule keys

`_validate_rule` checks markers, outbound, ≥1 matcher and regex length, but
whitelists **no keys**. Confirmed passing both our validator and `sing-box
check`:

```json
{"domain_suffix":["victim-bank.example"],"outbound":"proxy",
 "override_address":"203.0.113.66","override_port":8443}
```

A hostile rules document rewrites the dial destination for matched domains — a
redirect/interception primitive. **Fix:** whitelist the accepted keys.

### 4. `rule_set` remote-URL SSRF guard only blocks IP literals

`_validate_rule_set` calls `blocks_ssrf(host)` (literals only), not the
resolving guard used for the top-level rules/subscription URL:

```
blocks_ssrf('127.0.0.1')                = True   rejected
blocks_ssrf('localhost')                = False  ACCEPTED → http://localhost:9090/configs
blocks_ssrf('metadata.google.internal') = False  ACCEPTED
```

sing-box then fetches them direct from the router, reaching the local Clash
controller. **Fix:** resolve and block on the answer; reject bare names.

### 5. `_load_bypass_set` builds its restore script on the event loop

`_write_script`'s own comment says the point was to keep this off the loop; only
the `open()`/`write()` was moved. The multi-megabyte f-string comprehension plus
`"\n".join` stayed on it. **Measured event-loop stall:** 9.6 ms (0 nets) →
37.9 ms (8639) → **203.5 ms** (50000).

### 6. `/api/state` returns the whole bypass list on every poll

**Measured** with the 8640-net list: **161,832 bytes, p50 324 ms, max 499 ms**,
versus 28 bytes / 73 ms for `/api/health`. The UI polls this. Return a count;
the UI only renders `.length`.

### 7. `--probe` reports almost nothing

`installer/flows.py` runs `command -v opkg python3 pip3 sing-box fw3 uci
iptables`. busybox `ash`'s `command -v` takes **one** argument, so everything
after `opkg` is silently ignored. `installer/artifacts/README.md` tells users to
determine their Python version and platform with `--probe`; it prints neither.

### 8. httpx INFO logging evicts real errors from the log ring

Two `HTTP Request:` lines per second at `daemon.err`. On a router with a small
ring this buries the actual error within ~2 minutes — it measurably slowed the
clean-room agent's diagnosis of the `ip-full` blocker. Set the `httpx` logger to
WARNING.

### 9. Smaller

- `_atomic_write_durable` swallows `OSError` from the directory fsync. On the
  target stack it succeeds (measured), so nothing is wrong today — but on a
  filesystem that rejected it the lost guarantee would be invisible. Worth a
  comment recording that it was measured, not assumed.
- Dashboard spends state hues on decoration (`text-accent` on WAN down,
  `text-success` on WAN up), which collides with success/warning/error meaning
  protected/unverified/not-protected. Part of the D1 design integration.
- `insecure=1` in a subscription link disables TLS verification for that node.
  Standard client behaviour, but the UI gives no signal.

---

## Measured facts worth not re-deriving

**`hash:net` is NOT O(1).** Cost scales with the number of *distinct prefix
lengths*, not entry count. Same 8640 entries: 14 lengths → 1635 ns for a
non-member lookup, 1 length → 790 ns. 8640 → 50000 entries at 14 lengths is
flat. Decomposed: ~710 ns fixed, ~66 ns per distinct prefix length probed. A
member stops early; a non-member — every proxied packet — pays the full scan.
On real GSO-aggregated TCP the whole effect is **+4.5% router CPU per gigabyte**
versus a plain CIDR. The memory claim (~340 KB at 15,000) does check out.

**Chain traversal is not a bottleneck.** 38.7 ns per rule per packet
(least-squares over 0/100/500/1000 rules). The 12 rules a proxied packet walks
cost 0.46 µs — a quarter of *one* ipset lookup. Reordering was tested three ways
on real traffic and bought nothing; hoisting the bypass rule measured *worse*
(4930 → 4518 Mb/s). **Leave the order alone** — it is load-bearing for
correctness and effectively free.

**The terminating `-j DROP` costs nothing.** Zero measurable effect on
throughput, pps or CPU, and its counter stayed at 0 through every TCP/UDP load —
no TCP/UDP packet ever reaches it. It does not break fragmented UDP:
`nf_defrag_ipv4` reassembles before the chain, so a 3000-byte datagram matched
the UDP TPROXY rule as one packet.

**Throughput, from a LAN client with a no-capture baseline on the same wire:**
plain 4864 Mb/s → bypass-ipset 4591 (92%) → tproxy 3269 (67%), CPU-s/Gb 0.381 →
0.402 → 0.528. The project's earlier figures on this VM class were plain 5.98 /
tproxy 3.54 (59%), so nothing regressed.

**Nothing accumulates.** 60 install/remove cycles + 100 applies: ruleset
byte-identical, ipset counts identical, +8 KB and +196 KB RSS, +1 fd.

**Durability holds on the real storage stack.** `fsync()` on a directory *does*
propagate through overlayfs to f2fs on kernel 5.4 — block-layer counters show
+4 write_ios / +40 sectors, identical to raw f2fs, and it returns success rather
than `EINVAL`. 8 power cuts, 0 lost acknowledged writes, 0 corruption. The
control matters: with the directory fsync removed and the probe made the last
thing to touch f2fs before the cut, it lost a generation 3/3 times, with f2fs
roll-forward recovering `state.tmp` but **not** the rename. The directory fsync
is load-bearing on this stack, not decoration.

Caveats stated honestly: the overlay `lowerdir` was a plain directory rather
than the router's squashfs (irrelevant to directory fsync, which acts on the
upper; the merged case was covered separately), and qemu survives `sysrq-b`, so
the test measures whether f2fs *issued* the I/O — which is the question — but
does not exercise a device write cache below the guest.

---

## Lab verification of the hitless capture swap

72 rebuilds under ~1950 pps on the QEMU 5.4 kernel, escapes counted in
filter/FORWARD (property checked, not assumed: a correct capture gave 0 there
while 14,000 packets crossed) and corroborated at the far-end sink:

| | new | old |
|---|---|---|
| escapes per rebuild | **0** (72/72) | 2,162 mean (2,060-2,280) |
| share of offered packets lost | 0 of 219,300 | **25,946 of 33,495 = 77.5%** |
| unproxied seconds per rebuild | 0 | 1.06-1.17 s |
| SIGKILL mid-swap, 8 s under load | 0 escapes, 3/3 kill points | n/a |
| 14 × `firewall restart` racing 14 rebuilds | 2,654 escapes | 33,435 |
| 60 rebuilds: ip rules / accepts / chains | 1 / 1 / 1 throughout | — |

The 2,654 that still escape under an fw3 restart are fw3's own flush window —
the mangle table is wiped and nothing of ours is live to be handed over. That is
inherent and unchanged; the 12.6× reduction is the swap's contribution.

**This supersedes the first table's "3070-3463 packets / 1.54-1.73 s"** for the in-place
rebuild. Same conclusion, ~30% smaller number, larger sample.

Those runs drove `divert.install()` directly, to control timing and inject
faults. The **daemon** path was then exercised separately on the second VM, and
is clean: VPN toggled off/on ten times through `/api/toggle`, plus an
`/etc/init.d/firewall restart` that wiped the hook (0 hooks immediately after)
and was healed by the watchdog within one 30 s tick — back to one hook, 15
rules. Throughout, and after `/etc/init.d/kitewrt stop`, the counts were exactly
1/1/1/1 or 0/0/0/0 (hook, chain, ip rule, INPUT accept) with no staging chain
surviving and nothing matching error/traceback in the log.

**Two claims in the fix were refuted by measurement** (both corrected in
an earlier change): the double-hook window is fail-closed, not inert — 7,620 packets
(~600 pps) demonstrably reach the staging chain, and what holds is that only
packets the old chain RETURNs get there, so it can capture more but never
release what the old chain captured. And `_finish_swap` claimed idempotence
while being a full teardown when no swap was in flight: 4,180 escaped packets
in one 2.2 s call, reachable by deleting a single bookkeeping line.

## Still open — the honest list

*(Updated after a second round: rules-validator hardening, installer supply
chain, a JS test runner, and edge-case hunts on 21.02/fw3 and 24.10/fw4. Almost
everything below the first section is now fixed; what remains is listed here
rather than dropped.)*

### The measured limit nobody can fix by validating harder

**A capture flushed between watchdog ticks is invisible for up to 30 s, and the
dashboard says CAPTURED throughout.** Quantified deterministically on fw3, where
`/etc/init.d/firewall restart` really does flush the mangle table:

    t= 0.3s  hook=0  api capture=True  age= 2.1s  leaked=6
    t=17.2s  hook=0  api capture=True  age=19.3s  leaked=8442
    t=32.0s  hook=0  api capture=True  age=33.9s  leaked=15839
    t=34.4s  hook=0  api capture=False age= 1.1s  leaked=17062
    t=36.7s  hook=1  (capture restored)

**34.4 s, 15,839 plaintext packets**, `last_error` empty the whole time. The
capture reading never went stale — `capture_age_s` peaked at 33.9 s against the
UI's 95 s threshold — because it was *fresh evidence of a state that had already
changed*. The "lost and restored" note appears only afterwards, as `ok: true`.

This is polling, and the honest options are all trade-offs: a shorter watchdog
interval costs CPU on an A53 (a 5 s `iptables -S` loop was measured at ~18% of a
core), and there is no netfilter change notification to subscribe to. Recorded
here as a known, measured bound rather than closed. On fw4 the trigger is much
rarer — a `firewall restart` does not flush the capture there.

### Still genuinely open

Nine adversarial passes ran after the queue above was cleared (security, UI,
data plane, performance, clean-room install, and four fresh OpenWrt targets).
Most of what they found is fixed and committed. **This is what is not.** Nothing
here is believed to break a working install; several are things a public project
should not ship indefinitely.

The rules-validator section, the `is_running()`/`pidof` item, the server-`name`
cap, the `health.ts` test-runner item and two of the four installer items that
used to sit here are gone from this list because they were fixed — see the
"Fixed after that" table above for the commits.

### Installer / supply chain

- The GitHub-blocked failure message does not repeat the artifact filename,
  which was printed ~25 lines earlier.
- `installer/artifacts/README.md`'s worked example names sing-box `1.13.13`
  while the installer and CI pin `1.13.16`. Harmless (the reader substitutes the
  real version) but it is a number that drifts every bump.

### Daemon

- **`State.snapshot()` deep-copies everything on every read**, which with the
  payload trimmed is now the dominant cost of `/api/state`. Left alone
  deliberately — callers rely on being free to mutate — but it is the next thing
  to look at if the dashboard feels slow. **The recorded cost is disputed**; see
  "One number in here is wrong" under Environment notes.
- **`POST /{sub}/refresh` reads `active_server` from a snapshot taken before its
  own fetch**, so a server switch during that fetch makes it signal (or skip)
  the wrong apply. `subscriptions.refresh_all` re-reads for exactly this reason
  and its comment used to claim the route "gets this right"; it does not. The
  window is one fetch rather than a loop, which is why this is here and not
  above.
- **`/api/exit-ip` cannot see a 200-shaped block page.** The guard rejects
  non-2xx only; a captive portal answering 200 with HTML parses to empty strings
  and is served as `available: true` with a blank IP and country.
- An **orphan `kitewrt_tproxy_next` chain** can survive a crash between creating
  and hooking it. Inert, cleared by the next rebuild or by `sweep()`.

### UI

- Three places still spend a state hue on a non-state fact: the `polling`
  connectivity pill, `setup needed`, and the reachability ticks — three teal
  ticks can sit under a red LEAKING card. (Partially addressed in an earlier change,
  which stopped the *data* tiles doing it; the three above are separate.)

The rest of the UI list is closed and has been removed: the VPN switch is a
`radiogroup` with a roving tabindex and arrow keys (`parts.tsx`), the tab bar
is a real `tablist` with the same (`App.tsx`), remote strings are wrapped in
`<bdi>` throughout, `format.ts` clamps absurd daemon numbers, and `/assets/*`
now carries `Cache-Control: immutable` (`api._HashedAssets`).

### Product

- The daemon **cannot see a black-holed LAN while the VPN is off**:
  `mark_unavailable` fires unconditionally on `!vpn_on` without asking sing-box,
  so the UI has no evidence to tell a healthy off state from a capture with a
  dead listener — the exact state that took the owner's LAN down.
- **`_matches()` ANDs five kernel checks into one boolean**, which caps what the
  UI can report. Publishing them separately would let the dashboard show a
  per-assertion audit instead of a single "captured" bit.

## Environment notes

*(This section used to restate four items from the lists above, in slightly
different words and — for `State.snapshot()` — with contradictory numbers. The
duplicates are gone; only what is not said above remains.)*

- **`insecure=1` in a subscription link** disables TLS verification for that
  node. Standard client behaviour, but the UI gives no signal.
- **A public name whose owner points it at 127.0.0.1** still passes the
  rule-set URL guard. Nothing checkable at parse time closes it; only sing-box,
  as it dials, could.
- **The capture is IPv4-only.** IPv6 is blocked at the firewall rather than
  proxied, which is a deliberate fail-closed choice, not a solved problem.
- **Real hardware.** Everything above is QEMU x86-64. The A53 is slower, which
  widens the old strategy's window and cannot widen the new one's (it is zero
  by construction, not by timing). Nothing has been deployed to the router.

### One number in here is wrong and nobody knows which

The `State.snapshot()` cost was written down twice, from what was presented as
the same measurement:

- "measured **on the router** at **465 ms** with an 8,640-net bypass list and
  **1.14 s** at 50,000"
- "measured **1.23 ms** at 8,640 bypass nets and **7.09 ms** at 2,000 rules +
  500 servers"

They differ by ~380x and cannot both describe the same thing. Two pieces of
evidence bear on it, and both point at the smaller figure being the deep copy
itself: `state.py::update` records "~1.5 ms here with 8639 bypass networks, so
~10-15 ms on the router's A53", and the /api/state item above measured the *whole* pre-trim
`/api/state` at p50 324 ms on the router — so a post-trim 465 ms would mean
trimming the payload made the endpoint slower. The likeliest reading is that
465 ms/1.14 s was a whole-request figure on the router and 1.23 ms/7.09 ms is the
copy alone on a dev machine, but **that is a reconstruction, not a record** —
re-measure before quoting either. The conclusion is unaffected either way: the
deep copy is left in place deliberately, because callers rely on being free to
mutate, and it is the first thing to look at if the dashboard feels slow.

## Decided, not a defect

**The LAN is trusted; the perimeter is the WAN rule.** The API is
unauthenticated on the LAN by design, and `subscriptions[].source` is returned
unredacted (it is the credential for an inline node, and the subscription URL
for an HTTP one). The owner's position: LAN security is the router owner's
responsibility, and what matters is that nothing is reachable from outside.

Verified on the live router: the daemon binds `0.0.0.0:8088` (IPv4 only — there
is no v6 listener at all), the fw3 DROP for tcp/8088 from `wan` exists in
**both** iptables and ip6tables, and the WAN address is RFC1918 behind a second
NAT. DNS rebinding — an external attacker using the user's own browser — was
attacked and held: Host guard, Origin check and the WebSocket's own re-check all
rejected it.

The redaction middleware should therefore be documented as protection against
casual shoulder-surfing, **not** as a security boundary, so nobody mistakes it
for one.
