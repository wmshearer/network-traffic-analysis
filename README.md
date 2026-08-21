# Network Traffic Analysis

Nine investigations that read intent from packet captures. Each one takes a real
capture, asks a specific question of it with `tshark`, and writes a detection or
a finding that stands on the evidence rather than on a signature list. The common
thread: what a protocol *does* on the wire is visible even when its
contents are encrypted, and the shape of that behaviour is often enough to separate
ordinary traffic from something worth a closer look.

Every project is Python plus `tshark`, has its own tests, and states its own
limits plainly. Raw captures are not redistributed here (they belong to their
publishers); each project's README links its source and credits it.

Written up as case studies at **[wshearer.com](https://wshearer.com)**.

| Project | Question it answers | Capture | Tests |
|---|---|---|---|
| [beacon-analysis](beacon-analysis/) | Which internal host is quietly calling home on a fixed heartbeat? | Malware C2 traffic | 12 |
| [ics-protocol-analysis](ics-protocol-analysis/) | On an industrial network with no passwords, who is allowed to command the physical equipment? | 4SICS ICS lab (CS3Sthlm) | 24 |
| [tls-fingerprint-analysis](tls-fingerprint-analysis/) | Can you identify a client by how it negotiates TLS, without decrypting anything? | TLS handshakes | 11 |
| [rdp-exploit-analysis](rdp-exploit-analysis/) | How do you spot an RDP exploit when the exploit itself is inside the encrypted tunnel? | SANS ISC BlueKeep set | 8 |
| [scan-detection](scan-detection/) | How do you catch a network scanner by what never answered it? | CTU-13 rbot botnet | 12 |
| [ad-attack-detection](ad-attack-detection/) | How does an intruder moving through a Windows domain look on the wire, when every step is a normal protocol call? | AD attack lab captures | 29 |
| [smb-exploit-analysis](smb-exploit-analysis/) | What does an SMB exploit look like when you only have the packets? | SANS ISC EternalBlue set | 11 |
| [iot23-botnet-analysis](iot23-botnet-analysis/) | Do readable rules hold up when scored against published ground-truth labels? | CTU IoT-23 | 9 |
| [doh-tunneling-detection](doh-tunneling-detection/) | Can you catch a tunnel hidden inside encrypted DNS, without decrypting it? | CIRA-CIC-DoHBrw-2020 | 43 |

## The six, in more detail

**beacon-analysis** — Command-and-control malware phones home on a schedule. This
measures the regularity of a host's outbound connections using median absolute
deviation (robust against a single long gap, which would wreck a standard-deviation
score) to separate a machine-steady beacon from human browsing.

**ics-protocol-analysis** — Industrial protocols like Modbus and S7comm have no
authentication at all, so the security question flips from "who misused a password"
to "who is permitted to write." Finds one host issuing every command on the network,
which makes the detection rule trivial to state. Includes a real bug the analysis
caught by reading its own output: industrial devices echo the command code when they
reply, so counting replies made every device look like it issued the writes it had
merely obeyed.

**tls-fingerprint-analysis** — JA4 fingerprinting identifies a client from the exact
shape of its TLS Client Hello (cipher list, extensions, ALPN), before any application
data flows and without decryption. Reads the SNI position separately from the SNI
field so disagreements between them surface.

**rdp-exploit-analysis** — BlueKeep's published indicator (a channel named `MS_T120`)
returns zero matches across every capture, including the exploit, because RDP
negotiates TLS before channel setup, so the indicator is sealed inside the tunnel.
Session shape works where the signature cannot: a real RDP session streams a desktop
and is overwhelmingly server-to-client; an exploit connects, delivers a payload, and
leaves.

**scan-detection** — A scanner does not know what exists, so most of what it contacts
never answers. That low response rate across many distinct subnets is the signal, with
no payload inspection needed. Includes the phantom-host bug where `tshark` comma-joins
nested `ip.src` values, which fragmented one scanner into thousands of fake sources
until it was split correctly.

**ad-attack-detection** — Four steps of an Active Directory intrusion, each a normal
Windows protocol call: DCSync (a directory-replication pull from a host that is not a
domain controller), SPN discovery, manual LDAP recon, and SAMR enumeration of Domain
Admins. Every capture was verified packet-by-packet before use, which caught a file
whose name claimed Kerberoasting but held zero Kerberos traffic.

**smb-exploit-analysis** — EternalBlue on the wire, read from the SANS ISC capture:
the oversized transaction request and the sequence of writes that follow, described
by what the packets do rather than by a signature string.

**iot23-botnet-analysis** — Readable rules scored against CTU IoT-23's own published
labels, so the score is measured against ground truth rather than asserted.

**doh-tunneling-detection** — DNS-over-HTTPS hides the query inside TLS, so payload
inspection is off the table and only traffic shape is left: packet sizes, timing,
duration, byte rates. The useful result here is a negative one. The benign and
malicious captures in the public dataset were recorded as separate sessions on
separate machines, so client IP alone nearly separates the classes, and a "year of
capture" feature scores 100% accuracy on its own while learning nothing about
tunneling. The model is restricted to behavioural features, the leaky columns are
unreachable from the feature matrix by construction, and a test enforces it.

## Running any project

Each subdirectory is self-contained:

```
cd <project>/
python3 -m pytest          # run its tests
python3 scripts/run_analysis.py   # run the analysis (where a capture is present)
```

## A note on honesty

None of these claim to convict. A scanner and an asset-inventory tool look identical
on the wire; a backup product and a credential thief issue the same replication call.
Each classifier describes the *shape* of the traffic and names its false-positive
sources rather than asserting intent, and each has a test that enforces exactly that.
The value is narrowing a large pile of ordinary traffic down to the few things worth
a human's attention.
