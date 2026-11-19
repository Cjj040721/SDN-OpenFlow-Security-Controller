<div align="center">

# SDN OpenFlow Security Controller

**Learning switches, firewall rules, flow statistics, and SYN-flood defence in one Ryu controller.**

An educational SDN project using Ryu, OpenFlow 1.3, Mininet, and Open vSwitch, with a three-switch topology and JSON-driven security rules.

[![Python](https://img.shields.io/badge/Python-3.9-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Ryu](https://img.shields.io/badge/Ryu-SDN_Controller-2AA887)](https://ryu.readthedocs.io/)
[![OpenFlow](https://img.shields.io/badge/OpenFlow-1.3-0072B2)](#topology)
[![Mininet](https://img.shields.io/badge/Mininet-Integration_Recorded-6E56CF)](#verification)
[![Static Checks](https://img.shields.io/badge/Static_Checks-Passed-2AA887)](#verification)

[Topology](#topology) · [Features](#features) · [Quick Start](#quick-start) · [Verification](#verification) · [Limitations](#limitations)

**[Firewall rules](rules.json) · [Verification record](docs/verification.md)**

</div>

---

<a id="topology"></a>
## 1. Network Topology

```text
h1 ─┐
h2 ─┼─ s1 ── s2 ── s3 ─┬─ h4
h3 ─┘                  ├─ h5
                       └─ h6
```

| Component | DPID | Role |
| --- | --- | --- |
| `s1` | `0000000000000001` | L4-aware learning switch |
| `s2` | `0000000000000002` | Firewall, monitoring, and SYN-flood defence |
| `s3` | `0000000000000003` | L4-aware learning switch |

Hosts `h1`–`h6` use `10.0.0.1/24`–`10.0.0.6/24`. The controller handles table-miss entries, packet-in events, flow installation, and periodic statistics requests.

<a id="features"></a>
## 2. Features

| Capability | Implementation |
| --- | --- |
| **L4 learning** | Matches Ethernet, IPv4, and available TCP/UDP/ICMP fields when installing flows |
| **Firewall** | Loads deny rules from `rules.json` and installs them on `s2` |
| **Monitoring** | Requests flow statistics every five seconds and logs packet/byte counters |
| **SYN-flood defence** | More than 20 SYN packets from one source within 10 seconds installs a 60-second drop rule |
| **State cleanup** | Removes expired SYN timestamps and ban records in the background |

### Firewall Rules

| Match | Action |
| --- | --- |
| UDP destination port 443 to `10.0.0.5` | Drop |
| TCP destination port 80 | Drop |
| ICMP echo requests from `10.0.0.4` | Drop |
| All IPv4 traffic to `10.0.0.3` | Drop |

The ICMP rule matches only echo requests (`icmpv4_type=8`, `icmpv4_code=0`) rather than blocking every ICMP packet.

<a id="quick-start"></a>
## 3. Quick Start

### Requirements

- Linux or a Linux VM with Mininet and Open vSwitch
- Python 3.9 recommended for the original Ryu environment
- Ryu 4.x

Install the Python dependency:

```bash
git clone https://github.com/Cjj040721/SDN-OpenFlow-Security-Controller.git
cd SDN-OpenFlow-Security-Controller
python3.9 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Install Mininet and Open vSwitch through the operating system. On Debian/Ubuntu, the relevant packages are `mininet` and `openvswitch-switch`.

### Start the Controller

```bash
ryu-manager controller.py
```

In another terminal:

```bash
sudo mn -c
sudo mn \
  --custom topo.py \
  --topo courseworktopo \
  --controller=remote,ip=127.0.0.1,port=6633 \
  --switch ovsk,protocols=OpenFlow13
```

The controller loads `rules.json` relative to `controller.py`; no course-specific absolute paths are required.

### Static Checks

```bash
python -m py_compile controller.py topo.py
python -m json.tool rules.json > /dev/null
```

<a id="verification"></a>
## 4. Verification

| Check | Evidence |
| --- | --- |
| Python syntax | `controller.py` and `topo.py` compile successfully |
| Firewall configuration | Valid JSON with exactly four rules on datapath `0000000000000002` |
| Topology | DPIDs `1`, `2`, and `3`, with six expected host addresses |
| SYN parameters | Threshold `20`, window `10` seconds, ban duration `60` seconds |
| Original Linux integration | Topology, L4 learning, firewall counters, flow statistics, and temporary SYN blocking recorded |
| Current dynamic rerun | **Not performed**; Ryu and Mininet are unavailable in the current macOS environment |

The original integration run used a Python 3.9 Ryu environment. Its verbose logs and course-specific paths are not redistributed; the evidence is summarised in [`docs/verification.md`](docs/verification.md).

## 5. Repository Structure

```text
SDN-OpenFlow-Security-Controller/
├── controller.py          # Learning, firewall, statistics, and SYN defence
├── topo.py                # Three-switch, six-host Mininet topology
├── rules.json             # Datapath-specific firewall rules
├── docs/verification.md   # Original integration evidence and current checks
├── requirements.txt       # Ryu dependency
└── LICENSE
```

<a id="limitations"></a>
## 6. Limitations

- Designed for a local Mininet teaching environment, not production deployment.
- Uses fixed switch DPIDs and one controller without high availability.
- Does not provide controller authentication, TLS, or persistent network state.
- SYN detection is threshold-based and should be tuned for the target traffic pattern.

## 7. Licence

Original project code and documentation are available under the [MIT License](LICENSE). Ryu, Mininet, Open vSwitch, and other dependencies retain their original licences.

---

<div align="center">

**SDN OpenFlow Security Controller — Learn the route. Enforce the rule. Watch the traffic.**

Ryu + OpenFlow 1.3 + Mininet + Open vSwitch

</div>
