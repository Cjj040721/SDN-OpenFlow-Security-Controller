# SDN OpenFlow Security Controller

An educational software-defined networking project using Ryu, OpenFlow 1.3, Mininet, and Open vSwitch. One controller combines L4-aware learning switches, JSON-driven firewall rules, periodic flow statistics, and SYN-flood mitigation.

## Network Topology

```text
h1 ─┐
h2 ─┼─ s1 ── s2 ── s3 ─┬─ h4
h3 ─┘                  ├─ h5
                       └─ h6
```

| Component | DPID | Behavior |
| --- | --- | --- |
| `s1` | `0000000000000001` | L4-aware learning switch |
| `s2` | `0000000000000002` | Firewall, monitoring, and SYN-flood defence |
| `s3` | `0000000000000003` | L4-aware learning switch |

Hosts `h1`–`h6` use `10.0.0.1/24`–`10.0.0.6/24`.

## Features

- **L4 learning:** installs flows using Ethernet, IPv4, and transport-layer fields where available.
- **Firewall:** loads deny rules from `rules.json` and installs them on `s2`.
- **Monitoring:** requests flow statistics every five seconds and logs packet/byte counters.
- **SYN-flood defence:** more than 20 SYN packets from one source within 10 seconds installs a 60-second temporary drop rule.
- **Table-miss handling:** unmatched packets are sent to the controller.
- **State cleanup:** expired SYN timestamps and ban records are removed in the background.

## Firewall Rules

| Match | Action |
| --- | --- |
| UDP destination port 443 to `10.0.0.5` | Drop |
| TCP destination port 80 | Drop |
| ICMP echo requests from `10.0.0.4` | Drop |
| All IPv4 traffic to `10.0.0.3` | Drop |

The ICMP rule matches only echo requests (`icmpv4_type=8`, `icmpv4_code=0`) rather than all ICMP traffic.

## Requirements

- Linux or a Linux VM with Mininet and Open vSwitch
- Python 3.9 recommended for the original Ryu environment
- Ryu 4.x

Install Python dependencies:

```bash
python3.9 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Mininet and Open vSwitch should be installed through the operating system. On Debian/Ubuntu, the relevant packages are `mininet` and `openvswitch-switch`.

## Run

Start the Ryu controller from the repository root:

```bash
ryu-manager controller.py
```

In another terminal with Mininet available:

```bash
sudo mn -c
sudo mn \
  --custom topo.py \
  --topo courseworktopo \
  --controller=remote,ip=127.0.0.1,port=6633 \
  --switch ovsk,protocols=OpenFlow13
```

The controller loads `rules.json` relative to `controller.py`, so no course-specific absolute paths are required.

## Static Checks

```bash
python -m py_compile controller.py topo.py
python -m json.tool rules.json > /dev/null
```

## Verification

The original Linux run covered topology creation, L4 learning, firewall counters, flow statistics, and temporary SYN-flood blocking. The cleaned repository also passes syntax and configuration checks.

See [`docs/verification.md`](docs/verification.md) for the recorded evidence and the checks that could not be rerun in the current macOS environment.

## Scope and Limitations

- Designed for a local Mininet teaching environment, not production deployment.
- Uses fixed switch DPIDs and a single controller without high availability.
- Does not provide controller authentication, TLS, or persistent network state.
- SYN detection is threshold-based and can require tuning for different traffic patterns.

## License

Permission for public redistribution has been confirmed. Original project code and documentation are released under the [MIT License](LICENSE). Ryu, Mininet, Open vSwitch, and other dependencies retain their own licenses.
