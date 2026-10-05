# Arpie Automated Virtual Lab (Vagrant + VirtualBox)

This directory provides a 1-command reproducible virtual testbed matching the **IAS2 Project Proposal**.

---

## 🏗️ Architecture

- **Victim VM (`arpie-victim`)**: `192.168.56.10` — Runs Arpie Endpoint NIDS in Live Capture mode.
- **Attacker VM (`arpie-attacker`)**: `192.168.56.20` — Preinstalled with `simulate_attack.py`, `nmap`, `hping3`, `arpspoof`, and `bettercap`.
- **Network**: Isolated private network (`192.168.56.0/24`) with promiscuous mode enabled.

---

## 📦 1. Host Setup (CachyOS / Arch Linux)

Install VirtualBox and Vagrant on your host system:

```bash
# 1. Install VirtualBox kernel modules and host packages
sudo pacman -S virtualbox virtualbox-host-dkms linux-headers

# 2. Load the VirtualBox kernel driver
sudo modprobe vboxdrv
sudo usermod -aG vboxusers $USER

# 3. Install Vagrant (available in AUR via paru or yay)
paru -S vagrant   # or yay -S vagrant
```

*(Note: If kernel modules were newly installed, reboot or reload the vboxdrv module before launching Vagrant).*

---

## 🚀 2. Spinning Up the Lab

From the `lab/` directory:

```bash
cd lab
vagrant up
```

*Vagrant will automatically download the base image, create both VMs, configure network adapters, and provision dependencies.*

---

## 🎯 3. Running the Live Demo

### Terminal 1: Start Arpie on the Victim VM
```bash
vagrant ssh victim
cd arpie
sudo /home/vagrant/.venv-arpie/bin/python main.py --daemon --interface eth1 --gateway-ip 192.168.56.1
```
The VM has no display, so run the headless `--daemon` mode (same detection engine, alerts print to this terminal) rather than the GUI. Its own venv lives at `/home/vagrant/.venv-arpie`, outside the shared `arpie/` folder — never recreate it at `arpie/.venv`, since that path is live-synced back to the host and would overwrite the host's own virtualenv.

**Pin `--interface eth1` explicitly** — the VM has two NICs (`eth0` is the NAT adapter used for internet access, `eth1` at `192.168.56.10` is the actual lab network), and auto-detection can pick `eth0`, which never sees the attacker's traffic at all. Confirm it's listening on the right one:
```
[*] Arpie daemon monitoring eth1 (SSID: Wired, Gateway: 192.168.56.1)
```

---

### Terminal 2: Launch Attacks from the Attacker VM
```bash
vagrant ssh attacker
sudo python3 /home/vagrant/arpie/tools/simulate_attack.py --target 192.168.56.10 --gateway 192.168.56.1 --iface eth1
```
**`--iface eth1` is required here too** — Scapy defaults to the interface on the default route (`eth0`, the NAT adapter) when `--iface` is omitted, so the crafted packets never reach the victim at all and Arpie stays silent. This was verified with a live two-VM run: with `--iface eth1` set on both sides, the victim's daemon logged `[!] [HIGH] arp_spoof detected: 192.168.56.1 -> 192.168.56.1` within seconds of running option `1`.

### The 4 Detection Techniques:

| Option in Tool | Detection Technique | Tool / Command Used | Expected Arpie Response |
| :--- | :--- | :--- | :--- |
| **`[2]`** | **Port-Scan Behavior** | `nmap -sS -p 20-45 192.168.56.10` | **MEDIUM**: Port Scan (25 ports probed). Risk score rises. |
| **`[1]`** | **ARP Inconsistency** | Scapy / `arpspoof` | **HIGH**: ARP Spoofing (duplicate MACs detected). |
| **`[3]`** | **Traffic Anomaly** | `hping3 -S --flood -c 130` | **CRITICAL**: Traffic Anomaly (>100 pkts/s). Risk hits Critical (90+). |
| **`[4]`** | **Gateway Identity Change** | Scapy Rogue Gateway MAC flip | **CRITICAL**: Gateway Change detected. |
| **`[5]`** | **Full Attack Sequence** | Automated 4-stage scripted sequence | Full demo plays out over 15 seconds. |

---

### 🛑 4. Demonstrate Seal Mode
> **Note:** Seal Mode (the "Enable Seal Mode" button, PDF/HTML export) only exists in Arpie's GUI, which this lab's headless `--daemon` victim VM cannot display — the Ubuntu box has no desktop environment installed. Steps 1–3 above (real cross-VM detection) work as-is in `--daemon` mode. To demonstrate Seal Mode and report export interactively, either:
> - Run Arpie's GUI directly on your host machine against a *real* second attacker device per [docs/DEMO.md](../docs/DEMO.md), or
> - Install a lightweight desktop + VNC in the victim VM's provisioning script and run the GUI there (not currently set up — ask if you want this added).

1. In Arpie on the Victim VM, click **"Enable Seal Mode"** on the alert.
2. Confirm the prompt $\rightarrow$ Arpie injects an `iptables` rule dropping all packets from `192.168.56.20`.
3. In Terminal 2 (Attacker VM), test: `ping 192.168.56.10` $\rightarrow$ **Packets are dropped live!**
4. In Arpie, click **"Export PDF"** or **"Export HTML"** to inspect the generated session report.

---

## 🧹 5. Teardown
When finished with the demo, suspend or destroy the VMs to free up disk and RAM:

```bash
# To shut down and free RAM:
vagrant halt

# To completely delete the lab VMs when finished:
vagrant destroy -f
```
