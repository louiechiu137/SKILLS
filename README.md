# SKILLS

A collection of AI agent skills (SKILL.md) for use with [OpenCode](https://github.com/opencode-ai/opencode), Claude, and other AI coding assistants.

## Available Skills

### 🔌 [cisco-log-to-json-parsing](./cisco-log-to-json-parsing/)

Parse Cisco switch terminal log files (`.log`) into structured JSON. Supports **IOS**, **IOS-XE**, and **NX-OS** platforms.

**Use when:**
- Parsing Cisco switch `.log` files (terminal session captures)
- Extracting device info, interfaces, VLANs, CDP neighbors, IP phones
- Building network topology from CDP data
- Generating replacement/migration documentation

**What it produces:**
- `devices.json` — Structured device inventory (hostname, model, serial, IOS version, interfaces, VLANs, CDP neighbors, connected phones)
- `topology.json` — Network topology links derived from CDP neighbor data

**Commands parsed:**
| Command | Data Extracted |
|---------|---------------|
| `show version` | Hostname, model, serial, IOS version, uptime |
| `show interfaces status` | Port name, status, VLAN, speed, duplex, type |
| `show ip interface brief` | IP addresses, interface up/down status |
| `show cdp neighbors detail` | Connected devices, platforms, IPs, port mappings |
| `show vlan brief` | VLAN IDs, names, assigned ports |
| `show mac address-table` | MAC addresses, associated VLANs and ports |
| `show interfaces` | Detailed counters, MTU, bandwidth, errors |
| `show etherchannel summary` | Port-channel groups and member interfaces |
| `show spanning-tree` | STP root bridge, port roles, priorities |
| `show power inline` | PoE power draw per port, connected devices |

**Tech:** Pure Python stdlib — no external dependencies.

## What is a SKILL.md?

A `SKILL.md` file is a structured knowledge document that teaches AI coding agents how to perform specific tasks. It contains:

- **When to apply** — trigger conditions
- **Step-by-step instructions** — regex patterns, parsing logic, edge cases
- **Output schemas** — expected JSON structure
- **Platform-specific handling** — differences between IOS/IOS-XE/NX-OS

Skills are automatically discovered by platforms like [SkillsMP](https://skillsmp.com) and can be installed into AI assistants like OpenCode, Claude Code, and Codex.

## Installation

### OpenCode
```bash
# Copy skill to your OpenCode skills directory
cp -r cisco-log-to-json-parsing ~/.config/opencode/skills/
```

### Manual
Download the `SKILL.md` and reference it in your AI assistant's context.

## License

MIT
