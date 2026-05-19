import { execSync } from 'child_process';
import { stealthLogger } from './stealth-logger';

const PROXYCHAINS_TOOLS = [
  'nmap', 'masscan', 'sqlmap', 'nikto', 'gobuster', 'ffuf',
  'nuclei', 'httpx', 'subfinder', 'amass', 'curl', 'wget',
  'hydra', 'medusa', 'crackmapexec', 'wpscan', 'dirb',
  'dirsearch', 'wfuzz', 'whatweb',
] as const;

interface VPNStatus {
  openvpn: boolean;
  wireguard: boolean;
  interface?: string;
}

interface ReadinessCheck {
  check: string;
  status: 'pass' | 'fail' | 'warn';
  details: string;
}

interface NetworkStats {
  enabled: boolean;
  proxychains: boolean;
  torsocks: boolean;
  macRandomization: boolean;
  rotation: boolean;
  currentIP: string;
  vpnStatus: VPNStatus;
}

function envBool(key: string, defaultVal = false): boolean {
  const val = process.env[key];
  if (!val) return defaultVal;
  return val === 'true' || val === '1';
}

function isRealKali(): boolean {
  return envBool('REAL_TOOLS');
}

function safeExec(cmd: string): string {
  try {
    return execSync(cmd, { encoding: 'utf-8', timeout: 10000 }).trim();
  } catch {
    return '';
  }
}

class NetworkStealth {
  private originalMACs: Map<string, string> = new Map();
  private rotationTimer: ReturnType<typeof setInterval> | null = null;
  private currentIP: string = 'unknown';

  isEnabled(): boolean {
    return envBool('NETWORK_STEALTH_ENABLED');
  }

  randomizeMAC(iface: string): { success: boolean; oldMAC: string; newMAC: string } {
    stealthLogger.log('tool_execution', { action: 'mac_randomize', interface: iface });

    try {
      const currentMAC = safeExec(`cat /sys/class/net/${iface}/address`);
      if (!this.originalMACs.has(iface)) {
        this.originalMACs.set(iface, currentMAC);
      }

      safeExec(`ip link set ${iface} down`);
      const output = safeExec(`macchanger -r ${iface}`);
      safeExec(`ip link set ${iface} up`);

      const newMAC = safeExec(`cat /sys/class/net/${iface}/address`);

      stealthLogger.log('mode_change', {
        action: 'mac_randomized',
        interface: iface,
        oldMAC: currentMAC,
        newMAC,
      });

      return { success: true, oldMAC: currentMAC, newMAC };
    } catch (err) {
      stealthLogger.log('alert', { action: 'mac_randomize_failed', interface: iface, error: String(err) });
      return { success: false, oldMAC: '', newMAC: '' };
    }
  }

  restoreMAC(iface: string): { success: boolean; restoredMAC: string } {
    stealthLogger.log('tool_execution', { action: 'mac_restore', interface: iface });

    const originalMAC = this.originalMACs.get(iface);
    if (!originalMAC) {
      return { success: false, restoredMAC: '' };
    }

    try {
      safeExec(`ip link set ${iface} down`);
      safeExec(`macchanger -m ${originalMAC} ${iface}`);
      safeExec(`ip link set ${iface} up`);

      this.originalMACs.delete(iface);

      stealthLogger.log('mode_change', {
        action: 'mac_restored',
        interface: iface,
        restoredMAC: originalMAC,
      });

      return { success: true, restoredMAC: originalMAC };
    } catch (err) {
      stealthLogger.log('alert', { action: 'mac_restore_failed', interface: iface, error: String(err) });
      return { success: false, restoredMAC: '' };
    }
  }

  wrapCommand(command: string): string {
    if (!envBool('USE_PROXYCHAINS')) return command;

    const parts = command.trim().split(/\s+/);
    const tool = parts[0];

    if (PROXYCHAINS_TOOLS.includes(tool as any)) {
      stealthLogger.log('tool_execution', { action: 'proxychains_wrap', tool, command });
      return `proxychains4 -q ${command}`;
    }

    return command;
  }

  wrapWithTorsocks(command: string): string {
    if (!envBool('USE_TORSOCKS')) return command;

    const parts = command.trim().split(/\s+/);
    const tool = parts[0];

    if (PROXYCHAINS_TOOLS.includes(tool as any)) {
      stealthLogger.log('tool_execution', { action: 'torsocks_wrap', tool, command });
      return `torsocks ${command}`;
    }

    return command;
  }

  getPublicIP(): string {
    try {
      const ip = safeExec('curl -s --max-time 5 ifconfig.me');
      if (ip) {
        this.currentIP = ip;
        return ip;
      }
    } catch {}

    return this.currentIP;
  }

  startRotation(intervalMs: number = 300000): void {
    if (this.rotationTimer) {
      this.stopRotation();
    }

    stealthLogger.log('mode_change', { action: 'rotation_start', intervalMs });

    this.rotationTimer = setInterval(() => {
      this.performRotation();
    }, intervalMs);

    this.performRotation();
  }

  stopRotation(): void {
    if (this.rotationTimer) {
      clearInterval(this.rotationTimer);
      this.rotationTimer = null;
      stealthLogger.log('mode_change', { action: 'rotation_stop' });
    }
  }

  private performRotation(): void {
    stealthLogger.log('tool_execution', { action: 'identity_rotation_cycle' });

    if (envBool('STEALTH_MAC_RANDOMIZATION')) {
      const iface = safeExec("ip route | grep default | awk '{print $5}'") || 'eth0';
      this.randomizeMAC(iface);
    }

    safeExec('kill -HUP $(pidof tor) 2>/dev/null || true');

    const newIP = this.getPublicIP();
    stealthLogger.log('mode_change', { action: 'rotation_complete', newIP });
  }

  detectVPN(): VPNStatus {
    try {
      const linkOutput = safeExec('ip link show');
      const openvpn = /tun\d+/.test(linkOutput);
      const wireguard = /wg\d+/.test(linkOutput);

      let iface: string | undefined;
      if (openvpn) {
        const match = linkOutput.match(/tun\d+/);
        if (match) iface = match[0];
      } else if (wireguard) {
        const match = linkOutput.match(/wg\d+/);
        if (match) iface = match[0];
      }

      const status: VPNStatus = { openvpn, wireguard };
      if (iface) status.interface = iface;

      stealthLogger.log('tool_execution', { action: 'vpn_detect', status });
      return status;
    } catch {
      return { openvpn: false, wireguard: false };
    }
  }

  async checkReadiness(): Promise<ReadinessCheck[]> {
    const results: ReadinessCheck[] = [];

    const macchangerInstalled = safeExec('which macchanger') !== '';
    results.push({
      check: 'macchanger',
      status: macchangerInstalled ? 'pass' : 'fail',
      details: macchangerInstalled ? 'macchanger is installed' : 'macchanger not found',
    });

    const proxychainsInstalled = safeExec('which proxychains4') !== '';
    results.push({
      check: 'proxychains',
      status: proxychainsInstalled ? 'pass' : 'fail',
      details: proxychainsInstalled ? 'proxychains4 is installed' : 'proxychains4 not found',
    });

    const torsocksInstalled = safeExec('which torsocks') !== '';
    results.push({
      check: 'torsocks',
      status: torsocksInstalled ? 'pass' : 'fail',
      details: torsocksInstalled ? 'torsocks is installed' : 'torsocks not found',
    });

    const torRunning = safeExec('systemctl is-active tor 2>/dev/null') === 'active'
      || safeExec('pidof tor') !== '';
    results.push({
      check: 'tor_service',
      status: torRunning ? 'pass' : 'fail',
      details: torRunning ? 'Tor service is running' : 'Tor service is not running',
    });

    const vpn = this.detectVPN();
    const vpnRequired = envBool('VPN_REQUIRED');
    const vpnActive = vpn.openvpn || vpn.wireguard;
    results.push({
      check: 'vpn_status',
      status: vpnActive ? 'pass' : vpnRequired ? 'fail' : 'warn',
      details: vpnActive
        ? `VPN active on ${vpn.interface || 'unknown'} (OpenVPN: ${vpn.openvpn}, WireGuard: ${vpn.wireguard})`
        : vpnRequired ? 'VPN required but not detected' : 'No VPN detected',
    });

    const publicIP = this.getPublicIP();
    results.push({
      check: 'public_ip',
      status: publicIP && publicIP !== 'unknown' ? 'pass' : 'warn',
      details: publicIP && publicIP !== 'unknown' ? `Public IP: ${publicIP}` : 'Could not determine public IP',
    });

    const defaultIface = safeExec("ip route | grep default | awk '{print $5}'") || 'eth0';
    const currentMAC = safeExec(`cat /sys/class/net/${defaultIface}/address 2>/dev/null`);
    results.push({
      check: 'mac_status',
      status: currentMAC ? 'pass' : 'warn',
      details: currentMAC ? `Current MAC on ${defaultIface}: ${currentMAC}` : 'Could not read MAC address',
    });

    stealthLogger.log('tool_execution', { action: 'readiness_check', simulated: false, results });
    return results;
  }

  getStats(): NetworkStats {
    return {
      enabled: this.isEnabled(),
      proxychains: envBool('USE_PROXYCHAINS'),
      torsocks: envBool('USE_TORSOCKS'),
      macRandomization: envBool('STEALTH_MAC_RANDOMIZATION'),
      rotation: this.rotationTimer !== null,
      currentIP: this.currentIP,
      vpnStatus: this.detectVPN(),
    };
  }

  private generateSimulatedMAC(): string {
    const bytes = Array.from({ length: 6 }, () =>
      Math.floor(Math.random() * 256).toString(16).padStart(2, '0').toUpperCase()
    );
    bytes[0] = (parseInt(bytes[0], 16) & 0xfe | 0x02).toString(16).padStart(2, '0').toUpperCase();
    return bytes.join(':');
  }
}

export const networkStealth = new NetworkStealth();
