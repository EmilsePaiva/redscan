import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:network_info_plus/network_info_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() => runApp(const RedScanApp());

bool get isDesktop =>
    Platform.isWindows || Platform.isLinux || Platform.isMacOS;

class RedScanApp extends StatelessWidget {
  const RedScanApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'RedScan',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(colorSchemeSeed: Colors.teal, useMaterial3: true),
        home: const Home(),
      );
}

// Puertos comunes: si el equipo responde (o rechaza) en alguno, está activo.
const scanPorts = [80, 443, 53, 22, 445, 139, 8080, 62078, 5353];

// Códigos de "conexión rechazada" según el sistema:
// 111 = Linux/Android, 61 = macOS, 10061 = Windows (WSAECONNREFUSED).
const _refusedCodes = {111, 61, 10061};

/// Devuelve milisegundos si el host responde, o null si no.
/// "Conexión rechazada" también significa que el equipo está vivo.
Future<int?> probe(String ip, int port, {int timeoutMs = 700}) async {
  final sw = Stopwatch()..start();
  try {
    final s = await Socket.connect(ip, port,
        timeout: Duration(milliseconds: timeoutMs));
    s.destroy();
    return sw.elapsedMilliseconds;
  } on SocketException catch (e) {
    if (_refusedCodes.contains(e.osError?.errorCode)) {
      return sw.elapsedMilliseconds;
    }
    return null;
  } catch (_) {
    return null;
  }
}

Future<int?> bestLatency(String ip) async {
  final r = await Future.wait(scanPorts.map((p) => probe(ip, p)));
  final ok = r.whereType<int>().toList()..sort();
  return ok.isEmpty ? null : ok.first;
}

// ---------------------------------------------------------------------------
// Información de red (IP propia y router)
// ---------------------------------------------------------------------------

class NetInfo {
  final String? ip;
  final String? gateway;
  const NetInfo(this.ip, this.gateway);
}

final _ipRegex = RegExp(r'^\d{1,3}(\.\d{1,3}){3}$');
bool _isIp(String s) => _ipRegex.hasMatch(s);

bool _isPrivate(String ip) {
  if (ip.startsWith('192.168.') || ip.startsWith('10.')) return true;
  if (ip.startsWith('172.')) {
    final second = int.tryParse(ip.split('.')[1]) ?? 0;
    return second >= 16 && second <= 31;
  }
  return false;
}

/// Primera IPv4 privada de un adaptador "real" (ignora VMs, WSL, etc.).
Future<String?> _firstPrivateIPv4() async {
  try {
    final ifs = await NetworkInterface.list(type: InternetAddressType.IPv4);
    for (final i in ifs) {
      final n = i.name.toLowerCase();
      if (n.contains('vethernet') ||
          n.contains('vmware') ||
          n.contains('virtualbox') ||
          n.contains('wsl') ||
          n.contains('loopback')) {
        continue;
      }
      for (final a in i.addresses) {
        if (_isPrivate(a.address)) return a.address;
      }
    }
  } catch (_) {}
  return null;
}

/// En Windows: lee la tabla de rutas (`route print`), que no depende del
/// idioma del sistema. La ruta por defecto (0.0.0.0) con menor métrica nos da
/// el router y la IP del adaptador que realmente sale a la red.
Future<NetInfo> _windowsInfo() async {
  String? ip, gw;
  try {
    final r = await Process.run('route', ['print', '-4', '0.0.0.0'],
        stdoutEncoding: latin1);
    final rows = <List<String>>[];
    for (final line in r.stdout.toString().split('\n')) {
      final p = line.trim().split(RegExp(r'\s+'));
      if (p.length >= 5 &&
          p[0] == '0.0.0.0' &&
          p[1] == '0.0.0.0' &&
          _isIp(p[2]) &&
          _isIp(p[3])) {
        rows.add(p);
      }
    }
    rows.sort((a, b) => (int.tryParse(a[4]) ?? 99999)
        .compareTo(int.tryParse(b[4]) ?? 99999));
    if (rows.isNotEmpty) {
      gw = rows.first[2];
      ip = rows.first[3];
    }
  } catch (_) {}
  ip ??= await _firstPrivateIPv4();
  return NetInfo(ip, gw);
}

Future<NetInfo> loadNetInfo() async {
  if (Platform.isWindows) return _windowsInfo();
  final info = NetworkInfo();
  String? ip, gw;
  try {
    ip = await info.getWifiIP();
    gw = await info.getWifiGatewayIP();
  } catch (_) {}
  if (ip == null && isDesktop) ip = await _firstPrivateIPv4();
  return NetInfo(ip, gw);
}

/// En Windows: lee la tabla ARP (`arp -a`). Al probar las 254 IPs, Windows
/// "pregunta" por cada una, así que aparecen también los equipos con firewall
/// que ignoran las conexiones TCP. Devuelve {ip: mac} de la subred indicada.
Future<Map<String, String>> arpTable(String prefix) async {
  final out = <String, String>{};
  if (!Platform.isWindows) return out;
  try {
    final r = await Process.run('arp', ['-a'], stdoutEncoding: latin1);
    final re = RegExp(
        r'^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\S+)');
    for (final line in r.stdout.toString().split('\n')) {
      final m = re.firstMatch(line);
      if (m == null) continue;
      final ip = m.group(1)!;
      final mac = m.group(2)!.toLowerCase();
      final type = m.group(3)!.toLowerCase(); // dynamic/dinámico vs static/estático
      if (!ip.startsWith(prefix)) continue;
      if (mac == 'ff-ff-ff-ff-ff-ff') continue;
      if (type.startsWith('st') || type.startsWith('es')) continue;
      final last = int.tryParse(ip.split('.').last) ?? 0;
      if (last < 1 || last > 254) continue;
      out[ip] = mac;
    }
  } catch (_) {}
  return out;
}

// ---------------------------------------------------------------------------

class Device {
  final String ip;
  final int? ms; // null = no respondió por TCP, pero aparece en la tabla ARP
  final String? name;
  final String? mac;
  Device(this.ip, this.ms, this.name, [this.mac]);
  int get last => int.parse(ip.split('.').last);
}

class Home extends StatefulWidget {
  const Home({super.key});
  @override
  State<Home> createState() => _HomeState();
}

class _HomeState extends State<Home> {
  int tab = 0;

  void _go(int i) => setState(() => tab = i);

  @override
  Widget build(BuildContext context) {
    // Ventana ancha (PC): menú lateral. Ventana estrecha (móvil): barra inferior.
    final wide = MediaQuery.of(context).size.width >= 720;
    return Scaffold(
      body: Row(children: [
        if (wide) ...[
          NavigationRail(
            selectedIndex: tab,
            onDestinationSelected: _go,
            labelType: NavigationRailLabelType.all,
            destinations: const [
              NavigationRailDestination(
                  icon: Icon(Icons.wifi_find), label: Text('Escáner')),
              NavigationRailDestination(
                  icon: Icon(Icons.speed), label: Text('Latencia')),
            ],
          ),
          const VerticalDivider(width: 1),
        ],
        Expanded(
          key: const ValueKey('content'),
          child: IndexedStack(
              index: tab, children: const [ScanPage(), ToolsPage()]),
        ),
      ]),
      bottomNavigationBar: wide
          ? null
          : NavigationBar(
              selectedIndex: tab,
              onDestinationSelected: _go,
              destinations: const [
                NavigationDestination(
                    icon: Icon(Icons.wifi_find), label: 'Escáner'),
                NavigationDestination(
                    icon: Icon(Icons.speed), label: 'Latencia'),
              ],
            ),
    );
  }
}

class ScanPage extends StatefulWidget {
  const ScanPage({super.key});
  @override
  State<ScanPage> createState() => _ScanPageState();
}

class _ScanPageState extends State<ScanPage> {
  String? myIp, gateway;
  List<Device> devices = [];
  Set<String> known = {};
  bool scanning = false;
  double progress = 0;

  @override
  void initState() {
    super.initState();
    _loadInfo();
  }

  Future<void> _loadInfo() async {
    final info = await loadNetInfo();
    final prefs = await SharedPreferences.getInstance();
    if (!mounted) return;
    setState(() {
      myIp = info.ip;
      gateway = info.gateway;
      known = (prefs.getStringList('known') ?? []).toSet();
    });
  }

  Future<void> _saveKnown() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setStringList('known', known.toList());
  }

  Future<Device?> _check(String ip) async {
    final ms = await bestLatency(ip);
    if (ms == null) return null;
    String? name;
    try {
      final r = await InternetAddress(ip)
          .reverse()
          .timeout(const Duration(seconds: 1));
      if (r.host != ip) name = r.host;
    } catch (_) {}
    return Device(ip, ms, name);
  }

  Future<void> _scan() async {
    await _loadInfo();
    if (myIp == null) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Conéctate a una red para escanear')));
      return;
    }
    final prefix = myIp!.substring(0, myIp!.lastIndexOf('.') + 1);
    setState(() {
      scanning = true;
      devices = [];
      progress = 0;
    });
    const batch = 24;
    for (var start = 1; start <= 254; start += batch) {
      final end = min(start + batch - 1, 254);
      final res = await Future.wait(
          [for (var i = start; i <= end; i++) _check('$prefix$i')]);
      if (!mounted) return;
      setState(() {
        devices.addAll(res.whereType<Device>());
        devices.sort((a, b) => a.last.compareTo(b.last));
        progress = end / 254;
      });
    }
    final arp = await arpTable(prefix);
    if (!mounted) return;
    setState(() {
      if (arp.isNotEmpty) {
        final seen = {for (final d in devices) d.ip};
        devices = [
          for (final d in devices) Device(d.ip, d.ms, d.name, arp[d.ip]),
          for (final e in arp.entries)
            if (!seen.contains(e.key)) Device(e.key, null, null, e.value),
        ]..sort((a, b) => a.last.compareTo(b.last));
      }
      scanning = false;
    });
  }

  void _toggle(String ip) {
    setState(() => known.contains(ip) ? known.remove(ip) : known.add(ip));
    _saveKnown();
  }

  void _markAll() {
    setState(() => known.addAll(devices.map((d) => d.ip)));
    _saveKnown();
  }

  @override
  Widget build(BuildContext context) {
    final newCount =
        devices.where((d) => !known.contains(d.ip) && d.ip != myIp).length;
    final thisName = isDesktop ? 'Este equipo' : 'Este teléfono';
    final thisIcon = isDesktop ? Icons.computer : Icons.phone_android;
    return Scaffold(
      appBar: AppBar(
        title: const Text('RedScan'),
        actions: [
          if (devices.isNotEmpty)
            IconButton(
                tooltip: 'Marcar todos como conocidos',
                onPressed: _markAll,
                icon: const Icon(Icons.done_all)),
        ],
      ),
      body: Column(children: [
        Card(
          margin: const EdgeInsets.all(12),
          child: ListTile(
            leading: const Icon(Icons.wifi),
            title: Text('Mi IP: ${myIp ?? "sin red"}'),
            subtitle: Text('Router: ${gateway ?? "-"}'),
          ),
        ),
        if (scanning) LinearProgressIndicator(value: progress),
        if (devices.isNotEmpty)
          Padding(
            padding: const EdgeInsets.all(8),
            child: Text(
                '${devices.length} dispositivos activos · $newCount nuevos/desconocidos',
                style: Theme.of(context).textTheme.titleSmall),
          ),
        Expanded(
          child: devices.isEmpty
              ? Center(
                  child: Text(scanning
                      ? 'Escaneando...'
                      : 'Pulsa "Escanear" para buscar dispositivos'))
              : ListView.builder(
                  itemCount: devices.length,
                  itemBuilder: (_, i) {
                    final d = devices[i];
                    final isMe = d.ip == myIp;
                    final isGw = d.ip == gateway;
                    final isNew = !known.contains(d.ip) && !isMe;
                    return ListTile(
                      leading: Icon(isGw
                          ? Icons.router
                          : isMe
                              ? thisIcon
                              : Icons.devices_other),
                      title: Text(isMe
                          ? thisName
                          : isGw
                              ? 'Router'
                              : (d.name ?? 'Dispositivo ${d.ip}')),
                      subtitle: Text(d.ms != null
                          ? '${d.ip} · ${d.ms} ms${d.mac != null ? ' · ${d.mac}' : ''}'
                          : '${d.ip} · ${d.mac} · no responde a puertos'),
                      trailing: isNew
                          ? const Chip(
                              label: Text('NUEVO'),
                              backgroundColor: Color(0xFFFFE0B2))
                          : const Icon(Icons.check_circle, color: Colors.teal),
                      onTap: isMe ? null : () => _toggle(d.ip),
                    );
                  },
                ),
        ),
      ]),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: scanning ? null : _scan,
        icon: const Icon(Icons.search),
        label: Text(scanning ? 'Escaneando...' : 'Escanear'),
      ),
    );
  }
}

class ToolsPage extends StatefulWidget {
  const ToolsPage({super.key});
  @override
  State<ToolsPage> createState() => _ToolsPageState();
}

class _ToolsPageState extends State<ToolsPage> {
  final List<String> results = [];
  bool running = false;

  Future<String> _measure(String label, String host, List<int> ports) async {
    const tries = 4;
    final times = <int>[];
    for (var i = 0; i < tries; i++) {
      int? best;
      for (final p in ports) {
        best = await probe(host, p, timeoutMs: 1500);
        if (best != null) break;
      }
      if (best != null) times.add(best);
    }
    if (times.isEmpty) return '$label ($host): sin respuesta';
    final avg = times.reduce((a, b) => a + b) / times.length;
    final loss = ((tries - times.length) * 100 / tries).round();
    return '$label ($host): ${avg.toStringAsFixed(0)} ms promedio · $loss% pérdida';
  }

  Future<void> _run() async {
    setState(() {
      running = true;
      results.clear();
    });
    final gw = (await loadNetInfo()).gateway;
    final targets = <List<Object>>[
      if (gw != null) ['Router', gw, scanPorts],
      ['Google DNS', '8.8.8.8', [53]],
      ['Cloudflare', '1.1.1.1', [443, 53]],
    ];
    for (final t in targets) {
      final r = await _measure(t[0] as String, t[1] as String, t[2] as List<int>);
      if (!mounted) return;
      setState(() => results.add(r));
    }
    if (mounted) setState(() => running = false);
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('Latencia')),
        body: ListView(padding: const EdgeInsets.all(12), children: [
          const Text(
              'Mide qué tan rápido responde tu router y tu salida a internet. '
              'Un router con más de 20 ms o pérdida de paquetes suele indicar WiFi débil o saturado.'),
          const SizedBox(height: 12),
          FilledButton.icon(
              onPressed: running ? null : _run,
              icon: const Icon(Icons.play_arrow),
              label: Text(running ? 'Midiendo...' : 'Iniciar prueba')),
          const SizedBox(height: 12),
          for (final r in results) Card(child: ListTile(title: Text(r))),
        ]),
      );
}
