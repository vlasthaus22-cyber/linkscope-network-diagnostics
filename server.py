#!/usr/bin/env python3
"""Локальная панель диагностики сети. Запуск: python server.py"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import html
import ipaddress
import io
import json
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
MAX_BODY = 16_384


def valid_host(value: object) -> str:
    host = str(value or "").strip()
    if len(host) > 253 or not host:
        raise ValueError("Укажите IP-адрес или имя устройства.")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
            raise ValueError("Некорректный IP-адрес или DNS-имя.")
        return host


def run(args: list[str], timeout: int = 12) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace", check=False,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def ping_python(host: str, count: int) -> dict:
    if os.name == "nt":
        cmd = ["ping", "-n", str(count), "-w", "1200", host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "2", host]
    result = run(cmd, timeout=count * 2 + 5)
    output = result.stdout + "\n" + result.stderr
    loss = None
    # Windows ping output is localized and may use the OEM code page. Match the
    # numeric percentage independently of the translated word after it.
    patterns = [r"\(\s*(\d+(?:[.,]\d+)?)\s*%", r"(\d+(?:[.,]\d+)?)%\s*(?:packet loss|loss|потеряно|потеря)"]
    for pattern in patterns:
        match = re.search(pattern, output, re.I)
        if match:
            loss = float(match.group(1).replace(",", "."))
            break
    times = [float(x.replace(",", ".")) for x in re.findall(r"(?:time|время)[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", output, re.I)]
    if not times:
        # Also handles localized sub-millisecond replies such as "<1мс".
        times = [float(x.replace(",", ".")) for x in re.findall(r"(?<!\d)[<≤]\s*(\d+(?:[.,]\d+)?)", output)]
    if loss is None:
        sent = len(re.findall(r"(?:Reply from|Ответ от|bytes from|Из)\s|\bTTL\s*=", output, re.I))
        loss = max(0.0, 100.0 * (count - min(count, sent)) / count)
    return {"reachable": result.returncode == 0 or loss < 100,
            "packet_loss_percent": round(loss, 1),
            "latency_ms": round(sum(times) / len(times), 2) if times else None,
            "detail": output.strip()[-1600:]}


def ping_powershell(host: str, count: int) -> dict:
    # Host validated as an IP/DNS name before it is inserted into this command.
    ps = ("$ErrorActionPreference='Stop'; "
          f"$r=Test-Connection -ComputerName '{host}' -Count {count} -ErrorAction SilentlyContinue; "
          "if($r){$r | Select-Object Status,ResponseTime,Address | ConvertTo-Json -Compress -Depth 3} "
          "else{$raw=(& ping.exe -n " + str(count) + " -w 1200 '" + host + "' 2>&1 | Out-String); "
          "$replies=[regex]::Matches($raw,'(?i)\\bTTL\\s*='); "
          "$lossMatch=[regex]::Match($raw,'\\(\\s*(\\d+(?:[.,]\\d+)?)\\s*%'); "
          "$loss=if($lossMatch.Success){[double]::Parse($lossMatch.Groups[1].Value.Replace(',', '.'),[cultureinfo]::InvariantCulture)}else{100}; "
          "$times=[regex]::Matches($raw,'(?i)(?:time[=<]\\s*|[<≤]\\s*)(\\d+(?:[.,]\\d+)?)'); $latency=$null; "
          "if($times.Count){$sum=0.0; foreach($m in $times){$sum += [double]::Parse($m.Groups[1].Value.Replace(',', '.'),[cultureinfo]::InvariantCulture)}; $latency=[math]::Round($sum/$times.Count,2)}; "
          "$status=if($replies.Count){'Success'}else{'Failure'}; "
          "[pscustomobject]@{Status=$status;ResponseTime=$latency;PacketLoss=$loss;Detail=$raw} | ConvertTo-Json -Compress}")
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        raise RuntimeError("PowerShell не найден. Установите PowerShell или выберите Python.")
    result = run([exe, "-NoProfile", "-NonInteractive", "-Command", ps], timeout=count * 3 + 8)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "PowerShell не смог выполнить ping.")
    try:
        data = json.loads(result.stdout.strip() or "[]")
    except json.JSONDecodeError:
        data = []
    if isinstance(data, dict):
        data = [data]
    good = [x for x in data if str(x.get("Status", "Success")).lower() in ("success", "0")]
    latencies = [float(x["ResponseTime"]) for x in good if x.get("ResponseTime") is not None]
    explicit_loss = next((x.get("PacketLoss") for x in data if x.get("PacketLoss") is not None), None)
    loss = round(float(explicit_loss), 1) if explicit_loss is not None else round(100 * (count - len(good)) / count, 1)
    return {"reachable": bool(good), "packet_loss_percent": loss,
            "latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
            "detail": next((str(x["Detail"]).strip()[-1600:] for x in data if x.get("Detail")), f"Получено ответов: {len(good)} из {count}")}


def ping_cmd(host: str, count: int) -> dict:
    if os.name != "nt":
        raise RuntimeError("Режим Windows CMD доступен только в Windows.")
    exe = os.environ.get("COMSPEC", "cmd.exe")
    # host is validated to contain only safe DNS/IP characters.
    result = run([exe, "/d", "/s", "/c", f"ping -n {count} -w 1200 {host}"], timeout=count * 2 + 5)
    output = result.stdout + "\n" + result.stderr
    loss_match = re.search(r"\(\s*(\d+(?:[.,]\d+)?)\s*%", output, re.I)
    replies = len(re.findall(r"(?:Reply from|Ответ от)\s|\bTTL\s*=", output, re.I))
    times = [float(x.replace(",", ".")) for x in re.findall(r"(?:time|время)[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", output, re.I)]
    if not times:
        times = [float(x.replace(",", ".")) for x in re.findall(r"(?<!\d)[<≤]\s*(\d+(?:[.,]\d+)?)", output)]
    loss = float(loss_match.group(1).replace(",", ".")) if loss_match else max(0.0, 100.0 * (count - min(count, replies)) / count)
    return {"reachable": result.returncode == 0 or loss < 100,
            "packet_loss_percent": round(loss, 1),
            "latency_ms": round(sum(times) / len(times), 2) if times else None,
            "detail": output.strip()[-1600:]}


def iperf_test(host: str, port: int, seconds: int) -> dict:
    exe = shutil.which("iperf3") or shutil.which("iperf")
    if not exe:
        raise RuntimeError("iperf3 не установлен на этом устройстве. Установите iperf3 и повторите проверку.")
    result = run([exe, "-c", host, "-p", str(port), "-t", str(seconds), "-J"], timeout=seconds + 15)
    if result.returncode != 0:
        msg = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError("iperf3 не подключился. Проверьте iperf3 -s на целевом устройстве, порт и firewall. " + msg[-500:])
    try:
        data = json.loads(result.stdout)
        summary = data.get("end", {}).get("sum_received") or data.get("end", {}).get("sum") or data.get("end", {}).get("sum_sent") or {}
        bps = summary.get("bits_per_second")
        if bps is None:
            raise ValueError("В отчёте iperf3 нет скорости.")
        return {"mbps": round(float(bps) / 1_000_000, 2),
                "sender_mbps": round(float(data.get("end", {}).get("sum_sent", {}).get("bits_per_second", bps)) / 1_000_000, 2),
                "retransmits": data.get("end", {}).get("sum_sent", {}).get("retransmits")}
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Не удалось разобрать отчёт iperf3: {exc}") from exc


def native_tcp_test(host: str, port: int, seconds: int) -> dict:
    """Измеряет TCP-поток без внешнего клиента; на цели должен работать LinkScope."""
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.settimeout(max(10, seconds + 10))
    except OSError as exc:
        raise RuntimeError(f"Нет встроенного приёмника на {host}:{port}. Запустите LinkScope на целевом устройстве; если это невозможно, используйте receiver.ps1. ({exc})") from exc
    try:
        sock.settimeout(3)
        greeting = sock.recv(64).decode("ascii", errors="replace")
        if not greeting.startswith("LINKSCOPE-READY"):
            raise RuntimeError(f"На {host}:{port} нет приёмника LinkScope.")
        sock.sendall(b"START\n")
        if not sock.recv(32).startswith(b"GO"):
            raise RuntimeError("Целевой приёмник не подтвердил запуск замера.")
        sock.settimeout(max(10, seconds + 10))
    except (OSError, socket.timeout) as exc:
        sock.close()
        raise RuntimeError(f"Не удалось согласовать TCP-тест с {host}:{port}: {exc}") from exc
    except RuntimeError:
        sock.close()
        raise
    payload = os.urandom(64 * 1024)
    sent = 0
    start = time.perf_counter()
    deadline = start + seconds
    try:
        while time.perf_counter() < deadline:
            sock.sendall(payload)
            sent += len(payload)
        sock.shutdown(socket.SHUT_WR)
        # Receiver confirms that it drained the complete TCP stream.
        ack = sock.recv(128).decode("ascii", errors="replace").strip()
        elapsed = time.perf_counter() - start
        if not ack.startswith("OK"):
            raise RuntimeError("Целевой приёмник не подтвердил завершение теста.")
    except (OSError, socket.timeout) as exc:
        raise RuntimeError(f"TCP-замер прерван: {exc}") from exc
    finally:
        sock.close()
    rate = round(sent * 8 / elapsed / 1_000_000, 2)
    return {"mbps": rate, "sender_mbps": rate, "bytes_sent": sent,
            "seconds": round(elapsed, 2), "method": "native-tcp"}


def select_test_port(host: str, method: str, mode: str, manual_port: int) -> int:
    if mode == "manual":
        return manual_port
    if method == "iperf3":
        candidates = [5201, 5202, 5203]
        for port in candidates:
            try:
                with socket.create_connection((host, port), timeout=0.35):
                    return port
            except OSError:
                pass
        raise RuntimeError("Автопоиск не нашёл сервер iperf3 на стандартных портах 5201–5203.")
    # Only select a port after the LinkScope receiver identifies itself; arbitrary open ports are not enough.
    for port in (8766, 8767, 9000, 9001, 5201, 5202, 5203, 5001, 8080, 8081):
        try:
            with socket.create_connection((host, port), timeout=0.35) as probe:
                probe.settimeout(0.35)
                if probe.recv(64).decode("ascii", errors="replace").startswith("LINKSCOPE-READY"):
                    probe.sendall(b"PROBE\n")
                    if probe.recv(16).startswith(b"OK"):
                        return port
        except OSError:
            pass
    raise RuntimeError("Автопоиск не нашёл приёмник LinkScope. Запустите LinkScope на целевом устройстве или receiver.ps1.")


class LinkScopeReceiverHandler(socketserver.StreamRequestHandler):
    """Small built-in receiver for the LinkScope TCP throughput protocol."""
    def handle(self) -> None:
        self.connection.settimeout(40)
        try:
            self.wfile.write(b"LINKSCOPE-READY\n")
            self.wfile.flush()
            command = self.rfile.readline(32).strip()
            if command == b"PROBE":
                self.wfile.write(b"OK\n")
                self.wfile.flush()
                return
            if command != b"START":
                return
            self.wfile.write(b"GO\n")
            self.wfile.flush()
            total = 0
            while True:
                chunk = self.connection.recv(65_536)
                if not chunk:
                    break
                total += len(chunk)
            self.wfile.write(f"OK {total}\n".encode("ascii"))
            self.wfile.flush()
            print(f"[receiver] Получено {total:,} байт от {self.client_address[0]}")
        except (OSError, socket.timeout):
            pass


class LinkScopeReceiverServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_receiver(port: int = 8766) -> LinkScopeReceiverServer | None:
    try:
        receiver = LinkScopeReceiverServer(("0.0.0.0", port), LinkScopeReceiverHandler)
    except OSError as exc:
        print(f"[receiver] Встроенный приёмник не запущен на порту {port}: {exc}")
        return None
    thread = threading.Thread(target=receiver.serve_forever, name="linkscope-receiver", daemon=True)
    thread.start()
    print(f"[receiver] Встроенный TCP-приёмник запущен на порту {port}")
    return receiver


def valid_ssh_user(value: object) -> str:
    user = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", user):
        raise ValueError("Укажите корректное имя SSH-пользователя.")
    return user


def select_ssh_port(host: str, mode: str, manual_port: int) -> int:
    if mode == "manual":
        return manual_port
    for port in (22, 2222, 2200):
        try:
            with socket.create_connection((host, port), timeout=0.4):
                return port
        except OSError:
            pass
    raise RuntimeError("Автопоиск SSH не нашёл открытый порт 22, 2222 или 2200. Переключитесь на ручной режим.")


def ssh_native_test(source: str, user: str, ssh_port: int, key_file: str, target: str, target_port: int, seconds: int, port_mode: str) -> dict:
    ssh = shutil.which("ssh") or shutil.which("ssh.exe")
    if not ssh:
        raise RuntimeError("SSH-клиент не найден на компьютере с панелью.")
    remote_code = f"""
$ErrorActionPreference='Stop'
$hostName='{target}'; $port={target_port}; $portMode='{port_mode}'; $duration={seconds}; $count=4
$ping=Test-Connection -ComputerName $hostName -Count $count -ErrorAction SilentlyContinue
$loss=[Math]::Round(100*($count-@($ping).Count)/$count,1)
$lat=$null; if(@($ping).Count -gt 0){{ $lat=[Math]::Round(((@($ping)|Measure-Object -Property ResponseTime -Average).Average),2) }}
$found=$false
if($portMode -eq 'auto'){{ foreach($candidate in @(8766,8767,9000,9001,5201,5202,5203,5001,8080,8081)){{ $probe=[Net.Sockets.TcpClient]::new(); try{{ $ar=$probe.BeginConnect($hostName,$candidate,$null,$null); if(-not $ar.AsyncWaitHandle.WaitOne(300)){{ $probe.Close(); continue }}; $probe.EndConnect($ar); $probeStream=$probe.GetStream(); $probeStream.ReadTimeout=250; $gb=New-Object byte[] 64; $gn=$probeStream.Read($gb,0,$gb.Length); $gh=[Text.Encoding]::ASCII.GetString($gb,0,$gn); if($gh.StartsWith('LINKSCOPE-READY')){{ $probeStream.Write([Text.Encoding]::ASCII.GetBytes("PROBE`n")); $ok=New-Object byte[] 16; $null=$probeStream.Read($ok,0,$ok.Length); if([Text.Encoding]::ASCII.GetString($ok).StartsWith('OK')){{ $port=$candidate; $found=$true }} }} }} catch{{}}; $probe.Close(); if($found){{ break }} }}; if(-not $found){{ throw 'No LinkScope receiver found on common ports.' }} }}
$c=[Net.Sockets.TcpClient]::new(); $c.Connect($hostName,$port); $s=$c.GetStream(); $s.ReadTimeout=5000
$g=New-Object byte[] 64; $n=$s.Read($g,0,$g.Length); $hello=[Text.Encoding]::ASCII.GetString($g,0,$n)
if(-not $hello.StartsWith('LINKSCOPE-READY')){{ throw 'The remote port is not a LinkScope receiver.' }}
$s.Write([Text.Encoding]::ASCII.GetBytes("START`n")); $go=New-Object byte[] 16; $null=$s.Read($go,0,$go.Length); if(-not [Text.Encoding]::ASCII.GetString($go).StartsWith('GO')){{ throw 'Receiver did not accept the test.' }}
$buf=New-Object byte[] 65536; [Random]::new().NextBytes($buf); [long]$total=0
$sw=[Diagnostics.Stopwatch]::StartNew(); $until=[DateTime]::UtcNow.AddSeconds($duration)
while([DateTime]::UtcNow -lt $until){{ $s.Write($buf,0,$buf.Length); $total += $buf.Length }}
$c.Client.Shutdown([Net.Sockets.SocketShutdown]::Send); $ack=New-Object byte[] 128; $null=$s.Read($ack,0,$ack.Length); $sw.Stop(); $c.Close()
$rate=[Math]::Round(($total*8/$sw.Elapsed.TotalSeconds)/1000000,2)
$obj=@{{port=$port;ping=@{{reachable=(@($ping).Count -gt 0);packet_loss_percent=$loss;latency_ms=$lat}};throughput=@{{mbps=$rate;sender_mbps=$rate;bytes_sent=$total;seconds=[Math]::Round($sw.Elapsed.TotalSeconds,2);method='native-tcp'}}}}
'LINKSCOPE_RESULT:' + ($obj|ConvertTo-Json -Compress -Depth 4)
"""
    encoded = __import__("base64").b64encode(remote_code.encode("utf-16le")).decode("ascii")
    args = [ssh, "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-p", str(ssh_port)]
    if key_file:
        key_path = Path(key_file).expanduser()
        if not key_path.is_file():
            raise ValueError("SSH-ключ не найден по указанному пути.")
        args.extend(["-i", str(key_path)])
    ssh_host = f"[{source}]" if ":" in source else source
    args.extend([f"{user}@{ssh_host}", "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded])
    result = run(args, timeout=seconds + 45)
    match = re.search(r"LINKSCOPE_RESULT:(\{.*\})", result.stdout)
    if result.returncode != 0 or not match:
        detail = (result.stderr or result.stdout).strip()
        if "Host key verification failed" in detail:
            detail += " Подключитесь один раз из консоли командой ssh -p PORT USER@HOST и подтвердите ключ хоста."
        raise RuntimeError(detail[-1200:] or "SSH-команда не вернула результат. Убедитесь, что на источнике доступен Windows PowerShell.")
    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise RuntimeError("SSH вернул ответ, который не удалось разобрать.") from exc
    return data


def interface_info() -> dict:
    info = {"hostname": socket.gethostname(), "platform": sys.platform, "interfaces": []}
    if os.name == "nt":
        exe = shutil.which("powershell") or shutil.which("pwsh")
        if exe:
            ps = "Get-NetAdapter | Select-Object Name,Status,LinkSpeed,MacAddress,InterfaceDescription | ConvertTo-Json -Compress"
            result = run([exe, "-NoProfile", "-NonInteractive", "-Command", ps], timeout=8)
            try:
                items = json.loads(result.stdout.strip() or "[]")
                if isinstance(items, dict): items = [items]
                info["interfaces"] = items
            except json.JSONDecodeError:
                pass
    return info


def primary_ipv4() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        address = probe.getsockname()[0]
        return "" if address.startswith("127.") else address
    except OSError:
        return ""
    finally:
        probe.close()


def local_subnet() -> str:
    """Return the current IPv4 network, falling back to a common /24 mask."""
    address = primary_ipv4()
    if not address:
        return ""
    prefix = 24
    if os.name == "nt":
        exe = shutil.which("powershell") or shutil.which("pwsh")
        if exe:
            ps = (f"Get-NetIPAddress -AddressFamily IPv4 -IPAddress '{address}' "
                  "-ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty PrefixLength")
            try:
                result = run([exe, "-NoProfile", "-NonInteractive", "-Command", ps], timeout=5)
                parsed = int(result.stdout.strip())
                if 0 <= parsed <= 32:
                    prefix = parsed
            except (ValueError, subprocess.TimeoutExpired):
                pass
    return f"{address}/{prefix}"


def discover_devices(subnet_value: object) -> dict:
    """Discover responsive hosts on the local IPv4 subnet using ping and common TCP services."""
    local_ip = primary_ipv4()
    if not local_ip:
        raise RuntimeError("Не удалось определить локальный IPv4-адрес.")
    try:
        network = ipaddress.ip_network(str(subnet_value or "").strip(), strict=False)
    except ValueError as exc:
        raise ValueError("Укажите подсеть в формате CIDR, например 192.168.1.0/24.") from exc
    if network.version != 4:
        raise ValueError("Автопоиск поддерживает IPv4-подсети.")
    if ipaddress.ip_address(local_ip) not in network:
        raise ValueError(f"Подсеть должна включать локальный адрес {local_ip}.")
    if network.num_addresses > 1024:
        raise ValueError("Слишком большая подсеть: укажите диапазон максимум на 1024 адреса.")
    hosts = list(network.hosts())
    candidates = [str(host) for host in hosts if str(host) != local_ip]

    def probe(address: str) -> dict | None:
        if os.name == "nt":
            command = ["ping", "-n", "1", "-w", "350", address]
        else:
            command = ["ping", "-c", "1", "-W", "1", address]
        try:
            response = run(command, timeout=2)
            if response.returncode == 0 or re.search(r"\bTTL\s*=", response.stdout, re.I):
                return {"ip": address, "name": address, "detected_by": "ping"}
        except (OSError, subprocess.TimeoutExpired):
            pass
        for port in (22, 80, 443, 445, 3389, 8080, 8766):
            try:
                with socket.create_connection((address, port), timeout=0.12):
                    return {"ip": address, "name": address, "detected_by": f"TCP/{port}"}
            except OSError:
                continue
        return None

    found_by_ip = {}
    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = [pool.submit(probe, address) for address in candidates]
        for future in as_completed(futures):
            device = future.result()
            if device:
                found_by_ip[device["ip"]] = device
    # A ping sweep refreshes the local neighbor cache. Keep cached hosts too,
    # since firewalls often block both ICMP replies and unsolicited TCP probes.
    if os.name == "nt":
        try:
            arp = run(["arp", "-a"], timeout=5)
            for line in arp.stdout.splitlines():
                ip_match = re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", line)
                mac_match = re.search(r"\b(?:[0-9a-f]{2}[-:]){5}[0-9a-f]{2}\b", line, re.I)
                if not ip_match or not mac_match:
                    continue
                try:
                    address = ipaddress.ip_address(ip_match.group(0))
                except ValueError:
                    continue
                if address in network and str(address) != local_ip:
                    found_by_ip.setdefault(str(address), {"ip": str(address), "name": str(address),
                                                          "detected_by": "ARP", "mac": mac_match.group(0)})
        except (OSError, subprocess.TimeoutExpired):
            pass
    found = list(found_by_ip.values())
    found.sort(key=lambda item: tuple(int(part) for part in item["ip"].split(".")))
    return {"subnet": str(network), "local_ip": local_ip, "scanned": len(candidates), "devices": found}


def parse_endpoint(value: str) -> tuple[str, int | None]:
    value = value.strip()
    if value.startswith("[") and "]:" in value:
        address, port = value[1:].rsplit("]:", 1)
    elif ":" in value:
        address, port = value.rsplit(":", 1)
    else:
        return value, None
    try:
        return address, int(port) if port.isdigit() else None
    except ValueError:
        return address, None


def process_names_windows() -> dict[int, str]:
    if os.name != "nt":
        return {}
    result = run(["tasklist", "/FO", "CSV", "/NH"], timeout=8)
    names: dict[int, str] = {}
    for row in csv.reader(io.StringIO(result.stdout)):
        if len(row) >= 2 and row[1].isdigit():
            names[int(row[1])] = row[0]
    return names


def connections_netstat(engine: str) -> dict:
    if os.name == "nt":
        if engine == "cmd":
            result = run([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", "netstat -ano"], timeout=12)
        else:
            result = run(["netstat", "-ano"], timeout=12)
    else:
        if engine == "cmd":
            raise RuntimeError("Режим Windows CMD доступен только в Windows.")
        ss = shutil.which("ss")
        if not ss:
            raise RuntimeError("Для списка соединений установите утилиту ss (iproute2).")
        result = run([ss, "-tunap"], timeout=12)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Не удалось прочитать таблицу соединений.")

    processes = process_names_windows()
    rows = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if not fields or fields[0].upper() not in ("TCP", "UDP"):
            continue
        protocol = fields[0].upper()
        if os.name == "nt":
            # netstat: proto, local endpoint, foreign endpoint, [state], PID
            if len(fields) < 4:
                continue
            local, remote = fields[1], fields[2]
            state = fields[3] if protocol == "TCP" and len(fields) >= 5 else ("UDP endpoint" if protocol == "UDP" else "")
            pid_text = fields[4] if protocol == "TCP" and len(fields) >= 5 else fields[3] if protocol == "UDP" else ""
            try: pid = int(pid_text)
            except ValueError: pid = None
            remote_address, remote_port = parse_endpoint(remote)
            local_address, local_port = parse_endpoint(local)
            if protocol == "TCP" and (state.upper() == "LISTENING" or remote_port is None):
                continue
            if protocol == "UDP" and (remote_port is not None or remote not in ("*:*", "0.0.0.0:0", "[::]:0")):
                # UDP rows in netstat generally expose only local endpoints, not a peer.
                remote_address, remote_port = "", None
        else:
            # ss -tunap: State Recv-Q Send-Q Local Peer Process
            if len(fields) < 5:
                continue
            state = fields[0]
            local, remote = fields[3], fields[4]
            local_address, local_port = parse_endpoint(local)
            remote_address, remote_port = parse_endpoint(remote)
            pid_match = re.search(r"pid=(\d+)", " ".join(fields[5:]))
            pid = int(pid_match.group(1)) if pid_match else None
            process_match = re.search(r'users:\(\("([^\"]+)', " ".join(fields[5:]))
            process_name = process_match.group(1) if process_match else ""
            if protocol == "TCP" and (state.upper() in ("LISTEN", "LISTENING") or remote_port is None):
                continue
            if protocol == "UDP" and remote_port is None:
                remote_address = ""
        if local_address in ("127.0.0.1", "::1") or remote_address in ("127.0.0.1", "::1"):
            continue
        rows.append({"protocol": protocol, "local_address": local_address, "local_port": local_port,
                     "remote_address": remote_address, "remote_port": remote_port,
                     "state": state, "pid": pid,
                     "process": (processes.get(pid, "") if os.name == "nt" else process_name)})
    rows.sort(key=lambda item: (item["protocol"], item["remote_address"], item["remote_port"] or 0, item["local_port"] or 0))
    peers = len({item["remote_address"] for item in rows if item["remote_address"]})
    return {"hostname": socket.gethostname(), "connections": rows, "peer_count": peers,
            "updated_at": time.strftime("%H:%M:%S"), "udp_note": "UDP не устанавливает постоянное соединение; ОС показывает локальные UDP-порты, но обычно не хранит адрес устройства-получателя."}


def connections_powershell() -> dict:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        raise RuntimeError("PowerShell не найден. Выберите режим Python или Windows CMD.")
    ps = r"""
$tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Listen' -and $_.RemotePort -gt 0 -and $_.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1') } | ForEach-Object { $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; [pscustomobject]@{protocol='TCP';local_address=$_.LocalAddress;local_port=$_.LocalPort;remote_address=$_.RemoteAddress;remote_port=$_.RemotePort;state=[string]$_.State;pid=$_.OwningProcess;process=$p.ProcessName} })
$udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; [pscustomobject]@{protocol='UDP';local_address=$_.LocalAddress;local_port=$_.LocalPort;remote_address='';remote_port=$null;state='UDP endpoint';pid=$_.OwningProcess;process=$p.ProcessName} })
@{connections=@($tcp)+@($udp)} | ConvertTo-Json -Compress -Depth 4
"""
    result = run([exe, "-NoProfile", "-NonInteractive", "-Command", ps], timeout=25)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "PowerShell не смог получить сетевые соединения.")
    try:
        data = json.loads(result.stdout.strip() or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError("Не удалось разобрать ответ PowerShell.") from exc
    rows = data.get("connections", []) if isinstance(data, dict) else []
    if isinstance(rows, dict): rows = [rows]
    rows.sort(key=lambda item: (item.get("protocol", ""), item.get("remote_address", ""), item.get("remote_port") or 0, item.get("local_port") or 0))
    peers = len({item.get("remote_address") for item in rows if item.get("remote_address")})
    return {"hostname": socket.gethostname(), "connections": rows, "peer_count": peers,
            "updated_at": time.strftime("%H:%M:%S"), "udp_note": "UDP не устанавливает постоянное соединение; ОС показывает локальные UDP-порты, но обычно не хранит адрес устройства-получателя."}


class Handler(BaseHTTPRequestHandler):
    server_version = "CableCheck/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/info":
            self.send_json(interface_info()); return
        if path == "/api/connections":
            engine = parse_qs(urlparse(self.path).query).get("engine", ["python"])[0]
            try:
                if engine not in ("python", "powershell", "cmd"):
                    raise ValueError("Выберите Python, PowerShell или Windows CMD.")
                data = connections_powershell() if engine == "powershell" else connections_netstat(engine)
                self.send_json(data)
            except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
                self.send_json({"error": str(exc)}, 400)
            return
        if path == "/api/health":
            self.send_json({"ok": True, "iperf3": bool(shutil.which("iperf3") or shutil.which("iperf")), "hostname": socket.gethostname(), "local_ip": primary_ipv4(), "local_subnet": local_subnet()}); return
        file = ROOT / ("index.html" if path in ("/", "/index.html") else "")
        if path in ("/", "/index.html") and file.is_file():
            body = file.read_bytes()
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        self.send_error(404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/discover":
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if size < 1 or size > MAX_BODY:
                    raise ValueError("Некорректный размер запроса.")
                data = json.loads(self.rfile.read(size))
                self.send_json(discover_devices(data.get("subnet")))
            except (ValueError, json.JSONDecodeError) as exc:
                self.send_json({"error": str(exc)}, 400)
            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                self.send_json({"error": str(exc)}, 400)
            except Exception as exc:
                self.send_json({"error": str(exc)}, 500)
            return
        if path == "/api/test_ssh":
            self.do_ssh_test(); return
        if path != "/api/test":
            self.send_json({"error": "Неизвестный API-метод."}, 404); return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > MAX_BODY:
                raise ValueError("Некорректный размер запроса.")
            data = json.loads(self.rfile.read(size))
            host = valid_host(data.get("target"))
            engine = data.get("engine", "python")
            if engine not in ("python", "powershell", "cmd"):
                raise ValueError("Выберите Python, PowerShell или Windows CMD.")
            port_mode = data.get("port_mode", "auto")
            port = int(data.get("port") or 8766); count = int(data.get("ping_count", 4)); seconds = int(data.get("seconds", 5))
            method = data.get("method", "native")
            if method not in ("native", "iperf3"):
                raise ValueError("Выберите встроенный TCP-тест или iperf3.")
            if port_mode not in ("auto", "manual"):
                raise ValueError("Выберите автоматический или ручной режим порта.")
            if port_mode == "auto" and not 1 <= port <= 65535:
                port = 8766
            if not (1 <= port <= 65535 and 1 <= count <= 10 and 1 <= seconds <= 30):
                raise ValueError("Порт, число ping или длительность теста вне допустимых значений.")
            start = time.time()
            ping = ping_powershell(host, count) if engine == "powershell" else ping_cmd(host, count) if engine == "cmd" else ping_python(host, count)
            throughput = None; throughput_error = None
            selected_port = None
            try:
                selected_port = select_test_port(host, method, port_mode, port)
                throughput = native_tcp_test(host, selected_port, seconds) if method == "native" else iperf_test(host, selected_port, seconds)
            except (RuntimeError, subprocess.TimeoutExpired) as exc: throughput_error = str(exc)
            self.send_json({"target": host, "engine": engine, "ping": ping, "throughput": throughput,
                            "throughput_error": throughput_error, "duration_seconds": round(time.time() - start, 1),
                            "method": method, "selected_port": selected_port})
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except subprocess.TimeoutExpired:
            self.send_json({"error": "Истекло время ожидания сетевой команды."}, 504)
        except Exception as exc:
            self.send_json({"error": str(exc)}, 500)

    def do_ssh_test(self) -> None:
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > MAX_BODY:
                raise ValueError("Некорректный размер запроса.")
            data = json.loads(self.rfile.read(size))
            source = valid_host(data.get("source"))
            target = valid_host(data.get("target"))
            user = valid_ssh_user(data.get("ssh_user"))
            ssh_port = int(data.get("ssh_port", 22))
            ssh_port_mode = data.get("ssh_port_mode", "auto")
            target_port = int(data.get("port") or 8766)
            port_mode = data.get("port_mode", "auto")
            if data.get("method", "native") != "native":
                raise ValueError("Для удалённого источника по SSH выберите встроенный TCP-метод.")
            seconds = int(data.get("seconds", 5))
            if port_mode == "auto" and not 1 <= target_port <= 65535:
                target_port = 8766
            if not (1 <= ssh_port <= 65535 and 1 <= target_port <= 65535 and 1 <= seconds <= 30):
                raise ValueError("Порт SSH, тестовый порт или длительность вне допустимых значений.")
            if port_mode not in ("auto", "manual"):
                raise ValueError("Выберите автоматический или ручной режим порта.")
            if ssh_port_mode not in ("auto", "manual"):
                raise ValueError("Выберите автоматический или ручной режим SSH-порта.")
            ssh_port = select_ssh_port(source, ssh_port_mode, ssh_port)
            started = time.time()
            result = ssh_native_test(source, user, ssh_port, str(data.get("ssh_key", "")).strip(), target, target_port, seconds, port_mode)
            self.send_json({"target": target, "source": source, "engine": "SSH / PowerShell", "method": "native",
                            "ping": result.get("ping", {"reachable": True, "packet_loss_percent": 0, "latency_ms": None}),
                            "throughput": result.get("throughput"), "throughput_error": None,
                            "selected_port": result.get("port"), "selected_ssh_port": ssh_port,
                            "duration_seconds": round(time.time() - started, 1)})
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except subprocess.TimeoutExpired:
            self.send_json({"error": "Превышено время ожидания SSH-подключения или сетевого замера."}, 504)
        except Exception as exc:
            self.send_json({"error": str(exc)}, 500)


def main() -> None:
    parser = argparse.ArgumentParser(description="Веб-панель проверки сетевых соединений")
    parser.add_argument("--host", default="127.0.0.1", help="Адрес локального веб-сервера (по умолчанию только этот компьютер)")
    parser.add_argument("--port", type=int, default=8765, help="Порт веб-панели")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    receiver = start_receiver()
    print(f"Cable Check доступен: http://127.0.0.1:{args.port}")
    print("Остановить: Ctrl+C")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nСервер остановлен.")
    finally:
        server.server_close()
        if receiver:
            receiver.shutdown()
            receiver.server_close()


if __name__ == "__main__":
    main()
