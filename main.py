# File: main.py

import asyncio
import logging
from services.http_service import HTTPService
from services.ftp_service import FTPService
from services.ssh_service import SSHService
from utils.log_analyzer import LogAnalyzer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AdvancedHoneypot:
    def __init__(self):
        self.services = [
            HTTPService(port=8080),
            FTPService(port=2121),
            SSHService(port=2222)
        ]
        self.log_analyzer = LogAnalyzer()

    async def start_services(self):
        tasks = [service.start() for service in self.services]
        await asyncio.gather(*tasks)

    async def run(self):
        logger.info("Starting Advanced Honeypot...")
        await self.start_services()
        
        while True:
            self.log_analyzer.analyze_logs()
            await asyncio.sleep(300)  # Analyze logs every 5 minutes

if __name__ == "__main__":
    honeypot = AdvancedHoneypot()
    asyncio.run(honeypot.run())

# File: services/http_service.py

import asyncio
from aiohttp import web
import logging

logger = logging.getLogger(__name__)

class HTTPService:
    def __init__(self, port=8080):
        self.port = port

    async def handle_request(self, request):
        client_ip = request.remote
        headers = request.headers
        method = request.method
        path = request.path

        logger.info(f"HTTP request from {client_ip}: {method} {path}")
        logger.debug(f"Headers: {headers}")

        if request.method == 'POST':
            body = await request.text()
            logger.info(f"POST data: {body}")

        return web.Response(text="Welcome to our secure server!")

    async def start(self):
        app = web.Application()
        app.router.add_route('*', '/{tail:.*}', self.handle_request)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, 'localhost', self.port)
        await site.start()
        logger.info(f"HTTP service started on port {self.port}")

# File: services/ftp_service.py

import asyncio
import logging

logger = logging.getLogger(__name__)

class FTPService:
    def __init__(self, port=2121):
        self.port = port

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        logger.info(f"New FTP connection from {addr}")
        
        writer.write(b"220 Welcome to FTP server\r\n")
        await writer.drain()

        while True:
            data = await reader.readline()
            message = data.decode().strip()
            if not message:
                break

            logger.info(f"Received from {addr}: {message}")

            if message.startswith("USER"):
                writer.write(b"331 User name okay, need password\r\n")
            elif message.startswith("PASS"):
                writer.write(b"530 Login incorrect\r\n")
            elif message == "QUIT":
                writer.write(b"221 Goodbye\r\n")
                break
            else:
                writer.write(b"500 Command not understood\r\n")

            await writer.drain()

        writer.close()
        await writer.wait_closed()
        logger.info(f"FTP connection closed for {addr}")

    async def start(self):
        server = await asyncio.start_server(self.handle_client, 'localhost', self.port)
        logger.info(f"FTP service started on port {self.port}")
        async with server:
            await server.serve_forever()

# File: services/ssh_service.py

import asyncio
import logging
from asyncssh import SSHServer, create_server

logger = logging.getLogger(__name__)

class MySSHServer(SSHServer):
    def connection_made(self, conn):
        logger.info(f'SSH connection received from {conn.get_extra_info("peername")[0]}')

    def connection_lost(self, exc):
        if exc:
            logger.error(f'SSH connection error: {str(exc)}')
        else:
            logger.info('SSH connection closed')

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        logger.info(f'Login attempt - Username: {username}, Password: {password}')
        return False

class SSHService:
    def __init__(self, port=2222):
        self.port = port

    async def start(self):
        await create_server(
            MySSHServer, '', self.port,
            server_host_keys=['ssh_host_key'],
        )
        logger.info(f"SSH service started on port {self.port}")

# File: utils/log_analyzer.py

import logging
from collections import Counter
import re

logger = logging.getLogger(__name__)

class LogAnalyzer:
    def __init__(self):
        self.ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        self.logs = []

    def analyze_logs(self):
        with open('honeypot.log', 'r') as f:
            self.logs = f.readlines()

        ip_addresses = [re.search(self.ip_pattern, line).group() for line in self.logs if re.search(self.ip_pattern, line)]
        ip_counts = Counter(ip_addresses)

        logger.info("Top 5 IP addresses by request count:")
        for ip, count in ip_counts.most_common(5):
            logger.info(f"{ip}: {count}")

        self.detect_potential_attacks()

    def detect_potential_attacks(self):
        ssh_bruteforce_threshold = 10
        sql_injection_pattern = r'(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*'

        ssh_attempts = Counter()
        sql_injection_attempts = []

        for line in self.logs:
            if "SSH connection received" in line:
                ip = re.search(self.ip_pattern, line).group()
                ssh_attempts[ip] += 1
            
            if re.search(sql_injection_pattern, line, re.IGNORECASE):
                sql_injection_attempts.append(line)

        logger.info("Potential SSH brute force attacks:")
        for ip, count in ssh_attempts.items():
            if count > ssh_bruteforce_threshold:
                logger.warning(f"Possible SSH brute force from {ip}: {count} attempts")

        if sql_injection_attempts:
            logger.warning(f"Detected {len(sql_injection_attempts)} potential SQL injection attempts")
            for attempt in sql_injection_attempts[:5]:  # Log first 5 attempts
                logger.warning(f"SQL Injection attempt: {attempt.strip()}")

# File: ssh_host_key
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAu8q51eap4KQDaA4CNd3ZYoSV0YZWq5JThNsEQMrgLwtV3gTOUa6q
/example/key/content/FDwoPBBGeUZhz5SkXdF8DhLdklHvxqxM+cDSBFEXoQwFe1xD5Q==
-----END OPENSSH PRIVATE KEY-----
