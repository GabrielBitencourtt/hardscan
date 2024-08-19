import subprocess
import socket
import redis
from scapy.all import *
from impacket import smb
from impacket.smbconnection import SMBConnection
import streamlit as st
import telnetlib 



def check_port(ip, port, protocol):
    """
    Verifica se uma porta está aberta usando o nmap.

    :param ip: Endereço IP do alvo
    :param port: Número da porta a ser verificada
    :param protocol: Protocolo para verificação ('tcp' ou 'udp')
    :return: True se a porta estiver aberta, False caso contrário
    """
    try:
        # Determina a flag do protocolo para nmap
        protocol_flag = '-sT' if protocol == 'tcp' else '-sU'

        # Executa o comando nmap
        result = subprocess.run(['nmap', protocol_flag, '-p', str(port), '-Pn', ip],
                                capture_output=True, text=True, check=True)

        # Verifica se a porta está aberta ao analisar a saída
        if 'open' in result.stdout:
            return True
        else:
            return False
    except subprocess.CalledProcessError as e:
        st.text(f"An error occurred while running nmap: {e}")
        return False

def snmpwalk(ip, community='public', oid='.1.3.6.1.2.1.1.1.0'):
    """
    Executa o comando snmpwalk em um determinado IP e retorna a saída.

    :param ip: IP do dispositivo SNMP.
    :param community: Comunidade SNMP.
    :param oid: OID para consultar.
    :return: Saída do comando snmpwalk.
    """
    try:
        # Executa o comando snmpwalk
        result = subprocess.run(
            ['snmpwalk', '-v', '2c', '-c', community, ip, oid],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        st.text(f"Error executing snmpwalk: {e}")
        return None

def scan_snmp(ip, community='public'):
    """
    Realiza uma varredura SNMP em um IP específico para identificar informações úteis.
    
    :param ip: IP para realizar a varredura.
    :param community: Comunidade SNMP.
    :return: Resultados da varredura.
    """
    oids = {
        'System Description': '.1.3.6.1.2.1.1.1.0',
        'System Name': '.1.3.6.1.2.1.1.5.0',
        'System Location': '.1.3.6.1.2.1.1.6.0',
        'System Contact': '.1.3.6.1.2.1.1.4.0',
        'System Up Time': '.1.3.6.1.2.1.1.3.0',
        'CPU Load': '.1.3.6.1.4.1.2021.11.9.0',
        'System Object ID': '.1.3.6.1.2.1.1.2.0',
        'System Services': '.1.3.6.1.2.1.1.7.0',
        'System Boot Time': '.1.3.6.1.2.1.25.1.1.0',
        'System Hardware Configuration': '.1.3.6.1.2.1.25.1.2.0',
    }

    results = {}
    for description, oid in oids.items():
        st.text(f"Consultando OID {description}: {oid}")
        output = snmpwalk(ip, community, oid)
        if output:
            results[description] = output
        else:
            results[description] = "Nenhum dado encontrado ou erro na consulta."

    return results

def nmap_check(ip, port):
    """
    Executa uma varredura nmap para identificar a versão do serviço na porta especificada.

    :param ip: Endereço IP do alvo
    :param port: Número da porta a ser verificada
    :return: Saída da varredura nmap.
    """
    try:
        # Executa o comando nmap para detectar a versão do serviço
        result = subprocess.run(
            ['nmap', '-p', str(port), '-sV', '-Pn', ip],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        st.text(f"An error occurred while running nmap for version scan: {e}")
        return None

def query_a_record(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ipval in result:
            st.text(f'IP Address: {ipval.to_text()}')
    except Exception as e:
        st.text(f'Error: {e}')

def run_nmap_dns_scan(target_ip, target_site):
    try:
        result = subprocess.run(
            ['nslookup', target_site, target_ip],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return (st.text(f"An error occurred while running nmap: {e}"))
        
def scan_memcached(ip, port):
#    Cria um pacote SYN para verificar a porta
    # packet = IP(dst=ip)/TCP(dport=port, flags='S')
    # response = sr1(packet, timeout=1)

    # if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
    #     st.text(f"Porta {port} está aberta públicamente em {ip} e aceitando conexões.")
    # else:
    #     st.text(f"Porta {port} não está acessível.")

            # with telnetlib.Telnet(ip, port) as tn:
            # # Enviar o comando 'stats'
            #     tn.write(b'stats\n')
                
            #     # Ler e retornar a resposta do servidor
            #     st.text(tn.read_all().decode('utf-8'))

def scan_netbios(ip):
    try:
        # Executa o comando nmap para verificar NetBIOS
        result = subprocess.run(
            ['nmap', '-Pn', '137', '--script', 'nbstat', ip],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return (st.text(f"An error occurred while running nmap: {e}"))
    
def check_redis_vulnerability(ip, port=6379):
    try:
        # Cria uma conexão com o servidor Redis
        r = redis.Redis(host=ip, port=port, socket_timeout=5)
        
        # Verifica se o Redis exige autenticação
        try:
            r.ping()
            auth_required = False
        except redis.AuthenticationError:
            auth_required = True
        
        # Checa a configuração de senha
        if auth_required:
            st.text(f"Redis no IP {ip}:{port} requer autenticaçao.")
        else:
            st.text(f"Redis no IP {ip}:{port} não requer autenticação. Pode representar uma falha de segurança.")
        
        # Testa comandos potencialmente perigosos
        try:
            # Executa um comando de administração, por exemplo
            r.config_get('*')
            st.text(f"Redis no IP {ip}:{port} aceita comandos de configuração.")
        except redis.ResponseError:
            st.text(f"Redis no IP {ip}:{port} não aceita comandos de configuração.")
        
        # Testa se o Redis é acessível
        try:
            r.set('test_key', 'test_value')
            value = r.get('test_key')
            if value == b'test_value':
                st.text(f"Redis no IP {ip}:{port} é gravavel.")
            else:
                st.text(f"Redis no IP {ip}:{port} não é gravavel.")
        except redis.RedisError as e:
            st.text(f"Redis at {ip}:{port} error: {e}")
    
    except redis.ConnectionError as e:
        st.text(f"Falha ao conectar no Redis no IP {ip}:{port}: {e}")

def scan_ssdp(ip):
    try:
        # Executa o comando nmap para verificar NetBIOS
        result = subprocess.run(
            ['nmap', '-sU', '-Pn', '1900', '--script=upnp-info.nse', ip],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return (st.text(f"An error occurred while running nmap: {e}"))
    
def check_smb_vulnerability(target_ip):
    
    try:
        # Conectar ao servidor SMB
        conn = SMBConnection(target_ip, target_ip, timeout=10)  # Adiciona um timeout de 10 segundos
        conn.login('', '')  # Conexão anônima

        # Obter informações sobre o sistema
        server_os = conn.getServerOS()
        st.text(f"Informações do servidor SMB {target_ip}: {server_os}")

        # Listar compartilhamentos disponíveis
        shares = conn.listShares()
        st.text(f"Compartilhamentos disponíveis no servidor SMB {target_ip}:")
        for share in shares:
            st.text(f"- {share['shi1_netname']}")

        # Fechar a conexão
        conn.logoff()
        conn.close()

    except (socket.timeout, ConnectionRefusedError) as e:
        st.text(f"Erro de conexão ao servidor SMB {target_ip}: {e}")
    except SessionError as e:
        st.text(f"Erro de sessão SMB ao conectar ao servidor {target_ip}: {e}")
    except Exception as e:
        st.text(f"Erro inesperado: {e}")

def db_check(target_ip, port):
    result = subprocess.run(
            ['nmap', '-p', str(port), '-sV', '--script=mysql-info', '-Pn', target_ip],
            capture_output=True,
            text=True,
            check=True
        )
    st.text(result.stdout)

def main(target_ip, target_port):

    st.title('Testes de vunerabilidades...')

    if(target_ip == 445):
        check_smb_vulnerability(target_ip)

    if(target_ip == 137):
        result = scan_netbios(target_ip)
        if 'Host script results' in result:
            st.text("Vulnerabilidade encontrada, seu serviço NetBIOS está exposto e entregando informações do serviço e configurações de workgroups")
        else:
            st.text("Seu serviço NetBIOS está seguro.")

    if(target_ip == 1900):    
        result_ssdp = scan_ssdp(target_ip)
        st.text(result_ssdp)

        if 'upnp-info' in result_ssdp:
            st.text("Vulnerabilidade encontrada, o IP da maquina e o arquivo de configuração estão expostos.")
        else:
            st.text("Seu serviço SSDP está seguro.")

    if(target_port == 6379):       
        check_redis_vulnerability(target_ip, target_port)

    if(target_port == 53):
        target_site = 'rnp.br'
        result = run_nmap_dns_scan(target_ip, target_site)
        if target_site in result:
            st.text("Vulnerabilidade encontrada, seu DNS está respondendo publicamente.")
        else:
            st.text("Não há vulnerabilidade de DNS.")
    
    if(target_port == 11211):
        scan_memcached('200.130.38.131', target_port)
    
    if(target_port == 3306):
        db_check('200.130.38.131', target_port)    


    # Verifica TCP e UDP
    for protocol in ['tcp', 'udp']:
        is_open = check_port(target_ip, target_port, protocol)
        st.text(f"Port {target_port} ({protocol.upper()}) is {'open' if is_open else 'closed'} on {target_ip}")
        
        # Se a porta for 161 ou 123 e estiver aberta, realiza a varredura SNMP
        if (target_port == 161 and is_open and protocol == 'udp') or (target_port == 123 and is_open and protocol == 'udp'):
            st.text(f"Port {target_port} (UDP) is open. Performing SNMP scan...")
            results = scan_snmp(target_ip, 'public')
            st.text("\nResultados da Varredura SNMP:")
            for description, output in results.items():
                st.text(f"\n{description}:\n{output}")

    # Realiza uma varredura para identificar a versão do serviço
    st.text(f"\nScanning version for port {target_port} on {target_ip}:")
    check_map = nmap_check(target_ip, target_port)

    st.text(check_map)

        # Define as versões conhecidas
    services_port = {
            3306 : 'MySQL',
            53 : 'DNS',
            123 : 'NTP',
            161 : 'SNMP',
            445 : 'SMB',
            6379 : 'Redis',
            11211 : 'Memcached'

        }

    known_versions = {
            'DNS': '9.18.5',  
            'MySQL': '8.0.39',
            'NTP': '4.2.8p15', 
            'SNMP': 'v3',  
            'SMB': 'SMB3.1.1',
            'Redis': '7.4.0',
            'Memcached': '1.6.29'
        }
   
    if target_port in services_port:
            type_service = services_port[target_port]
            last_version = known_versions[type_service]
            st.text(check_map)
            if last_version in check_map:
                st.text(f'O seu {type_service} está atualizado na última versão {last_version}')
            else:
                st.text(f'O seu {type_service} está desatualizado, atualize para a versão {last_version}')
                

if __name__ == '__main__':
    st.title('Port Input Application')
    
    target_ip = st.text_input("Enter the IP number:", value='200.130.38.131')
    
    target_port = st.number_input("Enter the port number:", min_value=1, max_value=65535)
    
    if st.button('Run Main'):
        if target_port:
            main(target_ip, target_port)
        else:
            st.error("Please enter a valid port number.")