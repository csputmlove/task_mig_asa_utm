import os, sys, json
import ipaddress, copy
import logging
import argparse
import hashlib
from collections import deque
from core import MyConv
from utils import create_dir, read_json_file
from services_lib import (service_ports, ug_services,
                      zone_services, ip_proto)

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class ConvertCiscoASAConfig(MyConv):
    """Преобразуем файл конфигурации Cisco ASA в формат UserGate NGFW."""
    
    def __init__(self, current_asa_path, current_ug_path):
        super().__init__()
        self.current_asa_path = current_asa_path
        self.current_ug_path = current_ug_path
        self.services = {}
        self.service_groups = {}
        self.ip_lists = set()
        self.vendor = 'Cisco ASA'
        self.error_convert_config_file = 0
        self.error = 0

    def run(self):
        logging.info(f'{"Конвертация конфигурации Cisco ASA в формат UserGate NGFW.":>110}')
        logging.info(f'{"="*110}')
        self.convert_config_file()
        if self.error:
            logging.info('Конвертация конфигурации Cisco ASA в формат UserGate NGFW прервана.\n')
        else:
            if self.error_convert_config_file:
                self.error = 1
            json_file = os.path.join(self.current_asa_path, 'cisco_asa.json')
            err, data = self.read_json_file(json_file)
            if err:
                logging.error('iКонвертация конфигурации Cisco ASA в формат UserGate NGFW прервана.\n')
                self.error = 1
            else:
                self.convert_ntp_settings(data['ntp'])
                self.convert_dns_servers(data['dns']['system_dns'])
                self.convert_dns_rules(data['dns']['dns_rules'])
                self.convert_dns_static(data['dns']['dns_static'])
                self.convert_dhcp_settings(data)
                self.convert_vlan_interfaces(data)
                self.convert_gateways(data)
                self.convert_routes(data)
                self.convert_local_groups(data)
                self.convert_local_users(data['local-users'])
                self.convert_auth_servers(data)
                self.convert_service_object(data)
                self.convert_ip_lists(data['ip_lists'])
                self.convert_network_object_group(data)
                self.convert_firewall_rules(data)

                self.save_services()
                self.save_service_groups()

            if self.error:
                logging.info('Конвертация конфигурации Cisco ASA в формат UserGate NGFW прошла с ошибками.\n')
            else:
                logging.info('Конвертация конфигурации Cisco ASA в формат UserGate NGFW прошла успешно.\n')


    def convert_config_file(self):
        """Преобразуем файл конфигурации Cisco ASA в json."""
        logging.info('Преобразование файла конфигурации Cisco ASA в json.')
        if not os.path.isdir(self.current_asa_path):
            logging.error(f'    Не найден каталог {self.current_asa_path} с конфигурации Cisco ASA.')
            self.error = 1
            return

        error = 0
        asa_config_file = os.path.join(self.current_asa_path, 'cisco_asa.cfg')
        config_data = []

        try:
            with open(asa_config_file, "r") as fh:
                for line in fh:
                    config_data.append(line)
        except FileNotFoundError:
            logging.error(f'    Error! Не найден файл {asa_config_file} с конфигурации Cisco ASA.')
            self.error = 1
            return
        bgp_data = self.parse_bgp(config_data)

        data = {
            'timezone': '',
            'ntp': [],
            'domain-name': '',
            'dns': {
                'domain-lookup': [],
                'dns_rules': [],
                'system_dns': [],
                'dns_static': []
            },
            'cli-ssh': [],
            'web-console': [],
            'auth-type': {},
            'auth_servers': [],
            'time-range': {},
            'local-users': {},
            'local-groups': {},
            'identity_domains': {},
            'services': {},
            'url_lists': {},
            'ip_lists': {},
            'network-group': {},
            'bgp': bgp_data,
            'service-group': {},
            'protocol-group': {},
            'icmp-group': {},
            'direction': {},
            'fw_access-list': {},
            'fw_rule_number': 0,
            'cf_access-list': {},
            'cf_rule_number': 0,
        }

        for line in config_data:
            if line[:1] in {':', '!'}:
                continue
        num = 0
        while (len(config_data) - num):
            line = config_data[num]
            if line[:1] in {':', '!'}:
                num += 1
                continue
            tmp_block = []
            x = line.translate(self.trans_table).rsplit(' ')
            match x[0]:
                case 'domain-name':
                    data['domain-name'] = x[1]
                case 'dns':
                    match x[1:]:
                        case ['domain-lookup', zone_name]:
                            data['dns']['domain-lookup'].append(zone_name.translate(self.trans_object_name))
                        case 'forwarder':
                            create_dns_servers(data, x)
                        case ['server-group', servergroup_name]:
                            num, tmp_block = self.get_block(config_data, num)
                            self.create_dns_rules(data, servergroup_name, tmp_block)
                case 'name':
                    data['dns']['dns_static'].append(x[1:])
                case 'telnet' | 'ssh'| 'http':
                    match x:
                        case ['telnet' | 'ssh', ip, mask, zone_name]:
                            if ip not in ('version', 'key-exchange', 'cipher'):
                                err, ip_address = self.pack_ip_address(ip, mask)
                                if err:
                                    logging.error(f'    Error: Не корректный IP-адрес в "{" ".join(x)}".')
                                    error = 1
                                else:
                                    data['cli-ssh'].append({
                                        'zone': zone_name.translate(self.trans_object_name),
                                        'ip': ip_address
                                    })
                        case ['http', ip, mask, zone_name]:
                            err, packed_address = self.pack_ip_address(ip, mask)
                            if not err:
                                data['web-console'].append({
                                    'zone': zone_name.translate(self.trans_object_name),
                                    'ip': packed_address
                                })
                case 'aaa-server':
                    num, tmp_block = self.get_block(config_data, num)
                    self.create_auth_servers(data, x, tmp_block)
                case 'time-range':
                    num, tmp_block = self.get_block(config_data, num)
                    data['time-range'][x[1].translate(self.trans_object_name)] = tmp_block
                case 'ntp':
                    match x:
                        case ['ntp', 'server', ip, *other]:
                            data['ntp'].append(ip)
                case 'dhcp':
                    self.create_dhcp_settings(data, x[1:])
                case 'username':
                    if x[2] == 'password':
                        data['local-users'][x[1]] = []
                case 'object':
                    match x[1]:
                        case 'service':
                            num, tmp_block = self.get_block(config_data, num)
                            data['services'][x[2]] = tmp_block
                        case 'network':
                            num, tmp_block = self.get_block(config_data, num)
                            if tmp_block:
                                match tmp_block[0][0]:
                                    case 'subnet'|'host'|'range':
                                        data['ip_lists'][x[2]] = tmp_block
                                    case 'fqdn':
                                        data['url_lists'][x[2]] = tmp_block
                                    case _:
                                        logging.error(f'b    object network {x[2]} не конвертирован.')
                            else:
                                logging.info(f'r    object network {x[2]} не конвертирован так как не имеет содержимого.')
                case 'object-group':
                    match x[1]:
                        case 'network':
                            num, tmp_block = self.get_block(config_data, num)
                            data['network-group'][x[2]] = tmp_block
                        case 'service':
                            num, tmp_block = self.get_block(config_data, num)
                            data['service-group']['|'.join(x[2:])] = tmp_block
                        case 'protocol':
                            num, tmp_block = self.get_block(config_data, num)
                            data['protocol-group'][x[2]] = tmp_block
                        case 'user':
                            num, tmp_block = self.get_block(config_data, num)
                            data['local-groups'][x[2]] = tmp_block
                        case 'icmp-type':
                            num, tmp_block = self.get_block(config_data, num)
                            data['icmp-group'][x[2]] = tmp_block
                        case _:
                            logging.info(f'r    object network {x[2]} не конвертирован.')
                case 'access-group':
                    self.create_access_group(data, x[1:])
            num += 1

        num = 0
        remark = []
        while (len(config_data) - num):
            line = config_data[num]
            if line[:1] in {':', '!'}:
                num += 1
                continue
            tmp_block = []
            x = line.translate(self.trans_table).rsplit(' ')
            match x[0]:
                case 'access-list':
                    match x[2]:
                        case 'remark':
                            line = config_data[num+1]
                            y = line.translate(self.trans_table).rstrip().split(' ')
                            if y[1] == x[1]:
                                remark.append(f'{" ".join(x[3:])}\n')
                        case 'extended':
                            self.create_ace(data, x[1], x[3:], remark)
                            remark.clear()
                        case 'advanced':
                            self.create_ace(data, x[1], x[3:], remark)
                            remark.clear()
                        case 'line':
                            if x[4] == 'extended':
                                self.create_ace(data, x[1], x[5:], remark)
                            remark.clear()
                        case _:
                            string = line.rstrip('\n')
                            logging.info(f'r    Access-list "{string}" - не обработан.')
                            remark.clear()
                            self.msleep(3)
            num += 1

        bgp_dir = os.path.join(self.current_ug_path, 'Libraries', 'BGP')
        create_dir(bgp_dir, delete='no')
        with open(os.path.join(bgp_dir, 'bgp.json'), 'w', encoding='utf-8') as fh:
            json.dump(data['bgp'], fh, indent=4, ensure_ascii=False)

        json_file = os.path.join(self.current_asa_path, 'cisco_asa.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

        if error:
            self.error_convert_config_file = 1
            logging.info('    В процессе преобразования произошла ошибка. Некоторые параметры не будут конвертированы.')
        else:
            logging.info(f'    Конфигурация Cisco ASA в формате json выгружена в файл "{json_file}".')


    def get_block(self, config_data, num):
        """Читаем файл и создаём блок записей для раздела конфигурации"""
        block = []
        data_index = num + 1
        while config_data[data_index].startswith(' '):
            block.append(config_data[data_index].translate(self.trans_table).strip().split(' '))
            data_index += 1 
        return data_index - 1, block


    @staticmethod
    def create_dns_servers(data, x):
        """Заполняем список системных DNS"""
        data['dns']['system_dns'].append(x[2])


    @staticmethod
    def create_dns_rules(data, rule_name, data_block):
        """
        Если в data_block нет domain-name, то создаём системные DNS-сервера.
        Если есть, создаём правило DNS прокси Сеть->DNS->DNS-прокси->Правила DNS.
        """
        dns_rule = {
            "name": rule_name,
            "domains": [],
            "dns_servers": [],
        }
        for item in data_block:
            match item[0]:
                case 'name-server':
                    dns_rule['dns_servers'].append(item[1])
                case 'domain-name':
                    dns_rule['domains'].append(f'*.{item[1]}')
        if dns_rule['domains']:
            data['dns']['dns_rules'].append(dns_rule)
        else:
            for x in dns_rule['dns_servers']:
                data['dns']['system_dns'].append(x)

    @staticmethod
    def create_auth_servers(data, x, data_block):
        """Конвертируем сервера авторизации"""
        match x:
            case ['aaa-server', auth_server, 'protocol', protocol]:
                data['auth-type'][auth_server] = protocol

            case ['aaa-server', auth_server, zone_name, 'host', ip]:
                if (protocol := data['auth-type'].get(auth_server), None):
                    auth_srv = {
                        'name': f'{auth_server} ({ip})',
                        'description': '',
                        'address': ip,
                    }
                    if protocol in ['ldap', 'kerberos']:
                        auth_srv['description'] = 'ldap'
                    if protocol == 'radius':
                        auth_srv['description'] = 'radius'
                    if protocol.startswith('tacacs'):
                        auth_srv['description'] = 'tacacs'
                    auth_srv.update({k: ' '.join(v) for k, *v in data_block})
                    data['auth_servers'].append(auth_srv)


    @staticmethod
    def create_dhcp_settings(data, dhcp_array):
        """Конвертируем настройки DHCP"""
        match dhcp_array:
            case ['address', ip_range, name]:
                data['dhcp-subnets'][name] = {
                    'ip_range': ip_range,
                    'reserv': []
                }
            case ['reserve-address', ip, mac, name]:
                data['dhcp-subnets'][name]['reserv'].append([ip, mac])
            case ['dns', *ips]:
                data['dhcp-opt']['dns'] = ips
            case ['lease', lease]:
                data['dhcp-opt']['lease'] = int(lease) if (120 < int(lease) < 3600000) else 3600
            case ['domain', name]:
                data['dhcp-opt']['domain'] = name
            case ['option', code, 'ip'|'ascii', *ips]:
                data['dhcp-opt']['options'].append([int(code), ", ".join(ips)])

    
    @staticmethod
    def create_user_identity_domains(data, line):
        """Определяем домены идентификации"""
        match line:
            case ['domain', domain, 'aaa-server', server]:
                domain = domain.split(".")
                if len(domain) == 1:
                    data['identity_domains'][domain[0]] = data['domain-name']
                else:
                    for item in data['auth_servers']:
                        if item['name'].startswith(domain[0]):
                            dn = ".".join([y[1] for y in [x.split("=") for x in item['ldap-base-dn'].split(",")]]).lower()
                            data['identity_domains'][domain[0]] = dn
                            break
            case ['default-domain', domain]:
                if domain != 'LOCAL':
                    domain = domain.split(".")
                    data['identity_domains']['default'] = data['identity_domains'][domain[0]]

    def mask_to_cidr(mask: str) -> int:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen

    def parse_route_maps(lines: list[str]) -> dict:
        """Ищет в lines блоки route-map → возвращает {name: {'match': prefix_list_name}}."""
        rm = {}
        current = None
        for l in lines:
            m = re.match(r'\s*route-map\s+(\S+)\s+\S+\s+\d+', l)
            if m:
                current = m.group(1)
                rm[current] = {}
            m2 = re.match(r'\s* match ip address prefix-list\s+(\S+)', l)
            if m2 and current:
                rm[current]['match'] = m2.group(1)
        return rm

    def parse_prefix_lists(lines: list[str]) -> dict:
        """Ищет в lines префикс-листы → возвращает {name: [network1, …]}."""
        pl = {}
        for l in lines:
            m = re.match(r'\s*ip prefix-list\s+(\S+)\s+permit\s+(\S+)', l)
            if m:
                name, net = m.groups()
                pl.setdefault(name, []).append(net)
        return pl

    def parse_bgp(lines: list[str]) -> dict:
        """Полноценно парсит BGP: as-number, router-id, redistribute, networks, route-maps, neighbors."""
        bgp = {}
        in_af = False
        neighbors = {}
        redistribute = []
        networks = []
        route_maps = parse_route_maps(lines)
        prefixes   = parse_prefix_lists(lines)

        for l in lines:
            if l.startswith('router bgp'):
                bgp['as_number'] = int(l.split()[2])
            if 'bgp router-id' in l:
                bgp['router_id'] = l.split()[-1]
            if l.strip().startswith('address-family ipv4 unicast'):
                in_af = True
            if in_af:
                m1 = re.match(r'\s*neighbor\s+(\S+)\s+remote-as\s+(\d+)', l)
                if m1:
                    ip, asn = m1.groups()
                    neighbors[ip] = {'host':ip,'remote_asn':int(asn),'routemap_in':[],'routemap_out':[]}
                m2 = re.match(r'\s*neighbor\s+(\S+)\s+route-map\s+(\S+)\s+(in|out)', l)
                if m2:
                    ip, rm, dr = m2.groups()
                    if ip in neighbors: neighbors[ip][f'routemap_{dr}'].append(rm)
                m3 = re.match(r'\s*redistribute\s+(\S+)', l)
                if m3: redistribute.append(m3.group(1))
                m4 = re.match(
                   r'\s*network\s+(\d+\.\d+\.\d+\.\d+)\s+mask\s+(\d+\.\d+\.\d+\.\d+)', l)
                if m4:
                    net, mask = m4.groups()
                    cidr = mask_to_cidr(mask)
                    networks.append(f"{net}/{cidr}")
            if in_af and l.strip().startswith('exit-address-family'):
                in_af = False

        # Строим списки route-maps и neighbors
        rmlist = []
        for name,cfg in route_maps.items():
            items = prefixes.get(cfg.get('match',''), [])
            rmlist.append({
                "id":"", "name":name, "description":cfg.get('match',''),
                "action":"permit","match_by":"ip","next_hop":"",
                "metric":0,"weight":0,"preference":0,"as_prepend":"",
                "community":"","additive":False,"match_items":items
            })
        neigh_list = []
        for nb in neighbors.values():
            neigh_list.append({
                "id":"","enabled":True,"state":"","description":"",
                "host":nb['host'],"remote_asn":nb['remote_asn'],
                "weight":0,"next_hop_self":True,"ebgp_multihop":False,
                "route_reflector_client":False,"multihop_ttl":0,
                "soft_reconfiguration":False,"default_originate":False,
                "send_community":False,"password":False,"filter_in":[],
                "filter_out":[],"routemap_in":nb['routemap_in'],
                "routemap_out":nb['routemap_out'],
                "allowas_in":False,"allowas_in_number":0,"bfd_profile":""
            })
        bgp.update({
            "id":"","enabled":bool(bgp.get('as_number',0)),
            "multiple_path":False,"redistribute":redistribute,
            "networks":networks,"routemaps":rmlist,"filters":[],
            "neighbors":neigh_list
        })
        return bgp


    def create_access_group(self, data, x):
        """
        Конвертируе access-group. Сопоставляем имя access-list с зоной интерфейса и определяем источник это или назначение.
        """
        if x[0] not in data['direction']:
            data['direction'][x[0]] = {
                "src_zones": [],
                "dst_zones": []
            }
        match x:
            case [access_list_name, 'in', 'interface', zone_name]:
                data['direction'][access_list_name]['src_zones'].append(zone_name.translate(self.trans_object_name))
            case [access_list_name, 'out', 'interface', zone_name]:
                data['direction'][access_list_name]['dst_zones'].append(zone_name.translate(self.trans_object_name))
            case [access_list_name, 'interface', ifname, 'global']:
                pass
            case _:
                data['direction'].pop(x[0], None)


    @staticmethod
    def create_ace(data, acs_name, rule_block, remark):
        """Подгатавливаем access-list к конвертации. Формируем имя правила и описание."""
        data['fw_rule_number'] += 1
        name = f'Rule {data["fw_rule_number"]}'
        data['fw_access-list'][name] = {
            'name': acs_name,
            'description': ', '.join(remark),
            'content': rule_block
        }


    @staticmethod
    def create_webtype_ace(data, acs_name, rule_block, remark):
        """Подгатавливаем access-list к конвертации. Формируем имя правила и описание."""
        data['cf_rule_number'] += 1
        name = f'Rule {data["cf_rule_number"]}'
        data['cf_access-list'][name] = {
            'name': acs_name,
            'description': ', '.join(remark),
            'content': rule_block
        }

#------------------------------------ Конвертация структуры data в json UG NGFW -----------------------------------------
    def convert_settings_ui(self, timezone):
        """Конвертируем часовой пояс"""
        logging.info('Конвертация часового пояса.')
        if timezone:
            current_path = os.path.join(self.current_ug_path, 'UserGate', 'GeneralSettings')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                logging.error(f'    {msg}.')
                self.error = 1
                return

            settings = {"ui_timezone": timezone}

            json_file = os.path.join(current_path, 'config_settings_ui.json')
            with open(json_file, 'w') as fh:
                json.dump(settings, fh, indent=4, ensure_ascii=False)
            logging.info(f'    Значение часового пояса выгружено в файл "{json_file}".')
        else:
            logging.info('    Нет часового пояса для экспорта.')


    def convert_ntp_settings(self, ntp_data):
        """Конвертируем настройки для NTP"""
        logging.info('Конвертация настроек NTP.')
        if ntp_data:
            current_path = os.path.join(self.current_ug_path, 'UserGate', 'GeneralSettings')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                logging.error(f'    {msg}.')
                self.error = 1
                return

            ntp = {
                "ntp_servers": [],
                "ntp_enabled": True,
                "ntp_synced": True
            }
            for ip in ntp_data:
                if len(ntp['ntp_servers']) < 2:
                    ntp['ntp_servers'].append(ip)

            json_file = os.path.join(current_path, 'config_ntp.json')
            with open(json_file, 'w') as fh:
                json.dump(ntp, fh, indent=4, ensure_ascii=False)
            logging.info(f'    Настройка NTP выгружена в файл "{json_file}".')
        else:
            logging.info('    Нет настроек NTP для экспорта.')


    def convert_dns_servers(self, system_dns):
        """Заполняем список системных DNS"""
        logging.info('Конвертация системных DNS-серверов.')
        if system_dns:
            current_path = os.path.join(self.current_ug_path, 'Network', 'DNS')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                logging.error(f'    {msg}.')
                self.error = 1
                return

            dns_servers = []
            for ip in system_dns:
                dns_servers.append({
                    'dns': ip,
                    'is_bad': False
                })

            json_file = os.path.join(current_path, 'config_dns_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(dns_servers, fh, indent=4, ensure_ascii=False)
            logging.info(f'    Системные DNS-сервера выгружены в файл "{json_file}".')
        else:
            logging.info('    Нет системных DNS-серверов для экспорта.')


    def convert_dns_rules(self, dns_rules):
        """Создаём правило DNS прокси Сеть->DNS->DNS-прокси->Правила DNS"""
        logging.info('Конвертация правил DNS в DNS-прокси.')
        if dns_rules:
            current_path = os.path.join(self.current_ug_path, 'Network', 'DNS')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                logging.error(f'    {msg}.')
                self.error = 1
                return

            rules = []
            for item in dns_rules:
                error, rules_name = self.get_transformed_name(item['name'], descr='Имя правила DNS')
                rules.append({
                    'name': rules_name,
                    'description': 'Перенесено с Cisco ASA',
                    'enabled': True,
                    'position': 'last',
                    'domains': item['domains'],
                    'dns_servers': item['dns_servers']
                })

            json_file = os.path.join(current_path, 'config_dns_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(rules, fh, indent=4, ensure_ascii=False)
            logging.info(f'    Правила DNS выгружены в файл "{json_file}".')
        else:
            logging.info('    Нет правил DNS для экспорта.')


    def convert_dns_static(self, dns_static):
        """Конвертируем статические записи DNS"""
        logging.info('Конвертация статических записей DNS.')
        if dns_static:
            current_path = os.path.join(self.current_ug_path, 'Network', 'DNS')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                logging.error(f'    {msg}.')
                self.error = 1
                return

            records = []
            for item in dns_static:
                error, name = self.get_transformed_name(item[1], descr='Имя статической записи DNS')
                msg_descr = 'Перенесено с Cisco ASA'
                records.append({
                    'name': name,
                    'description': msg_descr if len(item) < 3 else f"{msg_descr}\n{' '.join(item[3:])}",
                    'enabled': True,
                    'domain_name': item[1],
                    'ip_addresses': [item[0]]
                })

            json_file = os.path.join(current_path, 'config_dns_static.json')
            with open(json_file, 'w') as fh:
                json.dump(records, fh, indent=4, ensure_ascii=False)
            logging.info(f'    Статические записи DNS выгружены в файл "{json_file}".')
        else:
            logging.info(f'    Нет статических записей DNS для экспорта.')

    def convert_vlan_interfaces(self, data):
        """Конвертируем интерфейсы VLAN."""
        self.stepChanged.emit('BLUE|Конвертация интерфейсов VLAN.')
        if data['ifaces']:
            current_path = os.path.join(self.current_ug_path, 'Network', 'Interfaces')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}.')
                self.error = 1
                return

            ifaces = []
            for item in data['interfaces']:
                if item.get('nameif','').lower() == 'mgmt':
                    continue
                if item['nameif'].lower() == 'outside':
                    zone_id = 3
                    port_num = '0'
                else:
                    zone_id = 2
                    port_num = '1'
                relay = data.get('dhcp_relay', {}).get(item['nameif'], {})
                    dhcp_relay = {
                        'enabled': bool(relay),
                        'host_ipv4': relay.get('host', ''),
                        'servers': relay.get('servers', [])
                ifaces.append({
                    'name': item.get('nameif', item['ipv4']),
                    'kind': 'vlan',
                    'enabled': False,
                    'description': f"Перенесено с Cisco ASA.\n{item['description']}",
                    'zone_id': zone_id,
                    'master': False,
                    'netflow_profile': 'undefined',
                    'lldp_profile': 'undefined',
                    'ipv4': [item['ipv4']],
                    'ifalias': '',
                    'flow_control': False,
                    'mode': 'static',
                    'mtu': data['zones'][item['nameif']] if item.get('nameif', False) in data['zones'] else 1500,
                    'tap': False,
                    'dhcp_relay': dhcp_relay,
                    'vlan_id': item['vlan'],
                    'link': ''
                })

            json_file = os.path.join(current_path, 'config_interfaces.json')
            with open(json_file, 'w') as fh:
                json.dump(ifaces, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Интерфейсы VLAN выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет интерфейсов VLAN для экспорта.')


    def convert_gateways(self, data):
        """Конвертируем шлюзы"""
        self.stepChanged.emit('BLUE|Конвертация шлюзов.')
        if data['gateways']:
            current_path = os.path.join(self.current_ug_path, 'Network', 'Gateways')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}.')
                self.error = 1
                return

            gateways = []
            for key, value in data['gateways'].items():
                _, name = self.get_transformed_name(key, descr='Имя шлюза')
                if value.get('interface','').lower() == 'outside':
                    iface = 'port0'
                else:
                    iface = 'port1'
                gateways.append({
                    'name': name,
                    'enabled': True,
                    'description': 'Перенесено с Cisco ASA.',
                    'ipv4': value['ipv4'],
                    'vrf': 'default',
                    'weight': value['weight'],
                    'multigate': False,
                    'default': False,
                    'iface': iface,
                    'is_automatic': False,
                })

            json_file = os.path.join(current_path, 'config_gateways.json')
            with open(json_file, 'w') as fh:
                json.dump(gateways, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройки шлюзов выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет шлюзов для экспорта.')


    def convert_routes(self, data):
        """Конвертируем статические маршруты"""
        self.stepChanged.emit('BLUE|Конвертация статических маршрутов.')
        if data['routes']:
            current_path = os.path.join(self.current_ug_path, 'Network', 'VRF')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}.')
                self.error = 1
                return

            default_vrf = {
                'name': 'default',
                'descriprion': 'Перенесено с Cisco ASA.',
                'interfaces': [],
                'routes': [],
                'ospf': {},
                'bgp': {},
                'rip': {},
                'pimsm': {}
            }
            for route in data['routes']:
                _, name = self.get_transformed_name(route['name'], descr='Имя шлюза')
                if value.get('interface','').lower() == 'outside':
                    r_iface = 'port0'
                else
                    r_iface = 'port1'
                default_vrf['routes'].append({
                    'name': name,
                    'description': 'Перенесено с Cisco ASA.',
                    'enabled': True,
                    'dest': route['dest'],
                    'gateway': route['gateway'],
                    'ifname': r_iface,
                    'kind': 'unicast',
                    'metric': route['metric']
                })

            json_file = os.path.join(current_path, 'config_vrf.json')
            with open(json_file, 'w') as fh:
                json.dump([default_vrf], fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Статические маршруты выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет статических маршрутов для экспорта.')


    def convert_dhcp_settings(self, data):
        """Конвертируем настройки DHCP"""
        self.stepChanged.emit('BLUE|Конвертация настроек DHCP.')
        if data['dhcp-subnets']:
            current_path = os.path.join(self.current_ug_path, 'Network', 'DHCP')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}.')
                self.error = 1
                return
    
            dhcp_subnets = []
            for key, item in data['dhcp-subnets'].items():
                if key.lower() == 'mgmt':
                    continue
                if key.lower() == 'outside':
                    iface_id = 'port0'
                else:
                    iface_id = 'port1'
                ips = item['ip_range'].split('-')
                netmask = '255.255.255.0'
                if data['dhcp-opt']['options']:
                    options = [x for x in data['dhcp-opt']['options'] if x[0] != 3]
                    gateways = [y for x, y in data['dhcp-opt']['options'] if x == 3]
                    gateway = gateways[0] if gateways else f'{ips[0].rpartition(".")[0]}.1'
                    for mask in ('255.255.255.0', '255.255.0.0', '255.0.0.0'):
                        sub1 = ipaddress.ip_interface(f'{gateway}/{mask}')
                        sub2 = ipaddress.ip_interface(f'{ips[0]}/{mask}')
                        if sub2.ip in sub1.network:
                            netmask = mask
                            break
                else:
                    options = []
                    gateway = f'{ips[0].rpartition(".")[0]}.1'
                reserve = []
                number = 0
                for ip, mac in item['reserv']:
                    number += 1
                    mac_address = ":".join([f"{x[:2]}:{x[2:]}" for x in mac.split('.')])
                    reserve.append({"mac": mac_address.upper(), "ipv4": ip, "hostname": f"Any{key.title()}-{number}"})

                    name = self.get_transformed_name(f'DHCP server for {key}', descr='Имя правила DHCP')
                dhcp_subnets.append({
                    'name': name,
                    'enabled': False,
                    'description': 'Перенесено с Cisco ASA',
                    'start_ip': ips[0],
                    'end_ip': ips[1],
                    'lease_time': lease if (120 < (lease := int(data['dhcp-opt']['lease'])) < 3600000) else 3600,
                    'domain': data['dhcp-opt']['domain'],
                    'gateway': gateway,
                    'boot_filename': '',
                    'boot_server_ip': '',
                    'iface_id': iface_id,
                    'netmask': netmask,
                    'nameservers': data['dhcp-opt']['dns'],
                    'ignored_macs': [],
                    'hosts': reserve,
                    'options': options,
                })

            json_file = os.path.join(current_path, 'config_dhcp_subnets.json')
            with open(json_file, 'w') as fh:
                json.dump(dhcp_subnets, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройки DHCP выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет настроек DHCP для экспорта.')


    def convert_local_groups(self, data):
        """Конвертируем локальные группы пользователей"""
        logging.info('Конвертация локальных групп пользователей.')
        if data['local-groups']:
            current_path = os.path.join(self.current_ug_path, 'UsersAndDevices', 'Groups')
            err, msg = self.create_dir(current_path)
            if err:
                logging.error(f'    {msg}.')
                self.error = 1
                return

            groups = {}
            for key, value in data['local-groups'].items():
                group = {
                    'name': key,
                    'description': 'Перенесено с Cisco ASA.',
                    'is_ldap': False,
                    'is_transient': False,
                    'users': []
                }
                for item in value:
                    match item:
                        case ['user', user]:
                            user_list = user.split("\\")
                            if user_list[0] == 'LOCAL' and user_list[1] in data['local-users']:
                                group['users'].append(user_list[1])
                            elif user_list[0] in data['identity_domains']:
                                group['users'].append(f"{user_list[1]} ({data['identity_domains'][user_list[0]]}\\{user_list[1]})")
                            else:
                                if len(user_list) == 1:
                                    if 'default' in data['identity_domains']:
                                        group['users'].append(f"{user_list[0]} ({data['identity_domains']['default']}\\{user_list[0]})")
                                    else:
                                        group['users'].append(user_list[0])
                        case ['group-object', group_name]:
                            group['users'].extend(groups[group_name]['users'])
                        case ['description', *content]:
                            group['description'] = f"{group['description']}\n{' '.join(content)}"
                groups[key] = group

            for key, value in groups.items():
                for user in value['users']:
                    if len(user.split(' ')) == 1:
                        data['local-users'][user].append(key)

            json_file = os.path.join(current_path, 'config_groups.json')
            with open(json_file, 'w') as fh:
                json.dump(list(groups.values()), fh, indent=4, ensure_ascii=False)
            logging.info(f'    Список локальных групп пользователей выгружен в файл "{json_file}".')
        else:
            logging.info('    Нет локальных групп пользователей для экспорта.')


    def convert_local_users(self, local_users):
        """Конвертируем локального пользователя"""
        logging.info('Конвертация локальных пользователей.')
        if local_users:
            current_path = os.path.join(self.current_ug_path, 'UsersAndDevices', 'Users')
            err, msg = self.create_dir(current_path)
            if err:
                logging.error(f'    {msg}.')
                self.error = 1
                return

            users = []
            for user_name, groups in local_users.items():
                users.append({
                    'name': user_name,
                    'enabled': True,
                    'auth_login': self.get_transformed_userlogin(user_name),
                    'is_ldap': False,
                    'static_ip_addresses': [],
                    'ldap_dn': '',
                    'emails': [],
                    'first_name': '',
                    'last_name': '',
                    'phones': [],
                    'groups': groups
                })
            json_file = os.path.join(current_path, 'config_users.json')
            with open(json_file, 'w') as fh:
                json.dump(users, fh, indent=4, ensure_ascii=False)
            logging.info(f'    Список локальных пользователей выгружен в файл "{json_file}".')
        else:
            logging.info('    Нет локальных пользователей для экспорта.')


    def convert_auth_servers(self, data):
        """Конвертируем сервера аутентификации"""
        logging.info('Конвертация серверов аутентификации.')
        if data['auth_servers']:
            current_path = os.path.join(self.current_ug_path, 'UsersAndDevices', 'AuthServers')
            err, msg = self.create_dir(current_path)
            if err:
                logging.error(f'    {msg}.')
                self.error = 1
                return

            ldap_servers = []
            radius_servers = []
            tacacs_servers = []
            for item in data['auth_servers']:
                if item['description'] == 'ldap':
                    dn = ''
                    ldap_srv = {
                        'name': item['name'],
                        'description': 'Перенесено с Cisco ASA',
                        'enabled': True,
                        'ssl': False,
                        'address': item['address'],
                        'bind_dn': '',
                        'password': '',
                        'domains': [],
                        'roots': [],
                        'keytab_exists': False
                    }
                    if 'ldap-over-ssl' in item and item['ldap-over-ssl'] == 'enable':
                        ldap_srv['ssl'] = True
                    if 'ldap-base-dn' in item:
                        dn = ".".join([y[1] for y in [x.split("=") for x in item['ldap-base-dn'].split(",")]]).lower()
                        ldap_srv['domains'].append(dn)
                        ldap_srv['roots'].append(item['ldap-base-dn'])
                    if 'ldap-login-dn' in item:
                        login = item['ldap-login-dn'] if '=' in item['ldap-login-dn'] else f'{item["ldap-login-dn"]}@{dn}'
                        ldap_srv['bind_dn'] = login
                    if 'ldap-login-password' in item:
                        ldap_srv['password'] = item['ldap-login-password']
                    if 'kerberos-realm' in item:
                        ldap_srv['domains'].append(item['kerberos-realm'])
                        ldap_srv['roots'].append(item['kerberos-realm'])
                        ldap_srv['bind_dn'] = f'login@{item["kerberos-realm"]}'
                        ldap_srv['password'] = "secret"
                    ldap_servers.append(ldap_srv)

                if item['description'] == 'radius':
                    address = {'host': item['address'], 'port': int(item.get('authentication-port', 1812))}
                    radius_servers.append({
                        'name': item['name'],
                        'description': 'Перенесено с Cisco ASA',
                        'enabled': True,
                        'secret': item.get('key', ''),
                        'addresses': [address]
                    })

                if item['description'] == 'tacacs':
                    tacacs_servers.append({
                        'name': item['name'],
                        'description': 'Перенесено с Cisco ASA',
                        'enabled': True,
                        'use_single_connection': False,
                        'timeout': int(item.get('timeout', 4)),
                        'address': item['address'],
                        'port': int(item.get('server-port', 49)),
                        'secret': item.get('key', ''),
                    })

            if ldap_servers:
                json_file = os.path.join(current_path, 'config_ldap_servers.json')
                with open(json_file, 'w') as fh:
                    json.dump(ldap_servers, fh, indent=4, ensure_ascii=False)
                logging.info(f'    Сервера аутентификации LDAP выгружены в файл "{json_file}".')

            if radius_servers:
                json_file = os.path.join(current_path, 'config_radius_servers.json')
                with open(json_file, 'w') as fh:
                    json.dump(radius_servers, fh, indent=4, ensure_ascii=False)
                logging.info(f'    Сервера аутентификации RADIUS выгружены в файл "{json_file}".')

            if tacacs_servers:
                json_file = os.path.join(current_path, 'config_tacacs_servers.json')
                with open(json_file, 'w') as fh:
                    json.dump(tacacs_servers, fh, indent=4, ensure_ascii=False)
                logging.info(f'    Сервера аутентификации TACACS выгружены в файл "{json_file}".')
        else:
            logging.info(f'    Нет серверов аутентификации для экспорта.')


    def convert_service_object(self, data):
        """Конвертируем сетевой сервис"""
        logging.info('Конвертация сервисов.')
        error = 0

        for key, value in data['services'].items():
            service_name = ug_services.get(key, key)
            service = {
                'name': service_name,
                'description': 'Перенесено с Cisco ASA.',
                'protocols': []
            }
            port = ''
            source_port = ''
            proto = None

            for item in value:
                proto = None
                match item:
                    case ['service', protocol]:
                        if protocol.isdigit():
                            protocol = ip_proto.get(protocol, None)
                        if protocol and protocol in network_proto:
                            proto = protocol
                        else:
                            logging.error(f'    Error: Сервис {key} не конвертирован. Протокол {protocol} не поддерживается в UG NGFW.')
                            error = 1
                    case ['service', 'tcp' | 'udp', *other]:
                        proto = item[1]
                        match other:
                            case ['source', 'eq', src_port]:
                                source_port = self.get_service_number(src_port)
                                if not source_port:
                                    logging.error(f'    Error: Сервис {key} не конвертирован. Порт "{src_port}" не поддерживается в UG NGFW.')
                                    error = 1
                                    proto = None
                            case ['source', 'range', port1, port2]:
                                source_port = f'{self.get_service_number(port1)}-{self.get_service_number(port2)}'
                            case ['destination', 'eq', dst_port]:
                                port = self.get_service_number(dst_port)
                                if not port:
                                    logging.error(f'    Error: Сервис {key} не конвертирован. Порт "{dst_port}" не поддерживается в UG NGFW.')
                                    error = 1
                                    proto = None
                            case ['destination', 'range', port1, port2]:
                                port = f'{self.get_service_number(port1)}-{self.get_service_number(port2)}'
                            case ['source', 'eq', src_port, 'destination', protocol, *dst_ports]:
                                source_port = self.get_service_number(src_port)
                                if protocol == 'eq':
                                    port = self.get_service_number(dst_ports[0])
                                else:
                                    port = f'{self.get_service_number(dst_ports[0])}-{self.get_service_number(dst_ports[1])}'
                            case ['source', 'range', port1, port2, 'destination', protocol, *dst_ports]:
                                source_port = f'{self.get_service_number(port1)}-{self.get_service_number(port2)}'
                                if protocol == 'eq':
                                    port = self.get_service_number(dst_ports[0])
                                else:
                                    port = f'{self.get_service_number(dst_ports[0])}-{self.get_service_number(dst_ports[1])}'
                                if port is None:
                                    logging.error(f'    Error: Сервис {key} не конвертирован. Порт "{dst_port[0]}" не поддерживается в UG NGFW.')
                                    error = 1
                                    proto = None
                            case _:
                                logging.error(f'    Error: Сервис {key} не конвертирован. Операторы lt, gt, neq не поддерживаются в UG NGFW.')
                                error = 1
                    case ['description', *content]:
                        service['description'] = f"{service['description']}\n{' '.join(content)}"

                if proto:
                    service['protocols'].append({
                        'proto': proto,
                        'port': port,
                        'app_proto': '',
                        'source_port': source_port,
                        'alg': ''
                    })
    
            if service['protocols']:
                self.services[service_name] = service
            else:
                self.services[service_name] = {}

        for item in self.create_ug_services():
            self.services[item['name']] = item
        if error:
            self.error = 1
            logging.info('    Список сервисов конвертирован с ошибками.')
        else:
            logging.info('    Список сервисов конвертирован.')


    def convert_ip_lists(self, ip_lists):
        """Конвертируем object network в списки IP-адресов"""
        logging.info('Конвертация списков IP-адресов.')
        if not ip_lists:
            logging.info('    Нет списков IP-адресов для экспорта.')
            return

        current_path = os.path.join(self.current_ug_path, 'Libraries', 'IPAddresses')
        err, msg = self.create_dir(current_path, delete='no')
        if err:
            logging.error(f'    {msg}.')
            self.error = 1
            return

        for key, value in ip_lists.items():
            self.ip_lists.add(key)
            ip_list = {
                'name': key,
                'description': 'Перенесено с Cisco ASA.',
                'type': 'network',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'threat_level': 3},
                'content': []
            }
            for item in value:
                match item:
                    case ['subnet', ip, mask]:
                        subnet = ipaddress.ip_network(f'{ip}/{mask}')
                        ip_list['content'].append({'value': f'{ip}/{subnet.prefixlen}'})
                    case ['host', ip]:
                        ip_list['content'].append({'value': ip})
                    case ['range', start_ip, end_ip]:
                        ip_list['content'].append({'value': f'{start_ip}-{end_ip}'})
                    case ['description', *content]:
                        ip_list['description'] = f"{ip_list['description']}\n{' '.join(content)}"

            json_file = os.path.join(current_path, f'{ip_list["name"].translate(self.trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            logging.info(f'    Список IP-адресов {ip_list["name"]} выгружен в файл "{json_file}".')

        logging.info(f'    Списки IP-адресов выгружены в каталог "{current_path}".')


    def convert_url_lists(self, url_lists):
        """Конвертируем object network в списки URL"""
        logging.info('Конвертация списков URL.')
        if not url_lists:
            logging.info('    Нет списков URL для экспорта.')
            return

        current_path = os.path.join(self.current_ug_path, 'Libraries', 'URLLists')
        err, msg = self.create_dir(current_path)
        if err:
            logging.error(f'    {msg}.')
            self.error = 1
            return

        for key, value in url_lists.items():
            url_list = {
                'name': key,
                'description': 'Перенесено с Cisco ASA.',
                'type': 'url',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'list_compile_type': 'case_insensitive'},
                'content': []
            }
            for item in value:
                match item:
                    case ['fqdn', domain_name]:
                        url_list['content'].append({'value': domain_name})
                    case ['fqdn', 'v4', domain_name]:
                        url_list['content'].append({'value': domain_name})
                    case ['description', *content]:
                        url_list['description'] = f"{url_list['description']}\n{' '.join(content)}"

            json_file = os.path.join(current_path, f'{url_list["name"].translate(self.trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(url_list, fh, indent=4, ensure_ascii=False)
            logging.info(f'    Список URL {url_list["name"]} выгружен в файл "{json_file}".')

        logging.info(f'    Списки URL выгружены в каталог "{current_path}".')


    def convert_network_object_group(self, data):
        """Конвертируем object-group network в список IP-адресов и список URL если object-group содержит объект с FQDN"""
        logging.info('Конвертация групп IP-адресов и URL.')
        if not data['network-group']:
            logging.info('    Нет групп IP-адресов и URL для экспорта.')
            return

        ip_path = os.path.join(self.current_ug_path, 'Libraries', 'IPAddresses')
        err, msg = self.create_dir(ip_path, delete='no')
        if err:
            logging.error(f'    {msg}.')
            self.error = 1
            return
        url_path = os.path.join(self.current_ug_path, 'Libraries', 'URLLists')
        err, msg = self.create_dir(url_path, delete='no')
        if err:
            logging.error(f'    {msg}.')
            self.error = 1
            return

        error = 0
        ip_groups = {}
        url_groups = {}
        for key, value in data['network-group'].items():
            ip_list = {
                'name': key,
                'description': 'Перенесено с Cisco ASA.',
                'type': 'network',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'threat_level': 3},
                'content': []
            }
            url_list = {
                'name': key,
                'description': 'Перенесено с Cisco ASA.',
                'type': 'url',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'list_compile_type': 'case_insensitive'},
                'content': []
            }
            for item in value:
                match item:
                    case ['network-object', 'host', ip]:
                        if self.check_ip(ip):
                            ip_list['content'].append({'value': ip})
                        else:
                            url_list['content'].append({'value': ip})
                    case ['network-object', 'object', object_name]:
                        if object_name in self.ip_lists:
                            ip_list['content'].append({'list': object_name})
                        else:
                            for item in data['url_lists'][object_name]:
                                match item:
                                    case ['fqdn', domain_name]:
                                        url_list['content'].append({'value': domain_name})
                                    case ['fqdn', 'v4', domain_name]:
                                        url_list['content'].append({'value': domain_name})
                    case ['network-object', ip, mask]:
                        err, result = self.pack_ip_address(ip, mask)
                        if err:
                            logging.error(f'    Error: [object-group "{key}"] {result} Данный объект не добавлен в список "{key}".')
                            error = 1
                        else:
                            ip_list['content'].append({'value': result})
                    case ['group-object', group_name]:
                        if group_name in ip_groups:
                            ip_list['content'].append({'list': group_name})
                        elif group_name in url_groups:
                            url_list['content'].extend(url_groups[group_name])
                        else:
                            logging.error(f'    Error: [object-group "{key}"] Не найдена группа URL/IP-адресов "{group_name}".')
                            error = 1
                    case ['description', *content]:
                        ip_list['description'] = f"{ip_list['description']}\n{' '.join(content)}"
                        url_list['description'] = f"{url_list['description']}\n{' '.join(content)}"

            if ip_list['content']:
                ip_groups[key] = ip_list['content']
                self.ip_lists.add(key)
                data['ip_lists'][key] = []
                json_file = os.path.join(ip_path, f'{ip_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                logging.info(f'    Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')

            if url_list['content']:
                url_groups[key] = url_list['content']
                data['url_lists'][key] = []
                json_file = os.path.join(url_path, f'{url_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(url_list, fh, indent=4, ensure_ascii=False)
                logging.info(f'    Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

        if error:
            self.error = 1
            logging.info('    Списки групп URL/IP-адресов выгружены. Конвертация прошла с ошибками.')
        else:
            logging.info('    Списки групп URL/IP-адресов выгружены.')


    def convert_service_object_group(self, data):
        """Конвертируем object-group service в список сервисов"""
        logging.info('Конвертация групп сервисов.')
        if not data['service-group']:
            logging.info(f'    Нет групп сервисов для экспорта.')
            return

        error = 0
        for key, value in data['service-group'].items():
            descr = key.split('|')
            srv_group = {
                'name': descr[0],
                'description': 'Перенесено с Cisco ASA.',
                'type': 'servicegroup',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {},
                'content': []
            }
            for item in value:
                service = {
                    'name': '',
                    'description': 'Перенесено с Cisco ASA.',
                    'protocols': []
                }
                proto_array = []
                source_port = ''
                port = ''
                match item:
                    case ['service-object', protocol]:
                        if protocol.isdigit():
                            protocol = ip_proto.get(protocol, None)
                        if protocol and protocol in network_proto:
                            match protocol:
                                case 'icmp':
                                    srv_group['content'].append(self.services['Any ICMP'])
                                    continue
                                case 'icmp6':
                                    srv_group['content'].append(self.services['Any IPV6-ICMP'])
                                    continue
                                case 'sctp':
                                    srv_group['content'].append(self.services['Any SCTP'])
                                    continue
                                case 'tcp':
                                    srv_group['content'].append(self.services['Any TCP'])
                                    continue
                                case 'udp':
                                    srv_group['content'].append(self.services['Any UDP'])
                                    continue
                                case _:
                                    proto_array.append(protocol)
                        else:
                            logging.error(f'    Error: [Группа сервисов "{descr[0]}"] Сервис {item} не конвертирован. Нельзя задать протокол {protocol} в UG NGFW.')
                            error = 1
                            continue
                    case ['service-object', 'object', object_name]:
                        object_name = ug_services.get(object_name, object_name)
                        srv_group['content'].append(self.services[object_name])
                        continue
                    case ['service-object', 'icmp', *other]:
                        srv_group['content'].append(self.services['Any ICMP'])
                        continue
                    case ['service-object', 'icmp6', *other]:
                        srv_group['content'].append(self.services['Any IPV6-ICMP'])
                        continue
                    case ['service-object', 'sctp', *other]:
                        srv_group['content'].append(self.services['Any SCTP'])
                        continue
                    case ['service-object', 'tcp'|'udp'|'tcp-udp', *other]:
                        proto_array = item[1].split('-')
                        match other:
                            case ['destination', protocol, dst_port]:
                                new_port = self.get_service_number(dst_port)
                                if not new_port:
                                    logging.error(f'    Error: [Группа сервисов "{descr[0]}"] Сервис {item} не конвертирован. Порт "{dst_port}" не поддерживается в UG NGFW.')
                                    error = 1
                                    continue
                                if protocol == 'eq':
                                    port = new_port
                                elif protocol == 'gt':
                                    port = f'{int(new_port)+1}-65535'
                                elif protocol == 'lt':
                                    port = f'0-{int(new_port)-1}'
                                else:
                                    logging.error(f'    Error: [Группа сервисов "{descr[0]}"] Сервис {item} не конвертирован. Оператор {protocol} не поддерживается в UG NGFW.')
                                    error = 1
                            case ['destination', 'range', port1, port2]:
                                port = f'{self.get_service_number(port1)}-{self.get_service_number(port2)}'
                            case ['source', protocol, src_port]:
                                new_port = self.get_service_number(src_port)
                                if not new_port:
                                    logging.error(f'    Error: [Группа сервисов "{descr[0]}"] Сервис {item} не конвертирован. Порт "{src_port}" не поддерживается в UG NGFW.')
                                    error = 1
                                    continue
                                if protocol == 'eq':
                                    source_port = new_port
                                elif protocol == 'gt':
                                    source_port = f'{int(new_port)+1}-65535'
                                elif protocol == 'lt':
                                    source_port = f'0-{int(new_port)-1}'
                                else:
                                    logging.error(f'    Error: [Группа сервисов "{descr[0]}"] Сервис {item} не конвертирован. Оператор {protocol} не поддерживается в UG NGFW.')
                                    error = 1
                            case ['source', 'range', port1, port2]:
                                source_port = f'{self.get_service_number(port1)}-{self.get_service_number(port2)}'
                            case ['source', src_protocol, src_port, 'destination', dst_protocol, *dst_ports]:
                                if src_protocol == 'eq':
                                    source_port = self.get_service_number(src_port)
                                    if not source_port:
                                        logging.error(f'    Error: [Группа сервисов "{descr[0]}"] Сервис {item} не конвертирован. Порт "{src_port}" не поддерживается в UG NGFW.')
                                        continue
                                elif src_protocol == 'gt':
                                    source_port = f'{int(self.get_service_number(src_port))+1}-65535'
                                elif dst_protocol == 'ge':
                                    source_port = f'{int(self.get_service_number(src_port))}-65535'
                                elif dst_protocol == 'lt':
                                    source_port = f'0-{int(self.get_service_number(src_port))-1}'
                                else:
                                    logging.error(f'    Error: [Группа сервисов "{descr[0]}"] Сервис {item} не конвертирован. Оператор {src_protocol} не поддерживается в UG NGFW.')
                                    error = 1
                                if dst_protocol == 'eq':
                                    port = self.get_service_number(dst_ports[0])
                                    if not port:
                                        logging.error(f'    Error: [Группа сервисов "{descr[0]}"] Сервис {item} не конвертирован. Порт {dst_ports[0]} не поддерживается в UG NGFW.')
                                        error = 1
                                        continue
                                elif dst_protocol == 'gt':
                                    port = f'{int(self.get_service_number(dst_ports[0]))+1}-65535'
                                elif dst_protocol == 'ge':
                                    port = f'{int(self.get_service_number(dst_ports[0]))}-65535'
                                elif dst_protocol == 'lt':
                                    port = f'0-{int(self.get_service_number(dst_ports[0]))-1}'
                                elif dst_protocol == 'range':
                                    port = f'{self.get_service_number(dst_ports[0])}-{self.get_service_number(dst_ports[1])}'
                                else:
                                    logging.error(f'    Error: [Группа сервисов "{descr[0]}"] Сервис {item} не конвертирован. Оператор {dst_protocol} не поддерживается в UG NGFW.')
                                    error = 1
                            case ['source', 'range', port1, port2, 'destination', protocol, *dst_ports]:
                                source_port = f'{self.get_service_number(port1)}-{self.get_service_number(port2)}'
                                if protocol == 'eq':
                                    port = self.get_service_number(dst_ports[0])
                                    if not port:
                                        logging.error(f'    Error: [Группа сервисов "{descr[0]}"] Сервис {item} не конвертирован. Порт {dst_ports[0]} не поддерживается в UG NGFW.')
                                        error = 1
                                        continue
                                elif protocol == 'gt':
                                    port = f'{int(self.get_service_number(dst_ports[0]))+1}-65535'
                                elif protocol == 'ge':
                                    port = f'{int(self.get_service_number(dst_ports[0]))}-65535'
                                elif protocol == 'lt':
                                    port = f'0-{int(self.get_service_number(dst_ports[0]))-1}'
                                elif protocol == 'range':
                                    port = f'{self.get_service_number(dst_ports[0])}-{self.get_service_number(dst_ports[1])}'
                                else:
                                    logging.error(f'    Error: [Группа сервисов "{descr[0]}"] Сервис {item} не конвертирован. Оператор {protocol} не поддерживается в UG NGFW.')
                            case ['source'|'destination', 'neq', *tmp]:
                                logging.error(f'    Error: [Группа сервисов "{descr[0]}"] Сервис {item} не конвертирован. Оператор "neq" не поддерживаются в UG NGFW.')
                                error = 1
                                continue

                    case ['port-object', 'eq'|'range', *dst_ports]:
                        if dst_ports[0].isalpha():
                            service['name'] = dst_ports[0]
                        proto_array = descr[1].split('-')
                        port = self.get_service_number(dst_ports[0]) if item[1] == 'eq' else f'{self.get_service_number(dst_ports[0])}-{self.get_service_number(dst_ports[1])}'

                    case ['group-object', group_name]:
                        srv_group['content'].extend(self.service_groups[group_name]['content'])
                        continue
                    case ['description', *content]:
                        srv_group['description'] = f"{srv_group['description']}\n{' '.join(content)}"
                        continue

                for proto in proto_array:
                    service['protocols'].append({
                        'proto': proto,
                        'port': port,
                        'app_proto': self.app_proto.get(proto, ''),
                        'source_port': source_port,
                        'alg': ''
                    })
                if service['protocols']:
                    tmp_name = []
                    for x in service['protocols']:
                        if x['source_port']:
                            tmp_name.append(f"{x['proto']}(src{x['source_port']}/dst{x['port']})")
                        else:
                            tmp_name.append(f"{x['proto']}{x['port']}")
                    service['name'] = '--'.join(tmp_name)
                    self.services[service['name']] = service
                srv_group['content'].append(service)
            
            self.service_groups[srv_group['name']] = srv_group
        if error:
            self.error = 1
            logging.info(f'    Список групп сервисов конвертирован c ошибками.')
        else:
            logging.info(f'    Список групп сервисов конвертирован.')


    def convert_protocol_object_group(self, data):
        """Конвертируем object-group protocol в группы сервисов"""
        logging.info('Конвертация групп протоколов в группы сервисов.')
        if 'protocol-group' not in data or not data['protocol-group']:
            logging.info('    Нет групп протоколов для экспорта.')
            return

        error = 0
        for key, value in data['protocol-group'].items():
            srv_group = {
                'name': key,
                'description': 'Перенесено с Cisco ASA.',
                'type': 'servicegroup',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {},
                'content': []
            }
            proto = set()
            for item in value:
                match item:
                    case ['protocol-object', protocol]:
                        if protocol.isdigit():
                            protocol = ip_proto.get(protocol, None)
                        if protocol and protocol in network_proto:
                            proto.add(protocol)
                        elif protocol == 'ip':
                            proto.update(['tcp', 'udp'])
                        else:
                            logging.error(f'    Error: [object-group protocol "{key}"] Сервис {item} не конвертирован. Нельзя задать протокол {protocol} в UG NGFW.')
                            error = 1
                    case ['description', *content]:
                        srv_group['description'] = f"{srv_group['description']}\n{' '.join(content)}"

            if proto:
                for protocol in proto:
                    match protocol:
                        case 'icmp':
                            srv_group['content'].append(self.services['Any ICMP'])
                        case 'icmp6':
                            srv_group['content'].append(self.services['Any IPV6-ICMP'])
                        case 'sctp':
                            srv_group['content'].append(self.services['Any SCTP'])
                        case 'tcp':
                            srv_group['content'].append(self.services['Any TCP'])
                        case 'udp':
                            srv_group['content'].append(self.services['Any UDP'])
                        case _:
                            service = {
                                'name': protocol,
                                'description': '',
                                'protocols': [{'proto': protocol, 'port': ''}]
                            }
                            self.services[service['name']] = service
                            srv_group['content'].append(service)
            
            self.service_groups[srv_group['name']] = srv_group
        if error:
            self.error = 1
            logging.info('    Список групп протоколов конвертирован с ошибками.')
        else:
            logging.info('    Список групп протоколов конвертирован.')
    

    def convert_icmp_object_group(self, data):
        """Конвертируем object-group icmp в сервис"""
        logging.info('Конвертация object-group icmp в сервис icmp.')
        if 'icmp-group' not in data or not data['icmp-group']:
            logging.info('    Нет icmp групп для экспорта.')
            return

        for key in data['icmp-group']:
            service = {
                'name': key,
                'description': 'Перенесено с Cisco ASA.',
                'protocols': [
                    {
                        'proto': 'icmp',
                        'port': '',
                        'app_proto': '',
                        'source_port': '',
                        'alg': ''
                    }
                ]
            }
            self.services[service['name']] = service
        logging.info(f'    Объекты "object-group icmp" конвертированы.')


    def save_services(self):
        """Сохраняем список сервисов в файл Libraries/Services/config_services_list.json"""
        current_path = os.path.join(self.current_ug_path, 'Libraries', 'Services')
        json_file = os.path.join(current_path, 'config_services_list.json')
        err, msg = self.create_dir(current_path)
        if err:
            logging.error(f'    {err}\n    Список сервисов не выгружен.')
            self.error = 1
            return

        with open(json_file, 'w') as fh:
            json.dump([x for x in self.services.values() if x], fh, indent=4, ensure_ascii=False)
        logging.info(f'    Список сервисов выгружен в файл "{json_file}".')


    def save_service_groups(self):
        """Сохраняем список групп сервисов в файл Libraries/ServicesGroups/config_services_groups_list.json"""
        if self.service_groups:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'ServicesGroups')
            err, msg = self.create_dir(current_path)
            if err:
                logging.error(f'    {msg}.')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_services_groups_list.json')
            with open(json_file, 'w') as fh:
                json.dump(list(self.service_groups.values()), fh, indent=4, ensure_ascii=False)
            logging.info(f'    Список групп сервисов выгружен в файл "{json_file}".')


    def convert_time_sets(self, data):
        """Конвертируем time set (календари)"""
        logging.info('Конвертация календарей.')
        if not data['time-range']:
            logging.info(f'    Нет календарей для экспорта.')
            return

        current_path = os.path.join(self.current_ug_path, 'Libraries', 'TimeSets')
        err, msg = self.create_dir(current_path)
        if err:
            logging.error(f'    {msg}.')
            self.error = 1
            return

        week = {
            'Monday': 1,
            'Tuesday': 2,
            'Wednesday': 3,
            'Thursday': 4,
            'Friday': 5,
            'Saturday': 6,
            'Sunday': 7
        }
        time_rules = []

        for rule_name, content in data['time-range'].items():
            rule = {
                'name': rule_name,
                'description': 'Перенесено с Cisco ASA',
                'type': 'timerestrictiongroup',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {},
                'content': []
            }
            i = 0
            for item in content:
                i += 1
                time_set = {
                    'name': f'{rule_name} {i}',
                    'type': 'span' if item[0] == 'absolute' else 'weekly'
                }
                match item:
                    case ['absolute', 'start' | 'end', time, day, month, year]:
                        if item[1] == 'start':
                            time_set['time_from'] = time
                            time_set['fixed_date_from'] = f'{year}-{MONTHS[month]}-{day}T00:00:00'
                        elif item[1] == 'end':
                            time_set['time_to'] = time
                            time_set['fixed_date_to'] = f'{year}-{MONTHS[month]}-{day}T00:00:00'
                    case ['absolute', 'start', start_time, start_day, start_month, start_year, 'end', end_time, end_day, end_month, end_year]:
                        time_set['time_from'] = start_time
                        time_set['fixed_date_from'] = f'{start_year}-{MONTHS[start_month]}-{start_day}T00:00:00'
                        time_set['time_to'] = end_time
                        time_set['fixed_date_to'] = f'{end_year}-{MONTHS[end_month]}-{end_day}T00:00:00'
                    case ['absolute', 'end', end_time, end_day, end_month, end_year, 'start', start_time, start_day, start_month, start_year]:
                        time_set['time_from'] = start_time
                        time_set['fixed_date_from'] = f'{start_year}-{MONTHS[start_month]}-{start_day}T00:00:00'
                        time_set['time_to'] = end_time
                        time_set['fixed_date_to'] = f'{end_year}-{MONTHS[end_month]}-{end_day}T00:00:00'
                    case ['periodic', *other]:
                        if other[0] in ('weekend', 'weekdays', 'daily'):
                            time_set['time_from'] = other[1] if other[1] != 'to' else '00:00'
                            time_set['time_to'] = other[len(other)-1]
                            if other[0] == 'daily':
                                time_set['type'] = 'daily'
                            else:
                                time_set['days'] = [6, 7] if other[0] == 'weekend' else [1, 2, 3, 4, 5]
                        else:
                            start, end = other[:other.index('to')], other[other.index('to')+1:]
                            days = set()
                            for x in start:
                                if week.get(x, None):
                                    days.add(week[x])
                                else:
                                    time_set['time_from'] = x
                            for x in end:
                                if week.get(x, None):
                                    days = {y for y in range(min(days), week[x]+1)}
                                else:
                                    time_set['time_to'] = x
                            if not time_set.get('time_from', None):
                                time_set['time_from'] = "00:00"
                            if not time_set.get('time_to', None):
                                time_set['time_to'] = "23:59"
                            if days:
                                time_set['days'] = sorted(list(days))
                            else:
                                time_set['type'] = 'daily'
                rule['content'].append(time_set)
            time_rules.append(rule)

        if time_rules:
            json_file = os.path.join(current_path, 'config_calendars.json')
            with open(json_file, 'w') as fh:
                json.dump(time_rules, fh, indent=4, ensure_ascii=False)
            logging.info(f'    Список календарей выгружен в файл "{json_file}".')
        else:
            logging.info(f'    Нет календарей для экспорта.')


    def convert_firewall_rules(self, data):
        """
        Конвертируем access-lists в правила МЭ.
        Не активные ACE пропускаются. ACE не назначенные интерфейсам пропускаются.
        ACE с именами ASA интерфейсов пропускаются.
        ACE c security-group и object-group-security пропускаются.
        """
        logging.info('Конвертация правил межсетевого экрана.')
        if not data['fw_access-list']:
            logging.info(f'    Нет правил межсетевого экрана для экспорта.')
            return

        current_path = os.path.join(self.current_ug_path, 'NetworkPolicies', 'Firewall')
        err, msg = self.create_dir(current_path)
        if err:
            logging.error(f'    {msg}.')
            self.error = 1
            return

        error = 0
        fw_rules = []
        not_valid = {'inactive', 'interface', 'security-group', 'object-group-security'}

        for key, value in data['fw_access-list'].items():
            intersection = not_valid.intersection(value['content'])
            if intersection:
                logging.error(f'b    Warning: ACE "{" ".join(value["content"])}" пропущено так как содержит параметр {intersection}.')
                continue

            deq = deque(value['content'])
            error, rule_name = self.get_transformed_name(f'{key} ({value["name"]})', err=error, descr='Имя правила МЭ')
            rule = {
                'name': rule_name,
                'description': f"\n{value.get('description', '')}",
                'action': 'drop' if deq.popleft() == 'deny' else 'accept',
                'position': 'last',
                'scenario_rule_id': False,     # При импорте заменяется на UID или "0". 
                'src_ips': [],
                'dst_ips': [],
                'services': [],
                'apps': [],
                'users': [],
                'enabled': True,
                'limit': True,
                'limit_value': '3/h',
                'limit_burst': 5,
                'log': False,
                'log_session_start': True,
                'src_zones_negate': False,
                'dst_zones_negate': False,
                'src_ips_negate': False,
                'dst_ips_negate': False,
                'services_negate': False,
                'apps_negate': False,
                'fragmented': 'ignore',
                'time_restrictions': [],
                'send_host_icmp': '',
            }

            rule_service = {'src_ips': '', 'dst_ips': '', 'protocol': ''}
            protocol = deq.popleft()
            match protocol:
                case 'object':
                    protocol = deq.popleft()
                    rule['services'].append(['service', ug_services.get(protocol, protocol)])
                case 'object-group':
                    object_group = deq.popleft()
                    rule_service['protocol'] = object_group
                    rule['services'].append(['list_id', object_group])
                case 'ip':
                    pass
                case 'icmp'|'tcp'|'udp'|'sctp'|'ipv6-icmp'|'gre':
                    rule_service['protocol'] = protocol if protocol in ('tcp', 'udp', 'sctp') else ''
                    rule['services'].append(['service', f'Any {protocol.upper()}'])
                case 'ipinip':
                    rule['services'].append(['service', 'Any IPIP'])

            argument = deq.popleft()
            match argument:
                case 'object-group-user':
                    rule['users'].append(['group', deq.popleft()])
                case 'user':
                    user = deq.popleft()
                    match user:
                        case 'any':
                            rule['users'].append(['special', 'known_user'])
                        case 'none':
                            rule['users'].append(['special', 'unknown_user'])
                        case _:
                            user_list = user.split("\\")
                            if user_list[0] == 'LOCAL' and user_list[1] in data['local-users']:
                                rule['users'].append(['user', user_list[1]])
                            elif user_list[0] in data['identity_domains']:
                                rule['users'].append(['user', f'{data["identity_domains"][user_list[0]]}\\{user_list[1]}'])
                case 'user-group':
                    group = deq.popleft()
                    group_list = group.split("\\\\")
                    if group_list[0] in data['identity_domains']:
                        rule['users'].append(['group', f'{data["identity_domains"][group_list[0]]}\\{group_list[1]}'])
                case _:
                    ips_mode = 'src_ips'
                    self.get_ips(data, ips_mode, argument, rule, deq)

            while deq:
                argument = deq.popleft()
                match argument:
                    case 'neq':
                        port = deq.popleft()
                        logging.error(f'    Error: [Правило МЭ "{rule["name"]}"] Сервис "neq {port}" не добавлен в правило так как оператор "neq" не поддерживается.')
                        error = 1
                        rule['enabled'] = False
                        rule['description'] = f'{rule["description"]}\nError: Сервис "neq {port}" не добавлен так как оператор "neq" не поддерживается.'
                        rule_service['protocol'] = ''

                    case 'eq'|'range'|'lt'|'gt':
                        tmp = deq.popleft()
                        port = self.get_service_number(tmp)
                        if not port:
                            logging.error(f'    Error: [Правило МЭ "{rule["name"]}"] Сервис "{argument} {tmp}" не добавлен в правило так как порт "{tmp}" не поддерживается.')
                            error = 1
                            rule['enabled'] = False
                            rule['description'] = f'{rule["description"]}\nError: Сервис "{argument} {tmp}" не добавлен так как порт "{tmp}" не поддерживается.'
                            rule_service['protocol'] = ''
                        elif argument == 'eq':
                            rule_service[ips_mode] = port
                        elif argument == 'range':
                            port2 = deq.popleft()
                            rule_service[ips_mode] = f'{port}-{port2}'
                        elif argument == 'lt':
                            rule_service[ips_mode] = f'0-{int(port)-1}'
                        elif argument == 'gt':
                            rule_service[ips_mode] = f'{int(port)+1}-65535'

                    case 'object-group':
                        grp_name = deq.popleft()
                        if grp_name in self.service_groups:
                            rule['services'].clear()
                            rule['services'].append(['list_id', grp_name])
                        else:
                            deq.appendleft(grp_name)
                            ips_mode = 'dst_ips'
                            self.get_ips(data, ips_mode, argument, rule, deq)
                    case 'log':
                        rule['log'] = True
                        other = list(deq)
                        deq.clear()
                        if 'time-range' in other:
                            time_object = other.index('time-range') + 1
                            rule['time_restrictions'].append(time_object)
                    case 'time-range':
                        rule['time_restrictions'].append(deq.popleft())
                    case 'rule-id':
                        rule['description'] = f'rule-id: {deq.popleft()}\n{rule["description"]}'
                    case _:
                        ips_mode = 'dst_ips'
                        self.get_ips(data, ips_mode, argument, rule, deq)

            if rule_service['protocol'] and (rule_service['src_ips'] or rule_service['dst_ips']):
                service_name = self.create_rule_service(rule_service)
                if service_name:
                    rule['services'].clear()
                    rule['services'].append(["service", service_name])

            fw_rules.append(rule)
            logging.info(f'    Создано правило межсетевого экрана "{rule["name"]}".')

        json_file = os.path.join(current_path, 'config_firewall_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(fw_rules, fh, indent=4, ensure_ascii=False)
        if error:
            self.error = 1
            logging.info(f'    Обнаружены ошибки при конвертации правил МЭ. Список правил межсетевого экрана выгружен в файл "{json_file}".')
        else:
            logging.info(f'    Список правил межсетевого экрана выгружен в файл "{json_file}".')


############################################# Служебные функции ###################################################
    def create_rule_service(self, rule_service, mode='fw'):
        """Для ACE. Создаём сервис, заданный непосредственно в правиле, а не в сервисной группе."""

        service = {
            'name': '',
            'description': '',
            'protocols': []
        }
        if rule_service['protocol'] in self.service_groups:
            services = copy.deepcopy(self.service_groups[rule_service['protocol']]['content'])
            content = [x for service in services for x in service['protocols']]
            rule_service['protocol'] = ''
            for item in content:
                item['source_port'] = rule_service['src_ips']
                item['port'] = rule_service['dst_ips']
                rule_service['protocol'] = f'{rule_service["protocol"]}-{item["proto"]}' if rule_service['protocol'] else f'{item["proto"]}'
            service['protocols'] = content
        else:
            service['protocols'].append({
                'proto': rule_service['protocol'],
                'port': rule_service['dst_ips'],
                'app_proto': '',
                'source_port': rule_service['src_ips'],
                'alg': ''
            })
        if rule_service['src_ips']:
            if rule_service['dst_ips']:
                service['name'] = f'{rule_service["protocol"]}(src{rule_service["src_ips"]}/dst{rule_service["dst_ips"]})'
            else:
                service['name'] = f'{rule_service["protocol"]}(src{rule_service["src_ips"]})'
        else:
            if rule_service['protocol'] == 'tcp' and rule_service['dst_ips'] in ug_services:
                service['name'] = ug_services[rule_service['dst_ips']]
            else:
                service['name'] = f'{rule_service["protocol"]}{rule_service["dst_ips"]}'

        if service['name'] not in self.services:
            self.services[service['name']] = service
            logging.info(f'    Создан сервис "{service["name"]}".')
        return service['name']


    def get_ips(self, data, ips_mode, address, rule, deq):
        """Для convert_firewall_rules()"""
        match address:
            case 'any'|'any4'|'any6':
                pass
            case 'object'|'object-group':
                ip_or_service_list = deq.popleft()
                if ip_or_service_list in data['ip_lists']:
                    rule[ips_mode].append(["list_id", ip_or_service_list])
                elif ip_or_service_list in data['url_lists']:
                    rule[ips_mode].append(["urllist_id", ip_or_service_list])
                elif ip_or_service_list in data['network-group']:
                    rule[ips_mode].append(["list_id", ip_or_service_list])
                elif ip_or_service_list in data['services']:
                    rule['services'].clear()
                    rule['services'].append(["service", ip_or_service_list])
            case 'host':
                ip = deq.popleft()
                h = hashlib.md5(ip.encode('utf-8')).hexdigest()[:8]
                grp = f'addr_{h}'
                self.create_ip_list(ips=[ip], name=grp, descr='')
                data['ip_lists'][grp] = []
                rule[ips_mode].append(['list_id', grp])
            case 'interface':
                ip = deq.popleft()
            case _:
                if self.check_ip(address):
                    mask = deq.popleft()
                    err, ip = self.pack_ip_address(address, mask)
                    if not err:
                        h = hashlib.md5(ip.encode('utf-8')).hexdigest()[:8]
                        grp = f'addr_{h}'
                        self.create_ip_list(ips=[ip], name=grp, descr='')
                        data['ip_lists'][grp] = []
                        rule[ips_mode].append(['list_id', grp])
                else:
                    logging.error(f'    Error: [Правило МЭ "{rule["name"]}"] Не корректный IP-адрес "{address}"')



    @staticmethod
    def get_service_number(service):
        """Получить цифровое значение сервиса из его имени"""
        if service.isdigit():
            return service
        elif (service_number := service_ports.get(service, False)):
            return service_number
        else:
            return False


#-----------------------------------------------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Export Cisco ASA config into UserGate JSON"
    )
    parser.add_argument('-i','--asa-config', required=True, help="ASA config file")
    parser.add_argument('-o','--export-dir',  required=True, help="Output directory")
    args = parser.parse_args()
    os.makedirs(args.export_dir, exist_ok=True)
    converter = ConvertCiscoASAConfig(
    current_asa_path=os.path.dirname(args.asa_config),
    current_ug_path=args.export_dir)
    converter.run()


if __name__ == '__main__':
    main()
