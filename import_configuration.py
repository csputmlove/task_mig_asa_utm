import os, sys, copy, json
import logging
import argparse
from core import ReadWriteBinFile, MyMixedService
from services_lib import zone_services
from utils import read_json_file
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')


class ImportSelectedPoints(ReadWriteBinFile, MyMixedService):
    """Импортируем разделы конфигурации на NGFW"""

    def __init__(self, utm, config_path, arguments, all_points=None, selected_path=None, selected_points=None):
        super().__init__()
        self.utm = utm
        self.config_path = config_path
        self.all_points = all_points
        self.selected_path = selected_path
        self.selected_points = selected_points
        self.error = 0
        self.import_funcs = {
            'Services': self.import_services_list,
            'ServicesGroups': self.import_services_groups,
            'IPDSSignatures': self.import_custom_idps_signature,
            'IDPSProfiles': self.import_idps_profiles,
            'LLDPProfiles': self.import_lldp_profiles,
            'Gateways': self.import_gateways,
            'AuthServers': self.import_auth_servers,
            'AuthProfiles': self.import_auth_profiles,
            'Groups': self.import_local_groups,
            'Users': self.import_local_users,
            'TerminalServers': self.import_terminal_servers,
            'Certificates': self.pass_function,
            'GeneralSettings': self.import_general_settings,
            'Administrators': self.pass_function,
            'DNS': self.import_dns_config,
            'Routes': self.pass_function,
            'OSPF': self.pass_function,
            'BGP': self.pass_function,
            'Firewall': self.import_firewall_rules,
            'SSLInspection': self.import_ssldecrypt_rules,
            'SSHInspection': self.import_sshdecrypt_rules,
            'IntrusionPrevention': self.import_idps_rules,
            'SNMP': self.import_snmp_rules,
            'SNMPParameters': self.import_snmp_settings,
        }


    def run(self):
        """Импортируем разделы конфигурации"""
        # Читаем бинарный файл библиотечных данных
        err, self.ngfw_data = self.read_bin_file()
        if err:
            logging.error('iИмпорт конфигурации на UserGate NGFW прерван! Не удалось прочитать служебные данные.')
            return

        if self.all_points:
            """Импортируем всё в пакетном режиме"""
            path_dict = {}
            for item in self.all_points:
                top_level_path = os.path.join(self.config_path, item['path'])
                for point in item['points']:
                    path_dict[point] = os.path.join(top_level_path, point)
            for key, value in self.import_funcs.items():
                if key in path_dict:
                    value(path_dict[key])
        else:
            """Импортируем определённые разделы конфигурации"""
            for point in self.selected_points:
                current_path = os.path.join(self.selected_path, point)
                if point in self.import_funcs:
                    self.import_funcs[point](current_path)
                else:
                    self.error = 1
                    logging.error(f'Не найдена функция для импорта {point}!')

        # Сохраняем бинарный файл библиотечных данных после изменений в процессе работы
        if self.write_bin_file(self.ngfw_data):
            logging.error('iИмпорт конфигурации на UserGate NGFW прерван! Не удалось записать служебные данные.')
            return

        if self.error:
            logging.info('iИмпорт конфигурации прошёл с ошибками!\n')
        else:
            logging.info('iИмпорт конфигурации завершён.\n')


    #------------------------------------------ UserGate -------------------------------------------------------

    def import_general_settings(self, path):
        """Импортируем раздел 'UserGate/Настройки'"""
        self.import_ntp_settings(path)


    def import_ntp_settings(self, path):
        """Импортируем настройки NTP"""
        json_file = os.path.join(path, 'config_ntp.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт настроек NTP раздела "UserGate/Настройки/Настройка времени сервера".')

        data.pop('utc_time', None)
        data.pop('ntp_synced', None)
        err, result = self.utm.add_ntp_config(data)
        if err:
            logging.error(f'    {result}\n    Ошибка импорта настроек NTP.')
            self.error = 1
        else:
            logging.info('    Импорт настроек NTP завершён.')



    #----------------------------------------------- Сеть -----------------------------------------------

    def import_gateways(self, path):
        self.import_gateways_list(path)
        self.import_gateway_failover(path)


    def import_gateways_list(self, path):
        """Импортируем список шлюзов"""
        json_file = os.path.join(path, 'config_gateways.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт шлюзов в раздел "Сеть/Шлюзы".')
        logging.info('L    После импорта шлюзы будут в не активном состоянии. Необходимо проверить и включить нужные.')
        error = 0

        err, result = self.utm.get_gateways_list()
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при импорте шлюзов.')
            self.error = 1
            return
        gateways_list = {x.get('name', x['ipv4']): x['id'] for x in result}
        gateways_read_only = {x.get('name', x['ipv4']): x.get('is_automatic', False) for x in result}

        if self.utm.float_version >= 6:
            err, result = self.utm.get_routes_list()
            if err:
                logging.error(f'    {result}\n    Произошла ошибка при импорте шлюзов.')
                self.error = 1
                return
            vrf_list = [x['name'] for x in result]

        for item in data:
            if self.utm.float_version >= 6:
                if item['vrf'] not in vrf_list:
                    err, result = self.add_empty_vrf(item['vrf'])
                    if err:
                        message = f'Error: Для шлюза "{item["name"]}" не удалось добавить VRF "{item["vrf"]}". Установлен VRF по умолчанию.'
                        logging.error(f'    {result}\n    {message}')
                        item['vrf'] = 'default'
                        item['default'] = False
                    else:
                        logging.info(f'    Для шлюза "{item["name"]}" создан VRF "{item["vrf"]}".')
                        self.sleep(3)   # Задержка, т.к. vrf долго применяет конфигурацию.
            else:
                item['iface'] = 'undefined'
                item.pop('is_automatic', None)
                item.pop('vrf', None)
            item.pop('node_name', None)         # удаляем если конфиг получен из МС
            
            if item['name'] in gateways_list:
                if not gateways_read_only[item['name']]:
                    err, result = self.utm.update_gateway(gateways_list[item['name']], item)
                    if err:
                        logging.error(f'    {result} [Шлюз "{item["name"]}"]')
                        error = 1
                    else:
                        logging.info(f'BLACK|    Шлюз "{item["name"]}" уже существует - Updated!')
                else:
                    logging.info(f'    Шлюз "{item["name"]}" - объект только для чтения. Not updated!')
            else:
                item['enabled'] = False
                err, result = self.utm.add_gateway(item)
                if err:
                    logging.error(f'    {result} [Шлюз "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    gateways_list[item['name']] = result
                    logging.info(f'BLACK|    Шлюз "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте шлюзов.')
        else:
            logging.info('    Импорт шлюзов завершён.')


    def import_gateway_failover(self, path):
        """Импортируем настройки проверки сети"""
        json_file = os.path.join(path, 'config_gateway_failover.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт настроек проверки сети раздела "Сеть/Шлюзы/Проверка сети".')

        err, result = self.utm.set_gateway_failover(data)
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при обновлении настроек проверки сети.')
            self.error = 1
        else:
            logging.info('    Настройки проверки сети обновлены.')


    def import_dns_config(self, path):
        """Импортируем настройки DNS"""
        self.import_dns_servers(path)
        self.import_dns_proxy(path)
        self.import_dns_rules(path)
        self.import_dns_static(path)


    def import_dns_servers(self, path):
        """Импортируем список системных DNS серверов"""
        json_file = os.path.join(path, 'config_dns_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт системных DNS серверов раздела "Сеть/DNS/Системные DNS-серверы".')
        error = 0
        for item in data:
            item.pop('id', None)
            item.pop('is_bad', None)
            err, result = self.utm.add_dns_server(item)
            if err == 1:
                logging.error(f'    {result} [DNS сервер "{item["dns"]}" не импортирован]')
                error = 1
            elif err == 2:
                logging.info(f'GRAY|    {result}')
            else:
                logging.info(f'BLACK|    DNS сервер "{item["dns"]}" импортирован.')

        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте системных DNS-серверов!')
        else:
            logging.info('    Импорт системных DNS-серверов завершён.')


    def import_dns_proxy(self, path):
        """Импортируем настройки DNS прокси"""
        json_file = os.path.join(path, 'config_dns_proxy.json')
        err, result = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт настроек DNS-прокси раздела "Сеть/DNS/Настройки DNS-прокси".')
        error = 0
        if self.utm.float_version < 6.0:
            result.pop('dns_receive_timeout', None)
            result.pop('dns_max_attempts', None)
        for key, value in result.items():
            err, result = self.utm.set_settings_param(key, value)
            if err:
                logging.error(f'    {result}')
                error = 1
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте настроек DNS-прокси!')
        else:
            logging.info('    Импорт настроек DNS-прокси завершён.')


    def import_dns_rules(self, path):
        """Импортируем список правил DNS прокси"""
        json_file = os.path.join(path, 'config_dns_rules.json')
        err, rules = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт правил DNS-прокси раздела "Сеть/DNS/Правила DNS".')
        error = 0
        dns_rules = [x['name'] for x in self.utm._server.v1.dns.rules.list(self.utm._auth_token, 0, 1000, {})['items']]

        for item in rules:
            item.pop('position_layer', None)    # Удаляем если экспорт был из шаблона МС.
            if self.utm.float_version >= 6.0:
                item['position'] = 'last'

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if item['name'] in dns_rules:
                logging.info(f'GRAY|    Правило DNS прокси "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_dns_rule(item)
                if err == 1:
                    logging.error(f'    {result} [Правило DNS прокси "{item["name"]}" не импортировано]')
                    error = 1
                elif err == 2:
                    logging.info(f'GRAY|    {result}')
                else:
                    logging.info(f'BLACK|    Правило DNS прокси "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте правил DNS-прокси!')
        else:
            logging.info('    Импорт правил DNS-прокси завершён.')


    def import_dns_static(self, path):
        """Импортируем статические записи DNS прокси"""
        json_file = os.path.join(path, 'config_dns_static.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт статических записей DNS-прокси раздела "Сеть/DNS/Статические записи".')
        error = 0

        for item in data:
            err, result = self.utm.add_dns_static_record(item)
            if err == 1:
                logging.error(f'    {result} [Статическая запись DNS "{item["name"]}" не импортирована]')
                error = 1
            elif err == 2:
                logging.info(f'GRAY|    {result}')
            else:
                logging.info(f'BLACK|    Статическая запись DNS "{item["name"]}" импортирована.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте статических записей DNS-прокси!')
        else:
            logging.info('    Импорт статических записей DNS-прокси завершён.')


    #-------------------------------------- Пользователи и устройства ---------------------------------------------
    def import_local_groups(self, path):
        """Импортируем список локальных групп пользователей"""
        json_file = os.path.join(path, 'config_groups.json')
        err, groups = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт локальных групп пользователей в раздел "Пользователи и устройства/Группы".')
        error = 0

        for item in groups:
            users = item.pop('users')
            # В версии 5 API добавления группы не проверяет что группа уже существует.
            if item['name'] in self.ngfw_data['local_groups']:
                logging.info(f'GRAY|    Группа "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_group(item)
                if err == 1:
                    logging.error(f'    {result} [Локальная группа "{item["name"]}" не импортирована]')
                    error = 1
                    continue
                elif err == 2:
                    logging.info(f'GRAY|    {result}.') # В версиях 6 и выше проверяется что группа уже существует.
                else:
                    self.ngfw_data['local_groups'][item['name']] = result
                    logging.info(f'BLACK|    Локальная группа "{item["name"]}" импортирована.')

            # В версии 5 в группах нет доменных пользователей.
            if self.utm.float_version <= 6:
                continue
            # Добавляем доменных пользователей в группу.
            for user_name in users:
                user_array = user_name.split(' ')
                if len(user_array) > 1 and ('\\' in user_array[1]):
                    domain, name = user_array[1][1:len(user_array[1])-1].split('\\')
                    err1, result1 = self.utm.get_ldap_user_guid(domain, name)
                    if err1:
                        logging.error(f'       {result1} [Не удалось получить GUID пользователя {user_name} из домена {domain}]')
                        error = 1
                        break
                    elif not result1:
                        message = (
                            f'    Нет LDAP-коннектора для домена "{domain}". Доменные пользователи не импортированы в группу "{item["name"]}".\n'
                            f'    Импортируйте и настройте LDAP-коннектор. Затем повторите импорт групп.'
                        )
                        logging.ierrorf'b{message}')
                        break
                    err2, result2 = self.utm.add_user_in_group(self.ngfw_data['local_groups'][item['name']], result1)
                    if err2:
                        logging.error(f'       {result2}  [Пользователь "{user_name}" не добавлен в группу "{item["name"]}"]')
                        error = 1
                    else:
                        logging.info(f'BLACK|       Пользователь "{user_name}" добавлен в группу "{item["name"]}".')
        if error:
            self.error = 1
            logging.info('    Ошибка импорта локальных групп пользователей!')
        else:
            logging.info('    Импорт локальных групп пользователей завершён.')


    def import_local_users(self, path):
        """Импортируем список локальных пользователей"""
        json_file = os.path.join(path, 'config_users.json')
        err, users = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт локальных пользователей в раздел "Пользователи и устройства/Пользователи".')
        error = 0

        for item in users:
            user_groups = item.pop('groups', None)
            # В версии 5 API добавления пользователя не проверяет что он уже существует.
            if item['name'] in self.ngfw_data['local_users']:
                logging.info(f'GRAY|    Пользователь "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_user(item)
                if err == 1:
                    logging.error(f'    {result} [Пользователь "{item["name"]}" не импортирован]')
                    error = 1
                    break
                elif err == 2:
                    logging.info(f'GRAY|    {result}.') # В версиях 6 и выше проверяется что пользователь уже существует.
                else:
                    self.ngfw_data['local_users'][item['name']] = result
                    logging.info(f'BLACK|    Добавлен локальный пользователь "{item["name"]}".')

            # Добавляем пользователя в группу.
            for group in user_groups:
                try:
                    group_guid = self.ngfw_data['local_groups'][group]
                except KeyError as err:
                    logging.ierrorf'b       Не найдена группа {err} для пользователя {item["name"]}. Импортируйте список групп и повторите импорт пользователей.')
                else:
                    err2, result2 = self.utm.add_user_in_group(group_guid, self.ngfw_data['local_users'][item['name']])
                    if err2:
                        logging.error(f'       {result2}  [User "{item["name"]}" не добавлен в группу "{group}"]')
                        error = 1
                    else:
                        logging.info(f'BLACK|       Пользователь "{item["name"]}" добавлен в группу "{group}".')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте локальных пользователей!')
        else:
            logging.info('    Импорт локальных пользователей завершён.')


    def import_auth_servers(self, path):
        """Импортируем список серверов аутентификации"""
        self.import_ldap_servers(path)
        self.import_ntlm_server(path)
        self.import_radius_server(path)
        self.import_tacacs_server(path)
        self.import_saml_server(path)
    

    def import_ldap_servers(self, path):
        """Импортируем список серверов LDAP"""
        json_file = os.path.join(path, 'config_ldap_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт серверов LDAP в раздел "Пользователи и устройства/Серверы аутентификации".')
        logging.info('L    После импорта необходимо включить LDAP-коннекторы, ввести пароль и импортировать keytab файл.')
        error = 0

        err, result = self.utm.get_ldap_servers()
        if err == 1:
            logging.error(f'    {result}')
            error = 1
        else:
            for x in result:
                error, x['name'] = self.get_transformed_name(x['name'], err=error, descr='Имя сервера')
            ldap_servers = {x['name']: x['id'] for x in result}

            for item in data:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
                if item['name'] in ldap_servers:
                    logging.info(f'GRAY|    LDAP-сервер "{item["name"]}" уже существует.')
                else:
                    item['enabled'] = False
                    item['keytab_exists'] = False
                    item.pop("cc", None)
                    if self.utm.float_version < 8.0:
                        item.pop("cache_ttl", None)
                    err, result = self.utm.add_auth_server('ldap', item)
                    if err:
                        logging.error(f'    {result} [Сервер аутентификации LDAP "{item["name"]}" не импортирован]')
                        error = 1
                    else:
                        ldap_servers[item['name']] = result
                        logging.info(f'BLACK|    Сервер аутентификации LDAP "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте серверов LDAP.')
        else:
            logging.info('    Импорт серверов LDAP завершён.')


    def import_ntlm_server(self, path):
        """Импортируем список серверов NTLM"""
        json_file = os.path.join(path, 'config_ntlm_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт серверов NTLM в раздел "Пользователи и устройства/Серверы аутентификации".')
        error = 0

        err, result = self.utm.get_ntlm_servers()
        if err == 1:
            logging.error(f'    {result}')
            error = 1
        else:
            for x in result:
                error, x['name'] = self.get_transformed_name(x['name'], err=error, descr='Имя сервера')
            ntlm_servers = {x['name']: x['id'] for x in result}

            for item in data:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
                if item['name'] in ntlm_servers:
                    logging.info(f'GRAY|    NTLM-сервер "{item["name"]}" уже существует.')
                else:
                    item['enabled'] = False
                    item.pop("cc", None)
                    err, result = self.utm.add_auth_server('ntlm', item)
                    if err:
                        logging.error(f'    {result} [Сервер аутентификации NTLM "{item["name"]}" не импортирован]')
                        error = 1
                    else:
                        ntlm_servers[item['name']] = result
                        logging.info(f'BLACK|    Сервер аутентификации NTLM "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте серверов NTLM!')
        else:
            logging.info('    Импорт серверов NTLM завершён.')


    def import_radius_server(self, path):
        """Импортируем список серверов RADIUS"""
        json_file = os.path.join(path, 'config_radius_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт серверов RADIUS в раздел "Пользователи и устройства/Серверы аутентификации".')
        logging.info(f'L    После импорта необходимо включить каждый сервер RADIUS и ввести пароль.')
        error = 0

        err, result = self.utm.get_radius_servers()
        if err == 1:
            logging.error(f'    {result}')
            error = 1
        else:
            for x in result:
                error, x['name'] = self.get_transformed_name(x['name'], err=error, descr='Имя сервера')
            radius_servers = {x['name']: x['id'] for x in result}

            for item in data:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
                if item['name'] in radius_servers:
                    logging.info(f'GRAY|    RADIUS-сервер "{item["name"]}" уже существует.')
                else:
                    item['enabled'] = False
                    item.pop("cc", None)
                    err, result = self.utm.add_auth_server('radius', item)
                    if err:
                        logging.error(f'    {result} [Сервер аутентификации RADIUS "{item["name"]}" не импортирован]')
                        error = 1
                    else:
                        radius_servers[item['name']] = result
                        logging.info(f'BLACK|    Сервер аутентификации RADIUS "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте серверов RADIUS!')
        else:
            logging.info('    Импорт серверов RADIUS завершён.')


    def import_tacacs_server(self, path):
        """Импортируем список серверов TACACS+"""
        json_file = os.path.join(path, 'config_tacacs_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт серверов TACACS+ в раздел "Пользователи и устройства/Серверы аутентификации".')
        logging.info(f'L    После импорта необходимо включить каждый сервер TACACS и ввести секретный ключ.')
        error = 0

        err, result = self.utm.get_tacacs_servers()
        if err == 1:
            logging.error(f'    {result}')
            error = 1
        else:
            for x in result:
                error, x['name'] = self.get_transformed_name(x['name'], err=error, descr='Имя сервера')
            tacacs_servers = {x['name']: x['id'] for x in result}

            for item in data:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
                if item['name'] in tacacs_servers:
                    logging.info(f'GRAY|    TACACS-сервер "{item["name"]}" уже существует.')
                else:
                    item['enabled'] = False
                    item.pop("cc", None)
                    err, result = self.utm.add_auth_server('tacacs', item)
                    if err:
                        logging.error(f'    {result} [Сервер аутентификации TACACS+ "{item["name"]}" не импортирован]')
                        error = 1
                    else:
                        tacacs_servers[item['name']] = result
                        logging.info(f'BLACK|    Сервер аутентификации TACACS+ "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте серверов TACACS+!')
        else:
            logging.info('    Импорт серверов TACACS+ завершён.')


    def import_saml_server(self, path):
        """Импортируем список серверов SAML"""
        json_file = os.path.join(path, 'config_saml_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт серверов SAML в раздел "Пользователи и устройства/Серверы аутентификации".')
        logging.info(f'L    После импорта необходимо включить каждый сервер SAML и загрузить SAML metadata.')
        error = 0

        err, result = self.utm.get_saml_servers()
        if err:
            logging.error(f'    {result}')
            error = 1
        else:
            for x in result:
                error, x['name'] = self.get_transformed_name(x['name'], err=error, descr='Имя сервера')
            saml_servers = {x['name']: x['id'] for x in result}

            for item in data:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
                if item['name'] in saml_servers:
                    logging.info(f'GRAY|    SAML-сервер "{item["name"]}" уже существует.')
                else:
                    item['enabled'] = False
                    item.pop("cc", None)
                    try:
                        item['certificate_id'] = self.ngfw_data['certs'][item['certificate_id']]
                    except KeyError:
                        logging.error(f'    Error: Для "{item["name"]}" не найден сертификат "{item["certificate_id"]}".')
                        error = 1
                        item['certificate_id'] = 0

                    err, result = self.utm.add_auth_server('saml', item)
                    if err:
                        logging.error(f'    {result} [Сервер аутентификации SAML "{item["name"]}" не импортирован]')
                        error = 1
                    else:
                        saml_servers[item['name']] = result
                        logging.info(f'BLACK|    Сервер аутентификации SAML "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте серверов SAML!')
        else:
            logging.info('    Импорт серверов SAML завершён.')


    def import_2fa_profiles(self, path):
        """Импортируем список 2FA профилей"""
        json_file = os.path.join(path, 'config_2fa_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт профилей MFA в раздел "Пользователи и устройства/Профили MFA".')
        error = 0

        if 'notification_profiles' not in self.ngfw_data:
            if self.get_notification_profiles():      # Устанавливаем атрибут self.ngfw_data['notification_profiles']
                logging.info('    Произошла ошибка при импорте профилей MFA.')
                return
        notification_profiles = self.ngfw_data['notification_profiles']

        if 'profiles_2fa' not in self.ngfw_data:
            if self.get_2fa_profiles():     # Устанавливаем self.ngfw_data['profiles_2fa']
                logging.info('    Произошла ошибка при импорте профилей MFA.')
                return
        profiles_2fa = self.ngfw_data['profiles_2fa']

        for item in data:
            if item['name'] in profiles_2fa:
                logging.info(f'GRAY|    Профиль MFA "{item["name"]}" уже существует.')
            else:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля MFA')
                if item['type'] == 'totp':
                    if item['init_notification_profile_id'] not in notification_profiles:
                        logging.error(f'    Error: Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения "{item["init_notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                        error = 1
                        continue
                    item['init_notification_profile_id'] = notification_profiles[item['init_notification_profile_id']]
                else:
                    if item['auth_notification_profile_id'] not in notification_profiles:
                        logging.error(f'    Error: Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения "{item["auth_notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                        error = 1
                        continue
                    item['auth_notification_profile_id'] = notification_profiles[item['auth_notification_profile_id']]

                err, result = self.utm.add_2fa_profile(item)
                if err:
                    logging.error(f'    {result}  [Профиль MFA "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    profiles_2fa[item['name']] = result
                    logging.info(f'BLACK|    Профиль MFA "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте профилей MFA.')
        else:
            logging.info('    Импорт профилей MFA завершён.')


    def import_auth_profiles(self, path):
        """Импортируем список профилей аутентификации"""
        json_file = os.path.join(path, 'config_auth_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт профилей аутентификации в раздел "Пользователи и устройства/Профили аутентификации".')
        error = 0

        err, ldap, radius, tacacs, ntlm, saml = self.utm.get_auth_servers()
        if err:
            logging.error(f'    {ldap}\n    Произошла ошибка при импорте профилей аутентификации.')
            self.error = 1
            return
        auth_servers = {x['name']: x['id'] for x in [*ldap, *radius, *tacacs, *ntlm, *saml]}

        if 'profiles_2fa' not in self.ngfw_data:
            if self.get_2fa_profiles():     # Устанавливаем self.ngfw_data['profiles_2fa']
                logging.info(f'    Произошла ошибка при импорте профилей аутентификации.')
                return
        profiles_2fa = self.ngfw_data['profiles_2fa']

        auth_type = {
            'ldap': 'ldap_server_id',
            'radius': 'radius_server_id',
            'tacacs_plus': 'tacacs_plus_server_id',
            'ntlm': 'ntlm_server_id',
            'saml_idp': 'saml_idp_server_id'
        }

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля аутентификации')
            if item['2fa_profile_id']:
                try:
                    item['2fa_profile_id'] = profiles_2fa[item['2fa_profile_id']]
                except KeyError:
                    logging.error(f'    Error: Для "{item["name"]}" не найден профиль MFA "{item["2fa_profile_id"]}". Загрузите профили MFA и повторите попытку.')
                    item['2fa_profile_id'] = False
                    error = 1

            for auth_method in item['allowed_auth_methods']:
                if len(auth_method) == 2:
                    method_server_id = auth_type[auth_method['type']]
                    try:
                        auth_method[method_server_id] = auth_servers[auth_method[method_server_id]]
                    except KeyError:
                        logging.error(f'    Error: Для "{item["name"]}" не найден сервер аутентификации "{auth_method[method_server_id]}". Загрузите серверы аутентификации и повторите попытку.')
                        auth_method.clear()
                        error = 1

                    if 'saml_idp_server_id' in auth_method and self.utm.float_version < 6:
                        auth_method['saml_idp_server'] = auth_method.pop('saml_idp_server_id', False)

            item['allowed_auth_methods'] = [x for x in item['allowed_auth_methods'] if x]

            if item['name'] in self.ngfw_data['auth_profiles']:
                logging.info(f'uGRAY|    Профиль аутентификации "{item["name"]}" уже существует.')
                err, result = self.utm.update_auth_profile(self.ngfw_data['auth_profiles'][item['name']], item)
                if err:
                    logging.error(f'       {result}  [Profile: item["name"]]')
                    error = 1
                else:
                    logging.info(f'uGRAY|       Профиль аутентификации "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_auth_profile(item)
                if err:
                    logging.error(f'    {result}  [Профиль аутентификации "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    self.ngfw_data['auth_profiles'][item['name']] = result
                    logging.info(f'BLACK|    Профиль аутентификации "{item["name"]}" импортирован.')

        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте профилей аутентификации.')
        else:
            logging.info('    Импорт профилей аутентификации завершён.')

    def import_terminal_servers(self, path):
        """Импортируем список терминальных серверов"""
        json_file = os.path.join(path, 'config_terminal_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт списка терминальных серверов в раздел "Пользователи и устройства/Терминальные серверы".')
        error = 0

        err, result = self.utm.get_terminal_servers()
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при импорте списка терминальных серверов.')
            self.error = 1
            return
        terminal_servers = {x['name']: x['id'] for x in result}

        for item in data:
            if item['name'] in terminal_servers:
                logging.info(f'uGRAY|    Терминальный сервер "{item["name"]}" уже существует.')
                err, result = self.utm.update_terminal_server(terminal_servers[item['name']], item)
                if err:
                    logging.error(f'       {result}  [Terminal Server "{item["name"]}"]')
                    error = 1
                else:
                    logging.info(f'uGRAY|       Терминальный сервер "{item["name"]}" updated.')
            else:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя терминального сервера')
                err, result = self.utm.add_terminal_server(item)
                if err:
                    logging.error(f'    {result}  [Terminal Server "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    terminal_servers[item['name']] = result
                    logging.info(f'BLACK|    Терминальный сервер "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте списка терминальных серверов.')
        else:
            logging.info('    Импорт терминальных серверов завершён.')



    def import_agent_config(self, path):
        """Импортируем настройки UserID агент"""
        json_file = os.path.join(path, 'userid_agent_config.json')
        err, result = self.read_json_file(json_file, mode=2)
        if err:
            return

        error = 0
        logging.info('Импорт свойств агента UserID в раздел "Пользователи и устройства/UserID агент".')

        if isinstance(result, list):
            # В случае версий 7.2 и выше - берём только первую конфигурацию свойств, так как при экспорте с кластера
            # могут быть конфигурации со всех узлов кластера и не понятно свойства с какого узла импортировать.
            try:
                data = result[0]
            except Exception:       # Будет ошибка если экспортировали конвертером версии 3.1 и ниже.
                logging.error(f'    Error: Произошла ошибка при импорте свойства агента UserID. Ошибка файла конфигурации.')
                self.error = 1
                return
        else:
            data = result

        data.pop('name', None)
        if self.utm.float_version != 7.2:
            data['expiration_time'] = 2700
            data.pop('radius_monitoring_interval', None)

        if data['tcp_ca_certificate_id']:
            try:
                data['tcp_ca_certificate_id'] = self.ngfw_data['certs'][data['tcp_ca_certificate_id']]
            except KeyError as err:
                loggingerroro('    Error: Не найден сертификат "{err}". Загрузите сертификаты и повторите попытку.')
                data.pop('tcp_ca_certificate_id', None)
                error = 1
        else:
            data.pop('tcp_ca_certificate_id', None)

        if data['tcp_server_certificate_id']:
            try:
                data['tcp_server_certificate_id'] = self.ngfw_data['certs'][data['tcp_server_certificate_id']]
            except KeyError as err:
                loggingerroro('    Error: Не найден сертификат УЦ "{err}". Загрузите сертификаты и повторите попытку.')
                data.pop('tcp_server_certificate_id', None)
                error = 1
        else:
            data.pop('tcp_server_certificate_id', None)

        new_networks = []
        for x in data['ignore_networks']:
            try:
                new_networks.append(['list_id', self.ngfw_data['ip_lists'][x[1]]])
            except KeyError as err:
                logging.error(f'    Error: Не найден список IP-адресов {err} для Ignore Networks. Загрузите списки IP-адресов и повторите попытку.')
                error = 1
        data['ignore_networks'] = new_networks

        err, result = self.utm.set_useridagent_config(data)
        if err:
            logging.error(f'    {result} [Свойства агента UserID не импортированы]')
            error = 1

        if error:
            self.error = 1
            logging.info(f'    Произошла ошибка при импорте свойства агента UserID.')
        else:
            logging.info('BLACK|    Свойства агента UserID обновлены.')


    def import_agent_servers(self, path):
        """Импортируем настройки AD и свойств отправителя syslog UserID агент"""
        json_file = os.path.join(path, 'userid_agent_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт Агент UserID в раздел "Пользователи и устройства/Агент UserID".')
        error = 0

        err, result = self.utm.get_useridagent_filters()
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при импорте настроек UserID агент.')
            self.error = 1
            return
        useridagent_filters = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_useridagent_servers()
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при импорте настроек UserID агент.')
            self.error = 1
            return
        useridagent_servers = {x['name']: x['id'] for x in result}


        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя UserID агент')
            if self.utm.float_version < 7.2:
                if item['type'] == 'radius':
                    logging.info(f'    Коннектор UserID агент "{item["name"]}" не импортирован так как ваша версия NGFW меньше 7.2.')
                    continue
                item.pop('exporation_time', None)
            try:
                item['auth_profile_id'] = self.ngfw_data['auth_profiles'][item['auth_profile_id']]
            except KeyError:
                logging.error(f'    Error: [UserID агент "{item["name"]}"] Не найден профиль аутентификации "{item["auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["auth_profile_id"]}".'
                item['auth_profile_id'] = 1
                error = 1
            if 'filters' in item:
                new_filters = []
                for filter_name in item['filters']:
                    try:
                        new_filters.append(useridagent_filters[filter_name])
                    except KeyError:
                        logging.error(f'    Error: [UserID агент "{item["name"]}"] Не найден Syslog фильтр UserID агента "{filter_name}". Загрузите фильтры UserID агента и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден Syslog фильтр UserID агента "{filter_name}".'
                        error = 1
                item['filters'] = new_filters

            if item['name'] in useridagent_servers:
                logging.info(f'uGRAY|    UserID агент "{item["name"]}" уже существует.')
                err, result = self.utm.update_useridagent_server(useridagent_servers[item['name']], item)
                if err:
                    logging.error(f'       {result}  [UserID агент "{item["name"]}"]')
                    error = 1
                else:
                    logging.info(f'uGRAY|       UserID агент "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_useridagent_server(item)
                if err:
                    logging.error(f'    {result}  [UserID агент "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    useridagent_servers[item['name']] = result
                    logging.info(f'BLACK|    UserID агент "{item["name"]}" импортирован.')
            if item['type'] == 'ad':
                logging.info(f'L       Необходимо указать пароль для этого коннетора Microsoft AD.')
            elif item['type'] == 'radius':
                logging.info(f'L       Необходимо указать секретный код для этого коннетора RADIUS.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте настроек UserID агент.')
        else:
            logging.info('    Импорт Агентов UserID завершён.')


    #---------------------------------------- Политики сети -----------------------------------------
    def import_firewall_rules(self, path):
        """Импортируем список правил межсетевого экрана"""
        json_file = os.path.join(path, 'config_firewall_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт правил межсетевого экрана в раздел "Политики сети/Межсетевой экран".')

        if self.utm.product != 'dcfw':
            if 'scenarios_rules' not in self.ngfw_data:
                if self.get_scenarios_rules():     # Устанавливаем атрибут self.ngfw_data['scenarios_rules']
                    logging.info('    Произошла ошибка при импорте правил межсетевого экрана.')
                    return
            scenarios_rules = self.ngfw_data['scenarios_rules']

        if self.utm.float_version >= 7.1:
            err, result = self.utm.get_idps_profiles_list()
            if err:
                logging.error(f'    {result}\n    Произошла ошибка при импорте правил межсетевого экрана.')
                self.error = 1
                return
            idps_profiles = {x['name']: x['id'] for x in result}

            err, result = self.utm.get_l7_profiles_list()
            if err:
                logging.error(f'    {result}\n    Произошла ошибка при импорте правил межсетевого экрана.')
                self.error = 1
                return
            l7_profiles = {x['name']: x['id'] for x in result}

            if self.utm.product != 'dcfw':
                err, result = self.utm.get_hip_profiles_list()
                if err:
                    logging.error(f'    {result}\n    Произошла ошибка при импорте правил межсетевого экрана.')
                    self.error = 1
                    return
                hip_profiles = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_firewall_rules()
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при импорте правил межсетевого экрана.')
            self.error = 1
            return
        firewall_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        error = 0
        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item.pop('time_created', None)
            item.pop('time_updated', None)

            if self.utm.product == 'dcfw':
                item['scenario_rule_id'] = False
            else:
                if item['scenario_rule_id']:
                    try:
                        item['scenario_rule_id'] = scenarios_rules[item['scenario_rule_id']]
                    except KeyError as err:
                        logging.error(f'    Error: [Правило МЭ "{item["name"]}"] Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                        item['scenario_rule_id'] = False
                        item['enabled'] = False
                        error = 1
            if self.utm.float_version < 7.1:
                if 'apps' in item:
                    item['apps'] = self.get_apps(item)
                else:
                    item['apps'] = []
                    item['apps_negate'] = False
                item.pop('ips_profile', None)
                item.pop('l7_profile', None)
                item.pop('hip_profiles', None)
                if self.utm.float_version >= 6:
                    item.pop('apps_negate', None)
            else:
                item.pop('apps', None)
                item.pop('apps_negate', None)
                if 'ips_profile' in item and item['ips_profile']:
                    try:
                        item['ips_profile'] = idps_profiles[item['ips_profile']]
                    except KeyError as err:
                        logging.error(f'    Error: [Правило МЭ "{item["name"]}"] Не найден профиль СОВ {err}. Загрузите профили СОВ и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден профиль СОВ {err}.'
                        item['ips_profile'] = False
                        item['enabled'] = False
                        error = 1
                else:
                    item['ips_profile'] = False
                if 'l7_profile' in item and item['l7_profile']:
                    try:
                        item['l7_profile'] = l7_profiles[item['l7_profile']]
                    except KeyError as err:
                        logging.error(f'    Error: [Правило МЭ "{item["name"]}"] Не найден профиль приложений {err}. Загрузите профили приложений и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден профиль приложений {err}.'
                        item['l7_profile'] = False
                        item['enabled'] = False
                        error = 1
                else:
                    item['l7_profile'] = False

                if self.utm.product == 'dcfw':
                    item['hip_profile'] = []
                else:
                    if 'hip_profiles' in item:
                        new_hip_profiles = []
                        for hip in item['hip_profiles']:
                            try:
                                new_hip_profiles.append(hip_profiles[hip])
                            except KeyError as err:
                                logging.error(f'    Error: [Правило МЭ "{item["name"]}"] Не найден профиль HIP {err}. Загрузите профили HIP и повторите попытку.')
                                item['description'] = f'{item["description"]}\nError: Не найден профиль HIP {err}.'
                                item['enabled'] = False
                                error = 1
                        item['hip_profiles'] = new_hip_profiles
                    else:
                        item['hip_profile'] = []

            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item)
            item['services'] = self.get_services(item['services'], item)
            item['time_restrictions'] = self.get_time_restrictions_id(item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in firewall_rules:
                logging.info(f'uGRAY|    Правило МЭ "{item["name"]}" уже существует.')
                err, result = self.utm.update_firewall_rule(firewall_rules[item['name']], item)
                if err:
                    error = 1
                    logging.error(f'       {result}  [Правило МЭ "{item["name"]}"]')
                else:
                    logging.info(f'uGRAY|       Правило МЭ "{item["name"]}" updated.')
            else:
                item['position'] = 'last' 
                err, result = self.utm.add_firewall_rule(item)
                if err:
                    error = 1
                    logging.error(f'    {result}  [Правило МЭ "{item["name"]}" не импортировано]')
                else:
                    firewall_rules[item['name']] = result
                    logging.info(f'BLACK|    Правило МЭ "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[firewall_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'fw_rules'):
                error = 1
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте правил межсетевого экрана.')
        else:
            logging.info('    Импорт правил межсетевого экрана завершён.')


    #-------------------------------------- Политики безопасности -----------------------------------


    def import_ssldecrypt_rules(self, path):
        """Импортируем список правил инспектирования SSL"""
        json_file = os.path.join(path, 'config_ssldecrypt_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт правил инспектирования SSL в раздел "Политики безопасности/Инспектирование SSL".')
        error = 0

        ssl_forward_profiles = {}
        if self.utm.float_version >= 7:
            err, rules = self.utm.get_ssl_forward_profiles()
            if err:
                logging.error(f'    {result}\n    Произошла ошибка при импорте правил инспектирования SSL.')
                self.error = 1
                return
            ssl_forward_profiles = {x['name']: x['id'] for x in rules}
            ssl_forward_profiles[-1] = -1

        err, result = self.utm.get_ssldecrypt_rules()
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при импорте правил инспектирования SSL.')
            self.error = 1
            return
        ssldecrypt_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item.pop('time_created', None)
            item.pop('time_updated', None)
            item['users'] = self.get_guids_users_and_groups(item)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['url_categories'] = self.get_url_categories_id(item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            item['time_restrictions'] = self.get_time_restrictions_id(item)
            if self.utm.float_version < 6:
                item.pop('ssl_profile_id', None)
            else:
                try:
                    item['ssl_profile_id'] = self.ngfw_data['ssl_profiles'][item['ssl_profile_id']]
                except KeyError as err:
                    logging.error(f'    Error: [Правило "{item["name"]}"] Не найден профиль SSL {err} для правила "{item["name"]}". Загрузите профили SSL и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
                    item['ssl_profile_id'] = self.ngfw_data['ssl_profiles']['Default SSL profile']
                    item['error'] = True
            if self.utm.float_version < 7:
                item.pop('ssl_forward_profile_id', None)
                if item['action'] == 'decrypt_forward':
                    item['action'] = 'decrypt'
            else:
                try:
                    item['ssl_forward_profile_id'] = ssl_forward_profiles[item['ssl_forward_profile_id']]
                except KeyError as err:
                    logging.error(f'    Error: [Правило "{item["name"]}"] Не найден профиль пересылки SSL {err} для правила "{item["name"]}". Загрузите профили SSL и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль пересылки SSL {err}.'
                    item['ssl_forward_profile_id'] = -1
                    item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in ssldecrypt_rules:
                logging.info(f'uGRAY|    Правило инспектирования SSL "{item["name"]}" уже существует.')
                err, result = self.utm.update_ssldecrypt_rule(ssldecrypt_rules[item['name']], item)
                if err:
                    error = 1
                    logging.error(f'       {result}  [Правило инспектирования SSL "{item["name"]}"]')
                    continue
                else:
                    logging.info(f'uGRAY|       Правило инспектирования SSL "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_ssldecrypt_rule(item)
                if err:
                    error = 1
                    logging.error(f'    {result}  [Правило инспектирования SSL "{item["name"]}" не импортировано]')
                    continue
                else:
                    ssldecrypt_rules[item['name']] = result
                    logging.info(f'BLACK|    Правило инспектирования SSL "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[ssldecrypt_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'content_https_rules'):
                error = 1
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте правил инспектирования SSL.')
        else:
            logging.info('    Импорт правил инспектирования SSL завершён.')


    def import_sshdecrypt_rules(self, path):
        """Импортируем список правил инспектирования SSH"""
        json_file = os.path.join(path, 'config_sshdecrypt_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт правил инспектирования SSH в раздел "Политики безопасности/Инспектирование SSH".')
        error = 0

        err, rules = self.utm.get_sshdecrypt_rules()
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при импорте правил инспектирования SSH.')
            self.error = 1
            return
        sshdecrypt_rules = {x['name']: x['id'] for x in rules}

        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item.pop('time_created', None)
            item.pop('time_updated', None)
            if self.utm.float_version < 7.1:
                item.pop('layer', None)
            item['users'] = self.get_guids_users_and_groups(item)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['time_restrictions'] = self.get_time_restrictions_id(item)
            item['protocols'] = self.get_services(item['protocols'], item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in sshdecrypt_rules:
                logging.info(f'uGRAY|    Правило инспектирования SSH "{item["name"]}" уже существует.')
                err, result = self.utm.update_sshdecrypt_rule(sshdecrypt_rules[item['name']], item)
                if err:
                    error = 1
                    logging.error(f'       {result}  [Правило инспектирования SSH "{item["name"]}"]')
                    continue
                else:
                    logging.info(f'uGRAY|       Правило инспектирования SSH "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_sshdecrypt_rule(item)
                if err:
                    error = 1
                    logging.error(f'    {result}  [Правило инспектирования SSH "{item["name"]}" не импортировано]')
                    continue
                else:
                    sshdecrypt_rules[item['name']] = result
                    logging.info(f'BLACK|    Правило инспектирования SSH "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[sshdecrypt_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'content_ssh_rules'):
                error = 1
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте правил инспектирования SSH.')
        else:
            logging.info('    Импорт правил инспектирования SSH завершён.')


    def import_idps_rules(self, path):
        """Импортируем список правил СОВ"""
        json_file = os.path.join(path, 'config_idps_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт правил СОВ в раздел "Политики безопасности/СОВ".')
        error = 0

        err, result = self.utm.get_nlists_list('ipspolicy')
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при импорте правил СОВ.')
            self.error = 1
            return
        idps_profiles = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_idps_rules()
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при импорте правил СОВ.')
            self.error = 1
            return
        idps_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            if self.utm.float_version < 7.0 and item['action'] == 'reset':
                item['action'] = 'drop'
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['services'] = self.get_services(item['services'], item)
            try:
                item['idps_profiles'] = [idps_profiles[x] for x in item['idps_profiles']]
            except KeyError as err:
                logging.error(f'    Error: [Правило "{item["name"]}"] Не найден профиль СОВ {err}. Загрузите профили СОВ и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль СОВ {err}.'
                item['idps_profiles'] = [idps_profiles['ENTENSYS_IPS_POLICY'],]
                item['error'] = True
            if self.utm.float_version < 6:
                item.pop('idps_profiles_exclusions', None)
            else:
                try:
                    item['idps_profiles_exclusions'] = [idps_profiles[x] for x in item['idps_profiles_exclusions']]
                except KeyError as err:
                    logging.error(f'    Error: [Правило "{item["name"]}"] Не найден профиль исключения СОВ {err}. Загрузите профили СОВ и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль исключения СОВ {err}.'
                    item['idps_profiles_exclusions'] = []
                    item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in idps_rules:
                logging.info(f'uGRAY|    Правило СОВ "{item["name"]}" уже существует.')
                err, result = self.utm.update_idps_rule(idps_rules[item['name']], item)
                if err:
                    error = 1
                    logging.error(f'       {result}  [Правило СОВ "{item["name"]}"]')
                    continue
                else:
                    logging.info(f'uGRAY|       Правило СОВ "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_idps_rule(item)
                if err:
                    error = 1
                    logging.error(f'    {result}  [Правило СОВ "{item["name"]}" не импортировано]')
                    continue
                else:
                    idps_rules[item['name']] = result
                    logging.info(f'BLACK|    Правило СОВ "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте правил СОВ.')
        else:
            logging.info('    Импорт правил СОВ завершён.')

    #--------------------------------------- Библиотека ---------------------------------------------


    def import_services_list(self, path):
        """Импортируем список сервисов раздела библиотеки"""
        json_file = os.path.join(path, 'config_services_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт списка сервисов в раздел "Библиотеки/Сервисы"')
        error = 0
    
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
            for value in item['protocols']:
                if self.utm.float_version < 7.1:
                    value.pop('alg', None)
                    if self.utm.float_version < 6:
                        value.pop('app_proto', None)
                        if value['port'] in ('110', '995'):
                            value['proto'] = 'tcp'
        
            if item['name'] in self.ngfw_data['services']:
                logging.info(f'uGRAY|    Сервис "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_service(item)
                if err == 1:
                    logging.error(f'    {result}  [Сервис "{item["name"]}"]')
                    error = 1
                elif err == 2:
                    logging.info(f'GRAY|    {result}')
                else:
                    self.ngfw_data['services'][item['name']] = result
                    logging.info(f'BLACK|    Сервис "{item["name"]}" добавлен.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при добавлении сервисов!')
        else:
            logging.info('    Импорт списка сервисов завершён.')


    def import_services_groups(self, path):
        """Импортируем группы сервисов в раздел Библиотеки/Группы сервисов"""
        json_file = os.path.join(path, 'config_services_groups_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт групп сервисов в раздел "Библиотеки/Группы сервисов".')
        error = 0

        for item in data:
            content = item.pop('content')
            item.pop('last_update', None)
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
        
            if item['name'] in self.ngfw_data['service_groups']:
                logging.info(f'uGRAY|    Группа сервисов "{item["name"]}" уже существует.')
                err, result = self.utm.update_nlist(self.ngfw_data['service_groups'][item['name']], item)
                if err == 1:
                    error = 1
                    logging.error(f'       {result}  [Группа сервисов: "{item["name"]}"]')
                    continue
                elif err == 2:
                    logging.info(f'GRAY|       {result}')
                else:
                    logging.info(f'uGRAY|       Группа сервисов "{item["name"]}" обновлена.')
            else:
                err, result = self.utm.add_nlist(item)
                if err:
                    error = 1
                    logging.error(f'    {result}  [Группа сервисов "{item["name"]}" не импортирована]')
                    continue
                else:
                    self.ngfw_data['service_groups'][item['name']] = result
                    logging.info(f'BLACK|    Группа сервисов "{item["name"]}" импортирована.')

            if content:
                new_content = []
                for service in content:
                    try:
                        service['value'] = self.ngfw_data['services'][self.get_transformed_name(service['name'], mode=0)[1]]
                        new_content.append(service)
                    except KeyError as err:
                        logging.ierrorf'b       Error: Не найден сервис {err}. Загрузите сервисы и повторите попытку.')

                err2, result2 = self.utm.add_nlist_items(self.ngfw_data['service_groups'][item['name']], new_content)
                if err2 == 1:
                    logging.error(f'       {result2}  [Группа сервисов "{item["name"]}"]')
                    error = 1
                elif err2 == 2:
                    logging.info(f'GRAY|       {result2}')
                else:
                    logging.info(f'BLACK|       Содержимое группы сервисов "{item["name"]}" импортировано.')
            else:
                logging.info(f'GRAY|       Нет содержимого в группе сервисов "{item["name"]}".')

        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте групп сервисов.')
        else:
            logging.info('    Импорт групп сервисов завершён.')

    def import_custom_idps_signature(self, path):
        """Импортируем пользовательские сигнатуры СОВ. Только для версии 7.1 и выше"""
        json_file = os.path.join(path, 'custom_idps_signatures.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт пользовательских сигнатур СОВ в раздел "Библиотеки/Сигнатуры СОВ".')
        error = 0

        err, result = self.utm.get_idps_signatures_list(query={'query': 'owner = You'})
        if err:
            logging.error(f'    {result}')
            self.error = 1
            return
        signatures = {x['msg']: x['id'] for x in result}

        for item in data:
            if item['msg'] in signatures:
                logging.info(f'GRAY|    Сигнатура СОВ "{item["msg"]}" уже существует.')
                err, result = self.utm.update_idps_signature(signatures[item['msg']], item)
                if err:
                    error = 1
                    logging.error(f'       {result}  [Сигнатура СОВ: {item["msg"]}]')
                    continue
                else:
                    logging.info(f'BLACK|       Сигнатура СОВ "{item["msg"]}" updated.')
            else:
                err, result = self.utm.add_idps_signature(item)
                if err:
                    error = 1
                    logging.error(f'    {result}  [Сигнатура СОВ: "{item["msg"]}" не импортирована]')
                    continue
                else:
                    signatures[item['msg']] = result
                    logging.info(f'BLACK|    Сигнатура СОВ "{item["msg"]}" импортирована.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте пользовательских сигнатур СОВ.')
        else:
            logging.info('    Импорт пользовательских сигнатур СОВ завершён.')


    def import_idps_profiles(self, path):
        """Импортируем профили СОВ"""
        json_file = os.path.join(path, 'config_idps_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт профилей СОВ в раздел "Библиотеки/Профили СОВ".')
        error = 0

        if self.utm.float_version < 6:
            loggingerroro('    Импорт профилей СОВ на версию 5 не поддерживается.')
            error = 1
        elif self.utm.float_version < 7.1:
            err, result = self.utm.get_nlist_list('ipspolicy')
            if err:
                logging.error(f'    {result}\n    Произошла ошибка при импорте профилей СОВ.')
                self.error = 1
                return
            idps = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

            for item in data:
                if 'filters' in item:
                    loggingerroro('    Error: Импорт профилей СОВ версий 7.1 и выше на более старые версии не поддерживается.')
                    error = 1
                    break

                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
                content = item.pop('content')
                item.pop('last_update', None)

                err = self.execute_add_update_nlist(idps, item, 'Профиль СОВ')
                if err:
                    error = 1
                    continue
                if content:
                    new_content = []
                    for signature in content:
                        if 'value' not in signature:
                            logging.error(f'    Error: [Профиль СОВ "{item["name"]}"] Сигнатура "{signature["msg"]}" пропущена так как формат не соответствует целевой системе.')
                            error = 1
                            continue
                        new_content.append({'value': signature['value']})
                    content = new_content

                    err = self.execute_add_nlist_items(idps[item['name']], item['name'], content)
                    if err:
                        error = 1
                else:
                    logging.info(f'GRAY|       Список "{item["name"]}" пуст.')
        else:
            err, result = self.utm.get_idps_profiles_list()
            if err:
                logging.error(f'    {result}\n    Произошла ошибка при импорте профилей СОВ.')
                self.error = 1
                return
            profiles = {x['name']: x['id'] for x in result}

            err, result = self.utm.get_idps_signatures_list(query={'query': 'owner = You'})
            if err:
                logging.error(f'    {result}\n    Произошла ошибка при импорте профилей СОВ.')
                self.error = 1
                return
            custom_idps = {x['msg']: x['id'] for x in result}

            for item in data:
                if 'filters' not in item:
                    loggingerroro('    Error: Импорт профилей СОВ старых версий не поддерживается для версий 7.1 и выше.')
                    error = 1
                    break
                # Исключаем отсутствующие сигнатуры. Получаем ID сигнатур по имени так как ID может не совпадать.
                new_overrides = []
                for signature in item['overrides']:
                    try:
                        if 1000000 < signature['signature_id'] < 1099999:
                            signature['id'] = custom_idps[signature['msg']]
#                        signature.pop('signature_id', None)
#                        signature.pop('msg', None)
                        new_overrides.append(signature)
                    except KeyError as err:
                        logging.error(f'    Error: [Профиль СОВ "{item["name"]}"] Не найдена сигнатура {err}.')
                        error = 1
                item['overrides'] = new_overrides

                if item['name'] in profiles:
                    logging.info(f'GRAY|    Профиль СОВ "{item["name"]}" уже существует.')
                    err, result = self.utm.update_idps_profile(profiles[item['name']], item)
                    if err:
                        error = 1
                        logging.error(f'       {result}  [Профиль СОВ: {item["name"]}]')
                    else:
                        logging.info(f'BLACK|       Профиль СОВ "{item["name"]}" updated.')
                else:
                    err, result = self.utm.add_idps_profile(item)
                    if err:
                        error = 1
                        logging.error(f'    {result}  [Профиль СОВ: "{item["name"]}" не импортирован]')
                    else:
                        profiles[item['name']] = result
                        logging.info(f'BLACK|    Профиль СОВ "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте профилей СОВ.')
        else:
            logging.info('    Импорт профилей СОВ завершён.')



    def import_lldp_profiles(self, path):
        """Импортируем список профилей LLDP"""
        json_file = os.path.join(path, 'config_lldp_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт профилей LLDP в раздел "Библиотеки/Профили LLDP".')
        error = 0

        err, result = self.utm.get_lldp_profiles_list()
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при импорте профилей LLDP.')
            self.error = 1
            return
        profiles = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in profiles:
                logging.info(f'GRAY|    Профиль LLDP "{item["name"]}" уже существует.')
                err, result = self.utm.update_lldp_profile(profiles[item['name']], item)
                if err:
                    error = 1
                    logging.error(f'       {result}  [Профиль LLDP: {item["name"]}]')
                else:
                    logging.info(f'BLACK|       Профиль LLDP "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_lldp_profile(item)
                if err:
                    error = 1
                    logging.error(f'    {result}  [Профиль LLDP: "{item["name"]}" не импортирован]')
                else:
                    profiles[item['name']] = result
                    logging.info(f'BLACK|    Профиль LLDP "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте профилей LLDP.')
        else:
            logging.info('    Импорт профилей LLDP завершён.')


    def import_snmp_security_profiles(self, path):
        """Импортируем профили безопасности SNMP"""
        json_file = os.path.join(path, 'config_snmp_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт профилей безопасности SNMP в раздел "Диагностика и мониторинг/Оповещения/Профили безопасности SNMP".')
        error = 0

        err, result = self.utm.get_snmp_security_profiles()
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при импорте профилей безопасности SNMP.')
            self.error = 1
            return
        snmp_security_profiles = {x['name']: x['id'] for x in result}

        for item in data:
            if item['name'] in snmp_security_profiles:
                logging.info(f'uGRAY|    Профиль безопасности SNMP "{item["name"]}" уже существует.')
                err, result = self.utm.update_snmp_security_profile(snmp_security_profiles[item['name']], item)
                if err:
                    error = 1
                    logging.error(f'       {result}  [Профиль безопасности SNMP "{item["name"]}"]')
                else:
                    logging.info(f'uGRAY|       Профиль безопасности SNMP "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_snmp_security_profile(item)
                if err:
                    error = 1
                    logging.error(f'    {result}  [Профиль безопасности SNMP "{item["name"]}" не импортирован]')
                else:
                    snmp_security_profiles[item['name']] = result
                    logging.info(f'BLACK|    Профиль безопасности SNMP "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте профилей безопасности SNMP.')
        else:
            logging.info('    Импорт профилей безопасности SNMP завершён.')


    def import_snmp_rules(self, path):
        """Импортируем список правил SNMP"""
        json_file = os.path.join(path, 'config_snmp_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        logging.info('Импорт списка правил SNMP в раздел "Диагностика и мониторинг/Оповещения/SNMP".')
        error = 0

        if self.utm.float_version >= 7.1:
            err, result = self.utm.get_snmp_security_profiles()
            if err:
                logging.error(f'    {result}')
                self.error = 1
                return
            snmp_security_profiles = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_snmp_rules()
        if err:
            logging.error(f'    {result}')
            self.error = 1
            return
        snmp_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if self.utm.float_version >= 7.1:
                if 'snmp_security_profile' in item:
                    if item['snmp_security_profile']:
                        try:
                            item['snmp_security_profile'] = snmp_security_profiles[item['snmp_security_profile']]
                        except KeyError as err:
                            logging.error(f'    Error: [Правило "{item["name"]}"] Не найден профиль безопасности SNMP {err}. Импортируйте профили безопасности SNMP и повторите попытку.')
                            item['description'] = f'{item["description"]}\nError: Не найден профиль безопасности SNMP {err}.'
                            item['snmp_security_profile'] = 0
                            item['enabled'] = False
                            error = 1
                else:
                    item['snmp_security_profile'] = 0
                    item['enabled'] = False
                    item.pop('username', None)
                    item.pop('auth_type', None)
                    item.pop('auth_alg', None)
                    item.pop('auth_password', None)
                    item.pop('private_alg', None)
                    item.pop('private_password', None)
                    if item['version'] == 3:
                        item['version'] = 2
                        item['community'] = 'public'
            else:
                if 'snmp_security_profile' in item:
                    item.pop('snmp_security_profile', None)
                    item.pop('enabled', None)
                    item['username'] = ''
                    item['auth_type'] = ''
                    item['auth_alg'] = 'md5'
                    item['auth_password'] = False
                    item['private_alg'] = 'aes'
                    item['private_password'] = False
                    if item['version'] == 3:
                        item['version'] = 2
                        item['community'] = 'public'

            if item['name'] in snmp_rules:
                logging.info(f'uGRAY|    Правило SNMP "{item["name"]}" уже существует.')
                err, result = self.utm.update_snmp_rule(snmp_rules[item['name']], item)
                if err:
                    error = 1
                    logging.error(f'       {result}  [Правило SNMP "{item["name"]}"]')
                else:
                    logging.info(f'uGRAY|       Правило SNMP "{item["name"]}" обновлено.')
            else:
                err, result = self.utm.add_snmp_rule(item)
                if err:
                    error = 1
                    logging.error(f'    {result}  [Правило SNMP "{item["name"]}" не импортировано]')
                else:
                    snmp_rules[item['name']] = result
                    logging.info(f'BLACK|    Правило SNMP "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            logging.info('    Произошла ошибка при импорте правил SNMP.')
        else:
            logging.info('    Импорт правил SNMP завершён.')


    def import_snmp_settings(self, path):
        """Импортируем параметры SNMP. Для версии 7.1 и выше."""
        logging.info('Импорт параметров SNMP в раздел "Диагностика и мониторинг/Оповещения/Параметры SNMP".')

        self.import_snmp_engine(path)
        self.import_snmp_sys_name(path)
        self.import_snmp_sys_location(path)
        self.import_snmp_sys_description(path)

        logging.info('    Параметры SNMP импортированы  в раздел "Диагностика и мониторинг/Оповещения/Параметры SNMP".')


    def import_snmp_engine(self, path):
        json_file = os.path.join(path, 'config_snmp_engine.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        err, result = self.utm.set_snmp_engine(data)
        if err:
            logging.error(f'    {result}/n    Произошла ошибка при импорте SNMP Engine ID.')
            self.error = 1
        else:
            logging.info('BLACK|    SNMP Engine ID импортирован.')


    def import_snmp_sys_name(self, path):
        json_file = os.path.join(path, 'config_snmp_sysname.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        err, result = self.utm.set_snmp_sysname(data)
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при импорте значения SNMP SysName.')
            self.error = 1
        else:
            logging.info('BLACK|    Значение SNMP SysName импортировано.')


    def import_snmp_sys_location(self, path):
        json_file = os.path.join(path, 'config_snmp_syslocation.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        err, result = self.utm.set_snmp_syslocation(data)
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при импорте значения SNMP SysLocation.')
            self.error = 1
        else:
            logging.info('BLACK|    Значение SNMP SysLocation импортировано.')


    def import_snmp_sys_description(self, path):
        json_file = os.path.join(path, 'config_snmp_sysdescription.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        err, result = self.utm.set_snmp_sysdescription(data)
        if err:
            logging.error(f'    {result}\n    Произошла ошибка при импорте значения SNMP SysDescription.')
            self.error = 1
        else:
            logging.info('BLACK|    Значение SNMP SysDescription импортировано.')


    def pass_function(self, path):
        """Функция заглушка"""
        logging.info(f'GRAY|Импорт раздела "{path.rpartition("/")[2]}" в настоящее время не реализован.')


    #############################------------ Служебные функции ------------#####################################
    def get_ips_id(self, mode, rule_ips, rule):
        """
        Получить ID списков IP-адресов. Если список IP-адресов не существует на NGFW, он пропускается.
        mode - принимает значения: src | dst (для формирования сообщений).
        """
        new_rule_ips = []
        for ips in rule_ips:
            if ips[0] == 'geoip_code':
                new_rule_ips.append(ips)
            if ips[0] == 'mac':
                new_rule_ips.append(ips)
            try:
                if ips[0] == 'list_id':
                    new_rule_ips.append(['list_id', self.ngfw_data['ip_lists'][ips[1]]])
                elif ips[0] == 'urllist_id':
                    if self.utm.float_version < 6:
                        logging.ierrorf'b    Error: [Правило "{rule["name"]}"] Список доменов "{ips[1]}" не добавлен в источник/назначение. Версия 5 не поддерживает данный функционал.')
                    else:
                        new_rule_ips.append(['urllist_id', self.ngfw_data['url_lists'][ips[1]]])
            except KeyError as err:
                logging.error(f'    Error: [Правило "{rule["name"]}"] Не найден список {mode}-адресов (IP/URL) "{ips[1]}". Загрузите списки в библиотеки и повторите импорт.')
                rule['description'] = f'{rule["description"]}\nError: Не найден список {mode}-адресов  (IP/URL) "{ips[1]}".'
                rule['error'] = True
        return new_rule_ips


    def get_zones_id(self, mode, zones, rule):
        """
        Получить ID зон. Если зона не существует на NGFW, то она пропускается.
        mode - принимает значения: src | dst (для формирования сообщений).
        """
        new_zones = []
        for zone_name in zones:
            try:
                new_zones.append(self.ngfw_data['zones'][zone_name])
            except KeyError as err:
                logging.error(f'    Error: [Правило "{rule["name"]}"] Не найдена {mode}-зона "{zone_name}". Импортируйте зоны и повторите попытку.')
                rule['description'] = f'{rule["description"]}\nError: Не найдена {mode}-зона "{zone_name}".'
                rule['error'] = True
        return new_zones


    def get_guids_users_and_groups(self, rule):
        """
        Получить GUID-ы групп и пользователей по их именам.
        Заменяет имена локальных и доменных пользователей и групп на GUID-ы.
        """
        new_users = []
        for item in rule['users']:
            match item[0]:
                case 'special':
                    new_users.append(item)
                case 'user':
                    user_name = None
                    try:
                        ldap_domain, _, user_name = item[1].partition("\\")
                    except IndexError:
                        logging.info(f'    Error: [Правило "{rule["name"]}"] Не указано имя пользователя в "{item}".')
                    if user_name:
                        err, result = self.utm.get_ldap_user_guid(ldap_domain, user_name)
                        if err:
                            logging.error(f'    {result}  [Rule "{rule["name"]}"]')
                            rule['description'] = f'{rule["description"]}\nError: Не удалось получить ID пользователя "{user_name}" - {result}.'
                            rule['error'] = True
                        elif not result:
                            logging.error(f'    Error: [Rule "{rule["name"]}"] Нет LDAP-коннектора для домена "{ldap_domain}". Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                            rule['description'] = f'{rule["description"]}\nError: Нет пользователя "{user_name}" в домене или LDAP-коннектора для домена "{ldap_domain}".'
                            rule['error'] = True
                        else:
                            new_users.append(['user', result])
                    else:
                        try:
                            new_users.append(['user', self.ngfw_data['local_users'][item[1]]])
                        except KeyError as err:
                            logging.error(f'    Error: [Правило "{rule["name"]}"] Не найден локальный пользователь "{err}". Импортируйте локальных пользователей.')
                            rule['description'] = f'{rule["description"]}\nError: Не найден локальный пользователь "{err}".'
                            rule['error'] = True
                case 'group':
                    group_name = None
                    try:
                        ldap_domain, _, group_name = item[1].partition("\\")
                    except IndexError:
                        logging.info(f'    Error: [Правило "{rule["name"]}"] Не указано имя группы в "{item}".')
                    if group_name:
                        err, result = self.utm.get_ldap_group_guid(ldap_domain, group_name)
                        if err:
                            logging.error(f'    {result}  [Rule "{rule["name"]}"]')
                            rule['description'] = f'{rule["description"]}\nError: Не удалось получить ID группы "{group_name}" - {result}.'
                            rule['error'] = True
                        elif not result:
                            logging.error(f'    Error: [Rule "{rule["name"]}"] Нет LDAP-коннектора для домена "{ldap_domain}". Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                            rule['description'] = f'{rule["description"]}\nError: Нет группы "{group_name}" в домене или LDAP-коннектора для домена "{ldap_domain}".'
                            rule['error'] = True
                        else:
                            new_users.append(['group', result])
                    else:
                        try:
                            new_users.append(['group', self.ngfw_data['local_groups'][item[1]]])
                        except KeyError as err:
                            logging.error(f'    Error: [Правило "{rule["name"]}"] Не найдена группа пользователей "{err}"]. Импортируйте группы пользователей.')
                            rule['description'] = f'{rule["description"]}\nError: Не найдена группа пользователей "{err}".'
                            rule['error'] = True
        return new_users


    def get_services(self, service_list, rule):
        """Получаем ID сервисов по их именам. Если сервис не найден, то он пропускается."""
        new_service_list = []
        if self.utm.float_version < 7:
            for item in service_list:
                if item[0] == 'list_id':
                    logging.ierrorf'b    Error: [Правило "{rule["name"]}"] Группа сервисов "{item[1]}" не добавлена. В версии 6 группы сервисов не поддерживаются.')
                else:
                    try:
                        new_service_list.append(self.ngfw_data['services'][item[1]])
                    except KeyError as err:
                        logging.error(f'    Error: [Правило "{rule["name"]}"] Не найден сервис "{item[1]}". Импортируйте сервисы и повторите попытку.')
                        rule['description'] = f'{rule["description"]}\nError: Не найден сервис "{item[1]}".'
                        rule['error'] = True
        else:
            for item in service_list:
                try:
                    if item[0] == 'service':
                        new_service_list.append(['service', self.ngfw_data['services'][item[1]]])
                    elif item[0] == 'list_id':
                        new_service_list.append(['list_id', self.ngfw_data['service_groups'][item[1]]])
                except KeyError as err:
                    logging.error(f'    Error: [Правило "{rule["name"]}"] Не найден сервис "{item[1]}". Загрузите сервисы и повторите импорт.')
                    rule['description'] = f'{rule["description"]}\nError: Не найден сервис "{item[1]}".'
                    rule['error'] = True
        return new_service_list


    def execute_add_update_nlist(self, ngfw_named_list, item, item_note):
        """Обновляем существующий именованный список или создаём новый именованный список"""
        if item['name'] in ngfw_named_list:
            logging.info(f'GRAY|    {item_note} "{item["name"]}" уже существует.')
            err, result = self.utm.update_nlist(ngfw_named_list[item['name']], item)
            if err == 1:
                logging.error(f'    {result}  [{item_note}: {item["name"]}]')
                return 1
            elif err == 2:
                logging.info(f'GRAY|    {result}')
            else:
                logging.info(f'BLACK|    {item_note} "{item["name"]}" updated.')
        else:
            err, result = self.utm.add_nlist(item)
            if err:
                logging.error(f'    {result}  [{item_note}: "{item["name"]}"]')
                return 1
            else:
                ngfw_named_list[item['name']] = result
                logging.info(f'BLACK|    {item_note} "{item["name"]}" импортирована.')
        return 0


    def execute_add_nlist_items(self, list_id, item_name, content):
        """Импортируем содержимое в именованный список"""
        err, result = self.utm.add_nlist_items(list_id, content)
        if err == 2:
            logging.info(f'GRAY|       {result}')
        elif err == 1:
            logging.error(f'       {result}  [Список: "{item_name}"]')
            return 1
        else:
            logging.info(f'BLACK|       Содержимое списка "{item_name}" обновлено.')
        return 0


    def add_new_nlist(self, name, nlist_type, content):
        """Добавляем в библиотеку новый nlist с содержимым."""
        nlist = {
            'name': name,
            'description': '',
            'type': nlist_type,
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
        }
        err, list_id = self.utm.add_nlist(nlist)
        if err:
            return err, list_id
        err, result = self.utm.add_nlist_items(list_id, content)
        if err:
            return err, result
        return 0, list_id


    def add_empty_vrf(self, vrf_name):
        """Добавляем пустой VRF"""
        vrf = {
            'name': vrf_name,
            'description': '',
            'interfaces': [],
            'routes': [],
            'ospf': {},
            'bgp': {},
            'rip': {},
            'pimsm': {}
        }
        err, result = self.utm.add_vrf(vrf)
        if err:
            return err, result
        return 0, result    # Возвращаем ID добавленного VRF



    def add_tags_for_objects(self, data, object_type):
        """Добавляем тэги к объектам определённой группы"""
        error = 0
        tag_relations = []
        for object_id, tags in data.items():
            for tag in tags:
                try:
                    tag_relations.append({
                        'tag_id': self.ngfw_data['tags'][tag],
                        'object_id': object_id,
                        'object_type': object_type
                    })
                except KetError as err:
                    self.parent.stepChanged.error(f'    Error: Не найден тэг {err}.')
                    error = 1
        err, result = self.utm.set_tags_in_objects(tag_relations)
        if err or error:
            self.parent.stepChanged.error(f'    Error: Произошла ошибка при импорте тэгов для {object_type}.')


class Zone:
    def __init__(self, parent, zone):
        self.parent = parent
        self.name = zone['name']
        self.description = zone['description']
        self.services_access = zone['services_access']
        self.enable_antispoof = zone['enable_antispoof']
        self.antispoof_invert = zone['antispoof_invert']
        self.networks = zone['networks']
        self.sessions_limit_enabled = zone['sessions_limit_enabled']
        self.sessions_limit_exclusions = zone['sessions_limit_exclusions']
        self.ngfw_version = parent.utm.float_version
        self.ngfw_zone_services = {v: k for k, v in zone_services.items()}
        self.error = 0
        self.check_services_access()
        self.check_sessions_limit()
        self.check_networks()


    def check_services_access(self):
        """Обрабатываем сервисы из контроля доступа."""
        new_service_access = []
        for service in self.services_access:
            service_name = service['service_id']
            # Проверяем что такой сервис существует в этой версии NGFW и получаем его ID.
            try:
                service['service_id'] = self.ngfw_zone_services[service['service_id']]
            except KeyError as err:
                self.parent.stepChanged.error(f'    Error: [Зона "{self.name}"] Не корректный сервис "{service_name}" в контроле доступа. Возможно он не существует в этой версии NGFW.')
                self.description = f'{self.description}\nError: Не импортирован сервис "{service_name}" в контроль доступа.'
                self.error = 1
                continue
            # Приводим список разрешённых адресов сервиса в соответствие с версией NGFW.
            if service['allowed_ips']:
                if self.ngfw_version < 7.1:
                    if isinstance(service['allowed_ips'][0], list):
                        service['allowed_ips'] = []
                        self.parent.stepChanged.emit(f'    Warning: Для зоны "{self.name}" в контроле доступа сервиса "{service_name}" удалены списки IP-адресов. Списки поддерживаются только в версии 7.1 и выше.')
                        self.description = f'{self.description}\nError: В контроле доступа сервиса "{service_name}" удалены списки IP-адресов. Списки поддерживаются только в версии 7.1 и выше.'
                else:
                    if isinstance(service['allowed_ips'][0], list):
                        allowed_ips = []
                        for item in service['allowed_ips']:
                            if item[0] == 'list_id':
                                try:
                                    item[1] = self.parent.ngfw_data['ip_lists'][item[1]]
                                except KeyError as err:
                                    self.parent.stepChanged.error(f'    Error: [Зона "{self.name}"] В контроле доступа сервиса "{service_name}" не найден список IP-адресов {err}.')
                                    self.description = f'{self.description}\nError: В контроле доступа сервиса "{service_name}" не найден список IP-адресов {err}.'
                                    self.error = 1
                                    continue
                            allowed_ips.append(item)
                        service['allowed_ips'] = allowed_ips
                    else:
                        nlist_name = f'Zone {self.name} (service access: {service_name})'
                        if nlist_name in self.parent.ngfw_data['ip_lists']:
                            service['allowed_ips'] = [['list_id', self.parent.ngfw_data['ip_lists'][nlist_name]]]
                        else:
                            content = [{'value': ip} for ip in service['allowed_ips']]
                            err, list_id = self.parent.add_new_nlist(self.parent.utm, nlist_name, 'network', content)
                            if err == 1:
                                message = f'Error: [Зона "{self.name}"] Не создан список IP-адресов в контроле доступа сервиса "{service_name}".'
                                self.parent.stepChanged.error(f'    {list_id}\n       {message}')
                                self.description = f'{self.description}\nError: В контроле доступа сервиса "{service_name}" не создан список IP-адресов.'
                                self.error = 1
                                continue
                            elif err == 2:
                                message = f'Warning: Список IP-адресов "{nlist_name}" контроля доступа сервиса "{service_name}" зоны "{self.name}" уже существует.'
                                self.parent.stepChanged.emit('    {message}\n       Перезапустите конвертер и повторите попытку.')
                                continue
                            else:
                                self.parent.stepChanged.emit(f'BLACK|    Cоздан список IP-адресов "{nlist_name}" контроля доступа сервиса "{service_name}" зоны "{self.name}".')
                                service['allowed_ips'] = [['list_id', list_id]]
                                self.parent.ngfw_data['ip_lists'][nlist_name] = list_id

            # Удаляем сервисы зон версии 7.1 которых нет в более старых версиях.
#            if self.ngfw_version < 7.1:
#                for service in self.services_access:
#                    if service['service_id'] in (31, 32, 33):
#                        continue
            new_service_access.append(service)

        self.services_access = new_service_access


    def check_networks(self):
        """Обрабатываем защиту от IP-спуфинга"""
        if self.networks:
            if self.ngfw_version < 7.1:
                if isinstance(self.networks[0], list):
                    self.networks = []
                    self.parent.stepChanged.emit(f'    Для зоны "{zone["name"]}" удалены списки IP-адресов в защите от IP-спуфинга. Списки поддерживаются только в версии 7.1 и выше.')
                    self.description = f'{self.description}\nError: В защите от IP-спуфинга удалены списки IP-адресов. Списки поддерживаются только в версии 7.1 и выше.'
            else:
                if isinstance(self.networks[0], list):
                    new_networks = []
                    for item in self.networks:
                        if item[0] == 'list_id':
                            try:
                                item[1] = self.parent.ngfw_data['ip_lists'][item[1]]
                            except KeyError as err:
                                self.parent.stepChanged.error(f'    Error: [Зона "{self.name}"] В разделе "Защита от IP-спуфинга" не найден список IP-адресов {err}.')
                                self.description = f'{self.description}\nError: В разделе "Защита от IP-спуфинга" не найден список IP-адресов {err}.'
                                self.error = 1
                                continue
                        new_networks.append(item)
                    self.networks = new_networks
                else:
                    nlist_name = f'Zone {self.name} (IP-spufing)'
                    if nlist_name in self.parent.ngfw_data['ip_lists']:
                        self.networks = [['list_id', self.parent.ngfw_data['ip_lists'][nlist_name]]]
                    else:
                        content = [{'value': ip} for ip in self.networks]
                        err, list_id = self.parent.add_new_nlist(self.parent.utm, nlist_name, 'network', content)
                        if err == 1:
                            message = f'Error: [Зона "{self.name}"] Не создан список IP-адресов в защите от IP-спуфинга.'
                            self.parent.stepChanged.error(f'    {list_id}\n       {message}')
                            self.description = f'{self.description}\nError: В разделе "Защита от IP-спуфинга" не создан список IP-адресов.'
                            self.networks = []
                            self.error = 1
                        elif err == 2:
                            message = f'Warning: Список IP-адресов "{nlist_name}" защиты от IP-спуфинга для зоны "{self.name}" уже существует.'
                            self.parent.stepChanged.emit('    {message}\n       Перезапустите конвертер и повторите попытку.')
                            self.networks = []
                        else:
                            self.parent.stepChanged.emit(f'BLACK|    Cоздан список IP-адресов "{nlist_name}" защиты от IP-спуфинга для зоны "{self.name}".')
                            self.networks = [['list_id', list_id]]
                            self.parent.ngfw_data['ip_lists'][nlist_name] = list_id
        if not self.networks:
            self.enable_antispoof = False
            self.antispoof_invert = False


    def check_sessions_limit(self):
        """Обрабатываем ограничение сессий"""
        new_sessions_limit_exclusions = []
        if self.ngfw_version >= 7.1:
            for item in self.sessions_limit_exclusions:
                try:
                    item[1] = self.parent.ngfw_data['ip_lists'][item[1]]
                    new_sessions_limit_exclusions.append(item)
                except KeyError as err:
                    self.parent.stepChanged.error(f'    Error: [Зона "{self.name}"] В разделе "Ограничение сессий" не найден список IP-адресов {err}.')
                    self.description = f'{self.description}\nError: В разделе "Ограничение сессий" не найден список IP-адресов {err}.'
                    self.error = 1
            self.sessions_limit_exclusions = new_sessions_limit_exclusions
            if not self.sessions_limit_exclusions:
                self.sessions_limit_enabled = False


def main():
    parser = argparse.ArgumentParser(
        description="Import UserGate JSON into NGFW via UTM client"
    )
    parser.add_argument(
        '-i', '--export-dir', required=True,
        help="Directory with exported JSON/configs and temporary_data.bin"
    )
    parser.add_argument(
        '-u', '--utm-host', required=True,
        help="UTM API host (e.g. https://10.0.0.1)"
    )
    parser.add_argument(
        '-U', '--utm-user', required=True,
        help="UTM API username"
    )
    parser.add_argument(
        '-P', '--utm-password', required=True,
        help="UTM API password"
    )
    args = parser.parse_args()

    # Инициализируем клиент UTM (замените на ваш реальный класс)
    from utm import UtmXmlRpc
    utm = UtmXmlRpc(
        server_ip=args.utm_host,
        login=args.utm_user,
        password=args.utm_password
    )
    code, ok = utm.connect()

    # Создаём импортёр без каких-либо фильтров — run() автоматически обработает все секции
    importer = ImportSelectedPoints(
        utm=utm,
        config_path=args.export_dir
    )
    importer.run()

if __name__ == '__main__':
    main()
