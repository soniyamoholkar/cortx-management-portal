#!/bin/env python3

# Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# For any questions about this software or licensing,
# please email opensource@seagate.com or cortx-questions@seagate.com.

import traceback
import os
import pwd
import crypt
import time
import subprocess
from cortx.utils.log import Log
from cortx.utils.conf_store import Conf
from cortx.utils.kv_store.error import KvError
from cortx.utils.validator.error import VError
from cortx.utils.validator.v_pkg import PkgV
from cortx.utils.validator.v_confkeys import ConfKeysV
from cortx.utils.security.cipher import Cipher, CipherInvalidToken
from cortx.utils.validator.v_path import PathV
from cortx.utils.service.service_handler import Service
from payload import Text

class Process:
    def __init__(self, cmd):
        self._cmd = cmd
        pass

    def run(self):
        pass

class SimpleProcess(Process):
    ''' Execute process and provide output '''
    def __init__(self, cmd):
        super(SimpleProcess, self).__init__(cmd)
        self.shell=False
        self.cwd=None
        self.timeout=None
        self.env=None
        self.universal_newlines=None

    def run(self, **args):
        ''' This will can run simple process '''
        for key, value in args.items():
            setattr(self, key, value)

        try:
            cmd = self._cmd.split() if type(self._cmd) is str else self._cmd
            self._cp = subprocess.run(cmd, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, shell=self.shell, cwd=self.cwd,
                    timeout=self.timeout, env=self.env,
                    universal_newlines=self.universal_newlines)

            self._output = self._cp.stdout
            self._err = self._cp.stderr
            self._returncode = self._cp.returncode
            return self._output, self._err, self._returncode
        except Exception as err:
            self._err = "SubProcess Error: " + str(err)
            self._output = ""
            self._returncode = -1
            return self._output, self._err, self._returncode


class CSMWebSetupError(Exception):
    """ Generic Exception with error code and output """

    def __init__(self, rc, message, *args):
        self._rc = rc
        self._desc = message % (args)

    def __str__(self):
        if self._rc == 0: return self._desc
        return "error(%d): %s\n\n%s" %(self._rc, self._desc,
            traceback.format_exc())

    @property
    def rc(self):
        return self._rc


class CSMWeb:
    """ Represents CSMWeb and Performs setup related actions """
    CONSUMER_INDEX = "consumer"
    CSM_WEB_DIST_ENV_FILE_PATH = "/opt/seagate/cortx/csm/web/web-dist/.env"
    CSM_WEB_SERVICE = "/etc/systemd/system/csm_web.service"
    CSM_WEB_SERVICE_TMPL = "/opt/seagate/cortx/csm/conf/service/csm_web.service"
    ENV_INDEX = "env_index"

    def __init__(self, conf_url):
        Conf.init()
        Conf.load(CSMWeb.CONSUMER_INDEX, conf_url)
        Conf.load(self.ENV_INDEX, f"properties://{self.CSM_WEB_DIST_ENV_FILE_PATH}")
        Log.init(service_name = "csm_web_setup", log_path = "/tmp",
                level="INFO")
        self.conf_url = conf_url
        self.machine_id = CSMWeb._get_machine_id()
        self.server_node_info = f"server_node>{self.machine_id}"
        self.conf_store_keys = {}
        self._is_env_dev = False
                
    def post_install(self):
        """ Performs post install operations for CSM Web as well as cortxcli. Raises exception on error """
        self._validate_nodejs_installed()
        self._validate_cortxcli()
        if os.environ.get("CLI_SETUP") == "true":
            CSMWeb._run_cmd(f"cli_setup post_install --config {self.conf_url}")
        self._prepare_and_validate_confstore_keys("post_install")
        self._set_service_user()
        self._config_user()
        self._configure_service_user()
        self._allow_access_to_pvt_ports()
        return 0

    def prepare(self):
        """ Performs post install operations. Raises exception on error """
        if os.environ.get("CLI_SETUP") == "true":
            CSMWeb._run_cmd(f"cli_setup prepare --config {self.conf_url}")
        self._prepare_and_validate_confstore_keys("prepare")
        self._set_deployment_mode()
        self._set_service_user()
        self._set_password_to_csm_user()
        return 0

    def config(self):
        """ Performs configurations. Raises exception on error """
        if os.environ.get("CLI_SETUP") == "true":
            CSMWeb._run_cmd(f"cli_setup config --config {self.conf_url}")
        self._prepare_and_validate_confstore_keys("config")
        self._set_deployment_mode()
        self._configure_csm_web_keys()
        return 0

    def init(self):
        """ Perform initialization. Raises exception on error """
        if os.environ.get("CLI_SETUP") == "true":
            CSMWeb._run_cmd(f"cli_setup init --config {self.conf_url}")
        self._prepare_and_validate_confstore_keys("init")
        self._set_service_user()
        self._configure_ssl_permissions()
        self._config_user_permission()
        self._run_cmd("systemctl daemon-reload")
        return 0
    
    def reset(self):
        """ Performs Configuraiton reset. Raises exception on error """
        self._disable_and_stop_service()
        self._reset_logs()
        self._directory_cleanup()
        
        return 0

    def pre_upgrade(self):
        """ Performs Pre upgrade functionalitied. Raises exception on error """

        # TODO: Perform actual steps. Obtain inputs using Conf.get(index, ..)
        return 0

    def post_upgrade(self):
        """ Performs Post upgrade functionalitied. Raises exception on error """
        
        return 0

    def test(self, plan):
        """ Perform configuration testing. Raises exception on error """

        # TODO: Perform actual steps. Obtain inputs using Conf.get(index, ..)
        return 0

    def cleanup(self):
        """ Performs Configuraiton cleanup. Raises exception on error """
        self.files_directory_cleanup()
        self._web_env_file_cleanup()
        # TODO: Perform actual steps. Obtain inputs using Conf.get(index, ..)
        prefactory = False
        if prefactory:
            self._set_service_user()
            self._replace_csm_service_file()
            self._service_user_cleanup()
        return 0

    def _validate_nodejs_installed(self):
        Log.info("Validating NodeJS 12.13.0")
        PathV().validate('exists', ['file:///opt/nodejs/node-v12.13.0-linux-x64/bin/node'])

    def _validate_cortxcli(self):
        Log.info("Validating third party rpms")
        try:
            PkgV().validate("rpms", ["cortx-cli"])
            os.environ["CLI_SETUP"] = "true"            
        except VError as ve:
            os.environ["CLI_SETUP"] = "false"
            Log.error(f"cortx-cli package is not installed: {ve}")

    def _set_deployment_mode(self):
        """if Conf.get(CSMWeb.CONSUMER_INDEX, "DEPLOYMENT>mode") == 'dev':
            Log.info("Running Csm Setup for Dev Mode.")
            self._is_env_dev = True"""
        if Conf.get(self.CONSUMER_INDEX, "DEPLOYMENT>mode") == 'dev':
            Log.info("Running Csm Setup for Dev Mode.")
            self._is_env_dev = True
        Log.info("Setting deployment mode.")

    def _prepare_and_validate_confstore_keys(self, phase: str):
        """ Perform validtions. Raises exceptions if validation fails """
        if phase == "post_install":
            self.conf_store_keys.update({
                "csm_user_key": "cortx>software>csm>user"
                })
        elif phase == "prepare":
            self.conf_store_keys.update({
                "csm_user_key": "cortx>software>csm>user",
                "server_node_info":self.server_node_info,
                "cluster_id":f"{self.server_node_info}>cluster_id",
                "secret_key": "cortx>software>csm>secret"
            })
        elif phase == "config":
            self.conf_store_keys.update({
                "cluster_id":f"{self.server_node_info}>cluster_id"
            })
        if phase == "init":
            self.conf_store_keys.update({
                "csm_user_key": "cortx>software>csm>user",
                "cluster_id":f"{self.server_node_info}>cluster_id"
                })
        elif phase == "post_upgrade":
            self.conf_store_keys.update({
                "csm_user_key": "cortx>software>csm>user",
                "server_node_info":self.server_node_info,
                "data_public_fqdn":f"{self.server_node_info}>network>data>public_fqdn",
                "cluster_id":f"{self.server_node_info}>cluster_id",                
            })

        self._validate_conf_store_keys(CSMWeb.CONSUMER_INDEX)
        return 0

    def _validate_conf_store_keys(self, index, keylist=None):
        if not keylist:
            keylist = list(self.conf_store_keys.values())
        if not isinstance(keylist, list):
            raise CSMWebSetupError(rc=-1, message="Keylist should be kind of list")
        Log.info(f"Validating confstore keys: {keylist}")
        ConfKeysV().validate("exists", index, keylist)

    @staticmethod
    def _get_machine_id():
        """
        Obtains current minion id. If it cannot be obtained, returns default node #1 id.
        """
        Log.info("Fetching Machine Id.")
        cmd = "cat /etc/machine-id"
        machine_id, _err, _returncode = CSMWeb._run_cmd(cmd)
        if _returncode != 0:
            raise CSMWebSetupError(rc=_returncode,message='Unable to obtain current machine id.')
        return machine_id.replace("\n", "")

    @staticmethod
    def _run_cmd(cmd):
        """
        Run command and throw error if cmd failed
        """

        _err = ""
        Log.info(f"Executing cmd: {cmd}")
        _proc = SimpleProcess(cmd)
        _output, _err, _rc = _proc.run(universal_newlines=True)
        Log.info(f"Output: {_output}, \n Err:{_err}, \n RC:{_rc}")
        if _rc != 0:
            raise CSMWebSetupError(rc=_rc,message=f'Obtained non-zero response count for cmd: {cmd} Error: {_err} ')
        return _output, _err, _rc

    def _fetch_csm_user_password(self, decrypt=False):
        """
        This Method Fetches the Password for CSM User from Provisioner.
        :param decrypt:
        :return:
        """
        csm_user_pass = None
        if self._is_env_dev:
            decrypt = False
        Log.info("Fetching CSM User Password from Conf Store.")
        csm_user_pass = Conf.get(self.CONSUMER_INDEX, self.conf_store_keys["secret_key"])
        if decrypt and csm_user_pass:
            Log.info("Decrypting CSM Password.")
            try:
                cluster_id = Conf.get(self.CONSUMER_INDEX, self.conf_store_keys["cluster_id"])
                password_decryption_key = self.conf_store_keys["secret_key"].split('>')[0]
                cipher_key = Cipher.generate_key(cluster_id, password_decryption_key)                
            except KvError as error:
                Log.error(f"Failed to Fetch Cluster Id. {error}")
                return None
            except Exception as e:
                Log.error(f"{e}")
                return None
            try:
                decrypted_value = Cipher.decrypt(cipher_key,
                                                 csm_user_pass.encode("utf-8"))
                return decrypted_value.decode("utf-8")
            except CipherInvalidToken as error:
                Log.error(f"Decryption for CSM Failed. {error}")
                raise CipherInvalidToken(f"Decryption for CSM Failed. {error}")
        return csm_user_pass
            
    def _set_password_to_csm_user(self):
        if not self._is_user_exist():
            raise CSMWebSetupError(f"{self._user} not created on system.")
        Log.info("Fetch decrypted password.")
        _password = self._fetch_csm_user_password(decrypt=True)
        if not _password:
            Log.error("CSM Password Not Available.")
            raise CSMWebSetupError("CSM Password Not Available.")
        _password = crypt.crypt(_password, "22")
        self._run_cmd(f"usermod -p {_password} {self._user}")
            
    def _set_service_user(self):
        """
        This Method will set the username for service user to Self._user
        :return:
        """
        self._user = Conf.get(self.CONSUMER_INDEX, self.conf_store_keys["csm_user_key"])

    def _is_user_exist(self):
        """
        Check if user exists
        """
        try:
            u = pwd.getpwnam(self._user)
            self._uid = u.pw_uid
            self._gid = u.pw_gid
            return True
        except KeyError as err:
            return False

    def _config_user(self):
        """
        Check user already exist and create if not exist
        If reset true then delete user
        """
        if not self._is_user_exist():
            Log.info("Creating Service User without password.")
            CSMWeb._run_cmd((f"useradd -M {self._user}"))
            Log.info("Adding Service User to Wheel Group.")
            CSMWeb._run_cmd(f"usermod -aG wheel {self._user}")
            Log.info("Enabling nologin for Service user.")
            CSMWeb._run_cmd(f"usermod -s /sbin/nologin {self._user}")
            if not self._is_user_exist():
                Log.error("Service User Creation Failed.")
                raise CSMWebSetupError(rc=-1, message=f"Unable to create {self._user} user")            
        else:
            Log.info(f"User {self._user} already exist")
            
    def _configure_service_user(self):
        """
        Configures the Service user in CSM web service files.
        :return:
        """
        Log.info(f"Update file for <USER>:{self._user}")
        service_file_data = Text(self.CSM_WEB_SERVICE).load()
        if not service_file_data:
            Log.warn(f"File {self.CSM_WEB_SERVICE} not updated.")            
        data = service_file_data.replace('<USER>', self._user)
        Text(self.CSM_WEB_SERVICE).dump(data)
        
    def _allow_access_to_pvt_ports(self):
        Log.info("Binding low ports to start a service as non-root")
        CSMWeb._run_cmd("setcap CAP_NET_BIND_SERVICE=+ep /opt/nodejs/node-v12.13.0-linux-x64/bin/node")
        
    def _fetch_management_ip(self):
        cluster_id = Conf.get(self.CONSUMER_INDEX, self.conf_store_keys["cluster_id"])
        virtual_host_key = f"cluster>{cluster_id}>network>management>virtual_host"
        self._validate_conf_store_keys(self.CONSUMER_INDEX,[virtual_host_key])
        virtual_host = Conf.get(self.CONSUMER_INDEX, virtual_host_key)
        if not virtual_host and not self._is_env_dev:
            Log.error("Management IP is not provided hence raising error.")
            raise CSMWebSetupError(rc=-1, message="Management IP is not provided.")
        Log.info(f"Fetch Virtual host: {virtual_host}")
        return virtual_host
    
    def _fetch_key_value(self, key: str, default_value: any):
        cluster_id = Conf.get(self.CONSUMER_INDEX, self.conf_store_keys["cluster_id"])
        key = f"cluster>{cluster_id}>network>management>{key}"
        value = default_value
        try:
            self._validate_conf_store_keys(self.CONSUMER_INDEX,[key])
            value = Conf.get(self.CONSUMER_INDEX, key)
        except VError as ve:
            Log.error("Protocol key does not exist. Set default port as protocol {ve}")
        
        Log.info(f"Fetch {key}: {value}")
        return value
    
    def _fetch_ssl_path(self):
        cluster_id = Conf.get(self.CONSUMER_INDEX, self.conf_store_keys["cluster_id"])
        ssl_path_key = f"cluster>{cluster_id}>network>management>ssl_path"
        ssl_path = None
        try:
            self._validate_conf_store_keys(self.CONSUMER_INDEX,[ssl_path_key])
            ssl_path = Conf.get(self.CONSUMER_INDEX, ssl_path_key)
        except VError as ve:
            print("SSL path does not exist.")
            Log.error(f"SSL path does not exist: {ve}")
        Log.info(f"Fetch SSL Path: {ssl_path}")
        return ssl_path
        
    def _configure_csm_web_keys(self):
        self._run_cmd(f"cp {self.CSM_WEB_DIST_ENV_FILE_PATH} {self.CSM_WEB_DIST_ENV_FILE_PATH}_tmpl")
        Log.info("Configuring CSM Web keys")
        virtual_host = self._fetch_management_ip()
        https_port = self._fetch_key_value("https_port", 443)
        http_port = self._fetch_key_value("http_port", 80)
        server_protocol = self._fetch_key_value("protocol", "https")
        agent_host = self._fetch_key_value("agent_host", "localhost")
        agent_port = self._fetch_key_value("agent_port", "28101")
        agent_protocol = self._fetch_key_value("agent_protocol", "http")
        Log.info(f"Set MANAGEMENT_IP:{virtual_host} and Port: {https_port} to csm web config")
        file_data = Text(self.CSM_WEB_DIST_ENV_FILE_PATH)
        data = file_data.load().split("\n")
        for ele in data:
            if "MANAGEMENT_IP" in ele:
                data.remove(ele)
            if "HTTPS_NODE_PORT" in ele:
                data.remove(ele)
            if "HTTP_NODE_PORT" in ele:
                data.remove(ele)
            if "SERVER_PROTOCOL" in ele:
                data.remove(ele)
            if "CSM_AGENT_HOST" in ele:
                data.remove(ele)
            if "CSM_AGENT_PORT" in ele:
                data.remove(ele)
            if "CSM_AGENT_PROTOCOL" in ele:
                data.remove(ele)
        data.append(f"MANAGEMENT_IP={virtual_host}")
        data.append(f"HTTPS_NODE_PORT={https_port}")
        data.append(f"HTTP_NODE_PORT={http_port}")
        data.append(f"SERVER_PROTOCOL={server_protocol}")
        data.append(f"CSM_AGENT_HOST={agent_host}")
        data.append(f"CSM_AGENT_PORT={agent_port}")
        data.append(f"CSM_AGENT_PROTOCOL={agent_protocol}")
        file_data.dump(("\n").join(data))
        
    def _config_user_permission(self):
        """
        Allow permission for csm resources
        """
        Log.info("Allow permission for csm resources")
        log_path = self._get_log_file_path()
        os.makedirs(log_path, exist_ok=True)
        self._run_cmd(f"setfacl -R -m u:{self._user}:rwx {log_path}")
        
    def _get_log_file_path(self):
        """
        Get log file path from .env
        """
        Log.info("Allow permission for csm resources")
        log_file_path = Conf.get(self.ENV_INDEX,"LOG_FILE_PATH").replace("\"", "")
        log_file_dir = os.path.dirname(log_file_path)
        return log_file_dir
    
    def _configure_ssl_permissions(self):
        """
        Congigure SSL and set permissions
        """
        Log.info("Congigure SSL and set permissions")
        ssl_path = self._fetch_ssl_path()
        self._run_cmd(f"cp {self.CSM_WEB_DIST_ENV_FILE_PATH} {self.CSM_WEB_DIST_ENV_FILE_PATH}_tmpl")
        file_data = Text(self.CSM_WEB_DIST_ENV_FILE_PATH)
        data = file_data.load().split("\n")            
        if not ssl_path:
            print("Setting protocol to http")
            for ele in data:
                if "SERVER_PROTOCOL" in ele:
                    data.remove(ele)
            data.append(f"SERVER_PROTOCOL=http")
        else:
            if os.path.exists(ssl_path):
                for ele in data:
                    if "CERT_PATH" in ele:
                        data.remove(ele)
                    if "PRV_KEY_PATH" in ele:
                        data.remove(ele)
                data.append(f"CERT_PATH={ssl_path}")
                data.append(f"PRV_KEY_PATH={ssl_path}")
                #set permissions
                self._run_cmd(f"setfacl -m u:{self._user}:rwx {ssl_path}")                
            else:
                raise CSMWebSetupError(rc=-1, message="SSL file does not exist")
        file_data.dump(("\n").join(data))
        
    def _reset_logs(self):
            Log.info("Reseting log files")
            log_file_path = Conf.get(self.ENV_INDEX,"LOG_FILE_PATH").replace("\"", "")
            self._run_cmd(f"truncate -s 0 {log_file_path}")
    
    def _disable_and_stop_service(self):
        try:
            service_obj = Service(self.CSM_WEB_SERVICE)
            if service_obj.is_enabled():
                Log.info(f"Disabling {self.CSM_WEB_SERVICE}")
                service_obj.disable()
            if service_obj.get_state().state == 'active':
                Log.info(f"Stopping {self.CSM_WEB_SERVICE}")
                service_obj.stop()

            Log.info(f"Checking if {self.CSM_WEB_SERVICE} stopped.")
            for count in range(0, 10):
                if not service_obj.get_state().state == 'active':
                    break
                time.sleep(2**count)
            if service_obj.get_state().state == 'active':
                Log.error(f"{self.CSM_WEB_SERVICE} still active")
                raise CSMWebSetupError(f"{self.CSM_WEB_SERVICE} still active")
        except Exception as e:
            Log.warn(f"{self.CSM_WEB_SERVICE} not available: {e}")
    
    def _directory_cleanup(self):
        Log.info("Deleting files and folders")
        _path = Conf.get(self.ENV_INDEX,"FILE_UPLOAD_FOLDER").replace("\"", "")
        Log.info(f"Deleting path :{_path}")
        self._run_cmd(f"rm -rf {_path}")
    
    def files_directory_cleanup(self):
        log_file_path = Conf.get(self.ENV_INDEX,"LOG_FILE_PATH").replace("\"", "")
        self._run_cmd(f"rm -rf {log_file_path}")
    
    def _web_env_file_cleanup(self):
        Log.info(f"Replacing {self.CSM_WEB_DIST_ENV_FILE_PATH}​​​​​​​​_tmpl " \
                                            f"{self.CSM_WEB_DIST_ENV_FILE_PATH}​​​​​​​​")
        self._run_cmd(f"cp -f {self.CSM_WEB_DIST_ENV_FILE_PATH}​​​​​​​​_tmpl " \
                                            f"{self.CSM_WEB_DIST_ENV_FILE_PATH}​​​​​​​​")
    
    def _replace_csm_service_file(self):
        '''
        Service file cleanup
        '''
        Log.info(f"Replacing service file.")
        self._run_cmd(f"cp -f {self.CSM_WEB_SERVICE_TMPL} /etc/systemd/system/") 

    def _service_user_cleanup(self):
        '''
        Remove service user if system deployed in dev mode.
        '''
        if Conf.get(self.CONSUMER_INDEX, "DEPLOYMENT>mode") == 'dev' and \
                    self._is_user_exist():
            Log.info(f"Removing Service user: {self._user}")
            self._run_cmd(f"userdel -f {self._user}")


            