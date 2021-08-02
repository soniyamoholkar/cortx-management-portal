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
from cortx.utils.log import Log
from cortx.utils.conf_store import Conf
from cortx.utils.kv_store.error import KvError
from cortx.utils.validator.error import VError
from cortx.utils.validator.v_pkg import PkgV
from cortx.utils.validator.v_confkeys import ConfKeysV
from cortx.utils.validator.v_network import NetworkV
from cortx.utils.validator.v_path import PathV
from payload import Text
from datetime import datetime
import subprocess


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
    CSM_ENV_FILE_PATH = "/home/934748/git/forkrepo/cortx-management-portal/web/.env"
    CSM_WEB_FILE = "/etc/systemd/system/csm_web.service"

    def __init__(self, conf_url):
        Conf.init()
        Conf.load(CSMWeb.CONSUMER_INDEX, conf_url)
        Log.init(service_name = "csm_web_setup", log_path = "/tmp",
                level="INFO")
        self.conf_url = conf_url
        self.machine_id = CSMWeb._get_machine_id()
        self.server_node_info = f"server_node>{self.machine_id}"
        self.conf_store_keys = {}
        self.is_cortxcli_installed = False
        

    def _validate_cortxcli(self):
        Log.info("Validating third party rpms")
        try:
            PkgV().validate("rpms", ["cortx-cli"])
            self.is_cortxcli_installed = True
        except VError as ve:
            Log.error(f"cortx-cli package is not installed: {ve}")

    def validate_cert_paths(self):
        Log.info("Validating certificate paths")
        cert_base_path = Conf.get(CSMWeb.CONSUMER_INDEX, self.conf_store_keys["crt_path_key"])
        PathV().validate('exists', [
            f"dir:{cert_base_path}",
            f"file:{os.path.join(cert_base_path, Conf.get(CSMWeb.CONSUMER_INDEX, self.conf_store_keys['native_crt']))}",
            f"file:{os.path.join(cert_base_path, Conf.get(CSMWeb.CONSUMER_INDEX, self.conf_store_keys['native_key']))}"
        ])
        
    def _set_deployment_mode(self):
        """if Conf.get(CSMWeb.CONSUMER_INDEX, "DEPLOYMENT>mode") == const.DEV:
            Log.info("Running Csm Setup for Dev Mode.")
            self._is_env_dev = True"""
        #TODO: Read .env file and set deployment mode as mentioned in .env.
        Conf.load("env_index", f"properties://{self.CSM_ENV_FILE_PATH}")
        if Conf.get("env_index","NODE_ENV") == "\"development\"":
            Log.info("Running Csm Setup for Dev Mode.")
            print("Running Csm Setup for Dev Mode.")
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
                "server_node_info":self.server_node_info,
                "data_public_fqdn":f"{self.server_node_info}>network>data>public_fqdn",
                "cluster_id":f"{self.server_node_info}>cluster_id",
            })
        elif phase == "config":
            self.conf_store_keys.update({
                
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

    def _create_config_backup(self):
        if os.path.exists("/etc/csm"):
            Log.info("Creating backup for older csm configurations")
            CSMWeb._run_cmd(f"cp -r /etc/csm /etc/csm_{str(datetime.now()).replace(' ','T').split('.')[0]}_bkp")
        else:
            os.makedirs("/etc/csm", exist_ok=True)
            CSMWeb._run_cmd("cp -r /opt/seagate/cortx/csm/conf/etc/csm /etc/csm")

    def post_install(self):
        """ Performs post install operations. Raises exception on error """
        #TODO: validate nodejs installed
        self._validate_cortxcli()
        print("_validate_cortxcli done")
        if self.is_cortxcli_installed:
            CSMWeb._run_cmd(f"cli_setup post_install --config {self.conf_url}")
        self._prepare_and_validate_confstore_keys("post_install")
        print("_prepare_and_validate_confstore_keys done")
        self._set_deployment_mode()
        print("_set_deployment_mode done")
        self._set_service_user()
        print("_set_service_user done")
        self._config_user()
        print("_config_user done")
        self._configure_service_user()
        print("_configure_service_user done")
        self._allow_access_to_pvt_ports()
        print("_allow_access_to_pvt_ports done")
        self.create()
        return 0

    def prepare(self):
        """ Performs post install operations. Raises exception on error """
        
        return 0

    def config(self):
        """ Performs configurations. Raises exception on error """
        
        return 0

    def init(self):
        """ Perform initialization. Raises exception on error """
        
        return 0


    def pre_upgrade(self):
        """ Performs Pre upgrade functionalitied. Raises exception on error """

        # TODO: Perform actual steps. Obtain inputs using Conf.get(index, ..)
        return 0

    def post_upgrade(self):
        """ Performs Post upgrade functionalitied. Raises exception on error """
        self._create_config_backup()
        #self.validate_pkgs()
        self.post_install()
        self.prepare()
        self.config()
        self.init()
        return 0

    def test(self, plan):
        """ Perform configuration testing. Raises exception on error """

        # TODO: Perform actual steps. Obtain inputs using Conf.get(index, ..)
        return 0

    def reset(self):
        """ Performs Configuraiton reset. Raises exception on error """

        # TODO: Perform actual steps. Obtain inputs using Conf.get(index, ..)
        return 0

    def create(self):
        """
        This Function Creates the CSM Conf File on Required Location.
        :return:
        """
        pass

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
            Log.info("Creating CSM User without password.")
            CSMWeb._run_cmd((f"useradd -M {self._user}"))
            Log.info("Adding CSM User to Wheel Group.")
            CSMWeb._run_cmd(f"usermod -aG wheel {self._user}")
            Log.info("Enabling nologin for CSM user.")
            CSMWeb._run_cmd(f"usermod -s /sbin/nologin {self._user}")
            if not self._is_user_exist():
                Log.error("Csm User Creation Failed.")
                raise CSMWebSetupError(rc=-1, message=f"Unable to create {self._user} user")
        else:
            Log.info(f"User {self._user} already exist")
            
    def _configure_service_user(self):
        """
        Configures the Service user in CSM service files.
        :return:
        """
        self._update_csm_web_file("<USER>", self._user)
        
    def _update_csm_web_file(self, key, value):
        """
        Update CSM Files Depending on Job Type of Setup.
        """
        Log.info(f"Update file for {key}:{value}")
        service_file_data = Text(self.CSM_WEB_FILE).load()
        if not service_file_data:
            Log.warn(f"File {self.CSM_WEB_FILE} not updated.")            
        data = service_file_data.replace(key, value)
        Text(self.CSM_WEB_FILE).dump(data)
        
    def _allow_access_to_pvt_ports(self):
        Log.info("Binding low ports to start a service as non-root")
        CSMWeb._run_cmd("setcap CAP_NET_BIND_SERVICE=+ep /opt/nodejs/node-v12.13.0-linux-x64/bin/node")