"""Support functionality needed to communicate with OnRamp REST clients,
administer system users, and launch parallel jobs.

Exports:
    get_visible_file: Verify access allowed to requested file and return it.
    module_log: Log a message to one of the log/onramp_*.log files in a module.
    launch_job: Launch a parallel job on system. DEPRECATED.
    encrypt: Encrypt a message. DEPRECATED.
    decrypt: Decript a message. DEPRECATED.
    create_admin: Create admin user with default settings. DEPRECATED.
    authenticate: Authenticate a user. DEPRECATED.
    admin_authenticate: Authenticate an admin user. DEPRECATED.
    modules: Functionality for working with OnRamp educational modules. DEPRECATED.
"""

import glob
import hashlib
import json
import logging
import os
import requests
from datetime import datetime
from subprocess import CalledProcessError, call, check_output

from configobj import ConfigObj
from Crypto import Random
from Crypto.Cipher import AES

from PCEHelper import pce_root

def get_visible_file(dirs):
    """Verify access allowed to requested file and return it.

    Args:
        dirs (list of str): Ordered list of folder names between base_dir
            (currently onramp/pce/users) and specific file.

    Returns:
        Tuple consisting of error code and either the requested file if no error
        or string indicating cause of error.
    """
    num_parent_dirs = 3
    if len(dirs) <= num_parent_dirs or '..' in dirs:
        return (-4, 'Bad request')

    run_dir = os.path.join(os.path.join(pce_root, 'users'),
                           '/'.join(dirs[:num_parent_dirs]))
    filename = os.path.join(run_dir, '/'.join(dirs[num_parent_dirs:]))

    cfg_file = os.path.join(run_dir, 'config/onramp_metadata.cfg')
    try:
        conf = ConfigObj(cfg_file, file_error=True)
    except (IOError, SyntaxError):
        return (-3, 'Badly formed or non-existant config/onramp_metadata.cfg') 

    if 'onramp' in conf.keys() and 'visible' in conf['onramp'].keys():
        globs = conf['onramp']['visible']
        if isinstance(globs, basestring):
            # Globs is only a single string. Convert to list.
            globs = [globs]
    else:
        globs = []


    if not os.path.isfile(filename):
        return (-2, 'Requested file not found') 

    for entry in globs:
        if filename in glob.glob(os.path.join(run_dir, entry)):
            return (0, open(os.path.join(run_dir, filename), 'r'))

    return (-1, 'Requested file not configured to be visible')

def module_log(mod_root, log_id, msg):
    """Log a message to one of the log/onramp_*.log files in a module.

    Overwrite existing log entry if any. Prefix message with preamble,
    timestamp, and blank line.

    Args:
        mod_root (str): Absolute path of module root folder.
        log_id (str): Determines logfile to use: log/onramp_{log_id}.log.
        msg (str): Message to be logged.
    """
    logname = os.path.join(mod_root, 'log/onramp_%s.log' % log_id)
    with open(logname, 'w') as f:
        f.write('The following output was logged %s:\n\n' % str(datetime.now()))
        f.write(msg)

# The stdlib's ssl module has some limitations which are adressed by PyOpenSSL.
# The following gets the requests lib to get the urllib3 lib to use PyOpenSSL
# bindings instead.
#
# Reference: https://urllib3.readthedocs.org/en/latest/security.html#pyopenssl
requests.packages.urllib3.contrib.pyopenssl.inject_into_urllib3()

def get_requests_err_msg(ex):
    """Return a sensible error message from a requests lib SSLError.

    Some (all?) exceptions from the requests lib do not stick to typical
    exception attrs (https://github.com/kennethreitz/requests/issues/3004),
    thus, this is needed.
    """
    error_number = None
    current_error = ex
    while isinstance(current_error, Exception) and error_number is None:
        error_number = getattr(current_error, 'errno', None)
        current_error = current_error.args[0]

    return current_error


class PCEClient():
    """Client-side interface to OnRamp PCE server.

    Methods:
        get_modules_avail: Return the list of modules that are available at the
            PCE but not currently installed.
        get_modules: Return the list of modules that are available at the PCE
            but not currently installed. (or a specific ID)
        add_module: Install given module on this PCE.
        deploy_module: Initiate module deployment actions.
        delete_module: Delete given module from PCE.
        get_jobs: Return the requested jobs.
        launch_job: Initiate job launch.
        delete_job: Delete given job from PCE.
        retrieve_cert: Retrieve, via SSH, the SSL certificate used by the given
            PCE.
        register_client: Register, using PCEClient instance attrs, a PCE user on
            the PCE.
    """
    _name = "[PCEClient] "
    _cert_dir = "src/certs"
    
    def __init__(self, logger, cert_dir, pce_hostname, pce_port, pce_id,
    			 servername, username, password):
        """Initialize PCEClient instance.

        Args:
            logger (logging.Logger): Logger for instance to use.
            dbaccess (onrampdb.DBAccess): Interface to server DB.
            pce_id (int): Id of PCE instance should provide interface to. Must
                exist in DB provided by dbaccess.
        """
        self._logger = logger
        self._cert_dir = cert_dir
        self._pce_id = int(pce_id)
        self._servername = servername
        self._username = username
        self._password = password
        self._url = "https://%s:%d" % (pce_hostname, pce_port)

    def _pce_get(self, endpoint, **kwargs):
        """Execute GET request to PCE endpoint.

        Args:
            endpoint (str): API URL endpoint for request. Must not have leading
                or trailing slashes.
            raw (bool): If True, return raw response, else return JSON portion
                of response only.

        Kwargs:
            Key/val pairs in kwargs will become key/val pairs included as HTTP
            query paramaters in the request.

        Returns:
            JSON response object on success, 'None' on error.
        """
        s = requests.Session()
        url = "%s/%s/" % (self._url, endpoint)
        credentials = {
            'servername': self._servername,
            'username': self._username,
            'password': self._password
        }

        try:
            r = s.get(url, params=kwargs, verify=self._get_cert_filename(),
                      auth=(json.dumps(credentials),''))
        except requests.exceptions.SSLError as e:
            msg = get_requests_err_msg(e)
            if msg.startswith('bad ca_certs'):
                return self._build_status_from_err(msg)
            raise

        if r.status_code != 200:
            err_msg = ('%s Error: %d from GET %s: %s'
                       % (self._name, r.status_code, url, r.text))
            self._logger.error('%s Error: %d from GET %s: %s'
                               % (self._name, r.status_code, url, r.text))
            return {'status_code': -11, 'status_msg': err_msg}
        else:
            return r.json()

    def _pce_post(self, endpoint, **kwargs):
        """Execute JSON-formatted POST request to PCE endpoint.

        Args:
            endpoint (str): API URL endpoint for request. Must not have leading
                or trailing slashes.
            raw (bool): If True, return raw response, else return JSON portion
                of response only.

        Kwargs:
            Key/val pairs in kwargs will be included as JSON key/val pairs in
            the request body.

        Returns:
            'True' if request was successfully processed by RXing PCE, 'False'
            if not.
        """
        s = requests.Session()
        url = "%s/%s/" % (self._url, endpoint)
        data = json.dumps(kwargs)
        headers = {"content-type": "application/json"}
        credentials = {
            'servername': self._servername,
            'username': self._username,
            'password': self._password
        }

        try:
            r = s.post(url, data=data, headers=headers,
                       verify=self._get_cert_filename(),
                       auth=(json.dumps(credentials),''))
        except requests.exceptions.SSLError as e:
            msg = get_requests_err_msg(e)
            if msg.startswith('bad ca_certs'):
                return self._build_status_from_err(msg)
            raise

        if r.status_code != 200:
            self._logger.error('%s Error: %d from POST %s: %s'
                               % (self._name, r.status_code, url, r.text))
            return False

        response = r.json()

        if ((not response) or ('status_code' not in response.keys())
            or (0 != response['status_code'])):
            return False

        return True

    def _pce_delete(self, endpoint):
        """Execute DELETE request to PCE endpoint.

        Args:
            endpoint (str): API URL endpoint for request. Must not have leading
                or trailing slashes.
        Returns:
            'True' if request was successfully processed by RXing PCE, 'False'
            if not.
        """
        s = requests.Session()
        url = "%s/%s/" % (self._url, endpoint)
        credentials = {
            'servername': self._servername,
            'username': self._username,
            'password': self._password
        }

        try:
            r = s.delete(url, verify=self._get_cert_filename(),
                         auth=(json.dumps(credentials),''))
        except requests.exceptions.SSLError as e:
            msg = get_requests_err_msg(e)
            if msg.startswith('bad ca_certs'):
                return self._build_status_from_err(msg)
            raise

        if r.status_code != 200:
            self._logger.error('%s Error: %d from DELETE %s: %s'
                               % (self._name, r.status_code, url, r.text))
            return False
        else:
            response = r.json()
            if ((not response) or ('status_code' not in response.keys())
                or (0 != response['status_code'])):
                return False
            return True

    def _build_status_from_err(self, msg):
        """Build and log requests SSLError response.

        Some (all?) exceptions from the requests lib do not stick to typical
        exception attrs (https://github.com/kennethreitz/requests/issues/3004),
        thus, this is needed.

        Args:
            msg (str): requests SSLError message returned from
                get_requests_err_msg().

        Returns:
            Minimal OnRamp-style JSON response object containing only status
            info.
        """
        errno = -10
        errmsg = 'SSL Certificate Error'
        missing_filename = msg.split("bad ca_certs: '")[1].split("'")[0]
        self._logger.error('%s Error: %s: File: %s'
                           % (self._name, errmsg, missing_filename))
        return {'status_code': errno, 'status_msg': errmsg}

    def _get_cert_filename(self):
        """Return the filename of the SSL certificate to be used by the
        instance.
        """
        return os.path.join(self._cert_dir, '%d.crt' % self._pce_id)

    def get_url(self):
        return self._url

    def retrieve_cert(self, hostname, ssh_port, unix_user, unix_password,
               onramp_base_dir=None):
        """Retrieve, via SSH, the SSL certificate used by the given PCE.

        Supports both password and pubkey SSH auth, however, cannot anticipate
        which prior to call, thus, the unix_password arg will be submitted for
        pubkey passphrase if requested, or for the account password if
        requested.

        Upon return, the retrieved SSL cert will be stored with the filename
        returned by self._get_cert_filename().

        Args:
            hostname (str): Hostname/IP of the PCE.
            ssh_port (int): PCE SSH daemon port.
            unix_user (str): Username of account with SSH access to PCE host
                and read access to the PCE OnRamp files.
            unix_password (str): Unix account password or pubkey passphrase for
                unix_user.

        Kwargs:
            onramp_base_dir (str): Root dir of OnRamp installation on PCE. If
                'None', a default of '/home/%s/onramp' % unix_user is used.

        Returns:
            One of the following tuples:
                (0, 'Success')
                (-1, 'Bad onramp_base_dir: Should end with "onramp"')
                (-2, 'Unexpected output when attempting to transfer cert')
                (-3, 'Incorrect username/password given')
                (-4, 'Connection refused')
        """

        if not onramp_base_dir:
            onramp_base_dir = '/home/%s/onramp' % unix_user

        while onramp_base_dir.endswith('/'):
            onramp_base_dir = onramp_base_dir[:-1]
        if not onramp_base_dir.endswith('onramp'):
            return (-1, 'Bad onramp_base_dir: Should end with "onramp"')

        # Retrieve SSL cert from PCE.
        command = ('scp '
            '-o StrictHostKeyChecking=no '
            '-P %d '
            '%s@%s:%s'
            '/pce/src/keys/onramp_pce.crt '
            '%s'
            % (ssh_port, unix_user, hostname, onramp_base_dir,
               self._get_cert_filename())
        )
        child = pexpect.spawn(command)
        result = child.expect(['Password:', 'password:', 'Enter passphrase',
                               'onramp_pce.crt', 'Connection refused'])

        if result in [0,1,2]:
            child.sendline(unix_password)
            result = child.expect(['onramp_pce.crt', 'Password:', 'password:',
                                   'Enter passphrase'])

            if result == 0:
                child.read()
            elif result in [1,2,3]:
                return (-3, 'Incorrect username/password given')
            else:
                return (-2, 'Unexpected output when attempting to transfer cert')

        elif result == 3:
            child.read()
        elif result == 4:
            return (-4, 'Connection refused')

        else:
            return (-2, 'Unexpected output when attempting to transfer cert')

        return (0, 'Success')

    def register_client(self, hostname, ssh_port, unix_user, unix_password,
               onramp_base_dir=None):
        """Register, using PCEClient instance attrs, a PCE user on the PCE.

        Supports both password and pubkey SSH auth, however, cannot anticipate
        which prior to call, thus, the unix_password arg will be submitted for
        pubkey passphrase if requested, or for the account password if
        requested.

        Args:
            hostname (str): Hostname/IP of the PCE.
            ssh_port (int): PCE SSH daemon port.
            unix_user (str): Username of account with SSH access to PCE host
                and read access to the PCE OnRamp files.
            unix_password (str): Unix account password or pubkey passphrase for
                unix_user.

        Kwargs:
            onramp_base_dir (str): Root dir of OnRamp installation on PCE. If
                'None', a default of '/home/%s/onramp' % unix_user is used.

        Returns:
            One of the following tuples:
                (0, REGISTERED_AUTH_TOKEN)
                (-1, 'Bad onramp_base_dir: Should end with "onramp"')
                (-2, 'PCE user registration sys error')
                (-3, 'Incorrect connection/auth attrs given')
                (-4, 'Unknown error occured during user registration')
        """

        if not onramp_base_dir:
            onramp_base_dir = '/home/%s/onramp' % unix_user
        while onramp_base_dir.endswith('/'):
            onramp_base_dir = onramp_base_dir[:-1]
        if not onramp_base_dir.endswith('onramp'):
            return (-1, 'Bad onramp_base_dir: Should end with "onramp"')

        child = pxssh.pxssh()
        try:
            child.login(hostname, unix_user, unix_password, port=ssh_port)
            child.sendline('cd %s/pce' % onramp_base_dir)
            child.prompt()
            child.before
            child.sendline('bin/onramp_pce_service.py gentoken'
            result = child.expect([
                'Access token: .*',
                'Exceeded max attempts at token generation',
                'Access token file "src/pce_client.pwd" has been corrupted',
                '.*'
            ])

            if result == 1 or result == 2:
                child.logout()
                return (-2, 'PCE user registration sys error')
            if result == 3:
                child.logout()
                return (-4, 'Unknown error occured during user registration')

            token = child.after.split(token_preamble)[1]

        except pexpect.exceptions.EOF:
            child.logout()
            return (-3, 'Incorrect connection/auth attrs given')
        except pexpect.exceptions.TIMEOUT:
            child.logout()
            return (-4, 'Unknown error occured during user registration')
            
        child.logout()
        return (0, token)

    def get_modules_avail(self):
        """Return the list of modules that are available at the PCE but not
        currently installed.

        Returns:
            List of JSON-formatted module objects. Returns 'None' on error.
        """
        response = self._pce_get("modules", state="Available")
        if (not response) or ("modules" not in response.keys()):
            return None
        return [mod for mod in response["modules"]]

    def get_modules(self, id=None):
        """Return the requested modules.

        Args:
            id (int): Id of the requested module. 'None' to return all modules.

        Returns:
            JSON-formatted module object for given id, or if no id given, list
            of JSON-formatted module objects. Returns 'None' on error.
        """
        url = "modules"
        if id:
            url += "/%d" % id

        response = self._pce_get(url)
        if not response:
            return None

        if id:
            if "module" not in response.keys():
                return None
            return response["module"]

        if "modules" not in response.keys():
            return None
        return [mod for mod in response["modules"]]
            

    def add_module(self, id, module_name, mod_type, mod_path):
        """Install given module on this PCE.

        Args:
            id (int): Id to be given to installed module on PCE.
            module_name (str): Name to be given to installed module on PCE.
            mod_type (str): Type of module source. Currently supported options:
                'local'.
            mod_path (str): Path, formatted as required by given mod_type, of
                the installation source.

        Returns:
            'True' if installation request was successfully processed, 'False'
            if not.
        """
        payload = {
            'mod_id': id,
            'mod_name': module_name,
            'source_location': {
                'type': mod_type,
                'path': mod_path
            }
        }
        return self._pce_post("modules", **payload)

    def deploy_module(self, id):
        """Initiate module deployment actions.

        Args:
            id (int): Id of the installed module to deploy.

        Returns:
            'True' if deployment request was successfully processed, 'False'
            if not.
        """
        endpoint = "modules/%d" % id
        return self._pce_post(endpoint)

    def delete_module(self, id):
        """Delete given module from PCE.

        Args:
            id (int): Id of the module to delete.

        Returns:
            'True' if delete request was successfully processed, 'False'
            if not.
        """
        endpoint = "modules/%d" % id
        return self._pce_delete(endpoint)

    def get_jobs(self, id):
        """Return the requested jobs.

        Args:
            id (int): Id of the requested job. 'None' to return all jobs.

        Returns:
            JSON-formatted job object for given id, or if no id given, list
            of JSON-formatted job objects. Returns 'None' on error.
        """
        url = "jobs/%d" % id

        response = self._pce_get(url)

        if not response:
            return None
        if "job" not in response.keys():
            return None

        return response["job"]


    def launch_job(self, user, mod_id, job_id, run_name, cfg_params=None):
        """Initiate job launch.

        Args:
            user (str): Username of user launching job.
            mod_id (int): Id of the module to run.
            job_id (int): Id to be given to launched job on PCE.
            run_name (str): Human-readable identifier for job.
            cfg_params (dict): Dict containing attrs to be written to
                onramp_runparams.cfg

        Returns:
            'True' if launch request was successfully processed, 'False' if not.
        """
        payload = {
            'username': user,
            'mod_id': mod_id,
            'job_id': job_id,
            'run_name': run_name
        }
        if cfg_params:
            payload['cfg_params'] = cfg_params
        return self._pce_post("jobs", **payload)

    def delete_job(self, id):
        """Delete given job from PCE.

        Args:
            id (int): Id of the job to delete.

        Returns:
            'True' if delete request was successfully processed, 'False'
            if not.
        """
        endpoint = "jobs/%d" % id
        return self._pce_delete(endpoint)

    def ping(self):
        """Ping the given PCE.

        Returns:
            True if able to succesfully connect via HTTP.
            False otherwise.
        """
        endpoint = "cluster/ping"
        result = self._pce_get(endpoint)
        return result['status_code'] == 0
