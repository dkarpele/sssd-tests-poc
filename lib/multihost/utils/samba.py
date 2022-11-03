from __future__ import annotations

import configparser
import subprocess
from io import StringIO
from random import randint
from typing import TYPE_CHECKING

from ..host import BaseHost
from .base import MultihostUtility

if TYPE_CHECKING:
    from ..command import RemoteCommandResult
    from .fs import HostFileSystem
    from .service import HostService


class HostSamba(MultihostUtility):
    """
    Manage Samba on remote host.

    All changes are automatically reverted when a test is finished.
    """

    def __init__(self, host: BaseHost, fs: HostFileSystem, svc: HostService,
                 load_config: bool = False) -> None:
        super().__init__(host)
        self.fs = fs
        self.svc = svc
        self.config = configparser.ConfigParser(interpolation=None)
        self.default_domain = None
        self.__load_config = load_config

    def setup(self) -> None:
        """
        Setup Samba on the host.

        - override systemd unit to disable burst limiting, otherwise we will be
          unable to restart the service frequently
        - reload systemd to apply change to the unit file
        - load configuration from the host (if requested in constructor) or set
          default configuration otherwise

        :meta private:
        """
        # Disable burst limiting to allow often samba restarts for tests
        self.fs.mkdir('/etc/systemd/system/samba.service.d')
        self.fs.write('/etc/systemd/system/samba.service.d/override.conf', '''
            [Unit]
            StartLimitIntervalSec=0
            StartLimitBurst=0
        ''')
        self.svc.reload_daemon()

        if self.__load_config:
            self.config_load()
            return

        # Set default configuration
        self.config.read_string('''
            [global]
            server string = Samba Server
        ''')

    def start(
        self,
        service='smb',
        *,
        raise_on_error: bool = True,
        wait: bool = True,
        apply_config: bool = True,
        check_config: bool = True,
        debug_level: str | None = '4'
    ) -> RemoteCommandResult:
        """
        Start Samba service.

        :param service: Service to start, defaults to 'samba'
        :type service: str, optional
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param wait: Wait for the command to finish, defaults to True
        :type wait: bool, optional
        :param apply_config: Apply current configuration, defaults to True
        :type apply_config: bool, optional
        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value,
         defaults to 4
        :type debug_level: str | None, optional
        :return: Remote command result.
        :rtype: RemoteCommandResult
        """
        if apply_config:
            self.config_apply(check_config=check_config,
                              debug_level=debug_level)

        return self.svc.start(service,
                              raise_on_error=raise_on_error,
                              wait=wait)

    def stop(self,
             service='smb',
             *,
             raise_on_error: bool = True,
             wait: bool = True) -> RemoteCommandResult:
        """
        Stop Samba service.

        :param service: Service to start, defaults to 'samba'
        :type service: str, optional
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param wait: Wait for the command to finish, defaults to True
        :type wait: bool, optional
        :return: Remote command result.
        :rtype: RemoteCommandResult
        """
        return self.svc.stop(service, raise_on_error=raise_on_error, wait=wait)

    def restart(
        self,
        service='smb',
        *,
        raise_on_error: bool = True,
        wait: bool = True,
        apply_config: bool = True,
        check_config: bool = True,
        debug_level: str | None = '4'
    ) -> RemoteCommandResult:
        """
        Restart Samba service.

        :param service: Service to start, defaults to 'samba'
        :type service: str, optional
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param wait: Wait for the command to finish, defaults to True
        :type wait: bool, optional
        :param apply_config: Apply current configuration, defaults to True
        :type apply_config: bool, optional
        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value,
        defaults to 4
        :type debug_level:  str | None, optional
        :return: Remote command result.
        :rtype: RemoteCommandResult
        """
        if apply_config:
            self.config_apply(check_config=check_config,
                              debug_level=debug_level)

        return self.svc.restart(service,
                                raise_on_error=raise_on_error,
                                wait=wait)

    def clear(self, *,
              db: bool = True,
              config: bool = False,
              logs: bool = False):
        """
        Clear Samba data.

        :param db: Remove cache and database, defaults to True
        :type db: bool, optional
        :param config: Remove configuration files, defaults to False
        :type config: bool, optional
        :param logs: Remove logs, defaults to False
        :type logs: bool, optional
        """
        cmd = 'rm -fr'

        if db:
            cmd += ' /var/lib/samba/lock/msg.lock'

        if config:
            cmd += ' /etc/samba/*.conf /etc/samba/lmhosts'

        if logs:
            cmd += ' /var/log/samba/*'

        self.host.exec(cmd)

    def config_dumps(self) -> str:
        """
        Get current Samba configuration.

        :return: Samba configuration.
        :rtype: str
        """
        return self.__config_dumps(self.config)

    def config_load(self) -> None:
        """
        Load remote Samba configuration.
        """
        result = self.host.exec(['cat', '/etc/samba/smb.conf'],
                                log_stdout=False)
        self.config.clear()
        self.config.read_string(result.stdout)

    def config_apply(self,
                     check_config: bool = True,
                     debug_level: str | None = '4') -> None:
        """
        Apply current configuration on remote host.

        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value,
        defaults to 4
        :type debug_level: str | None, optional
        """
        cfg = self.__set_debug_level(debug_level)
        contents = self.__config_dumps(cfg)
        self.fs.write('/etc/samba/smb.conf', contents, mode='0600')

        if check_config:
            self.host.exec('testparm -s')

    def share(self, name: str = None, path: str = None):
        rand = randint(1000, 10000)
        if not name:
            name = f'share-{rand}'
        if not path:
            path = f'/tmp/{name}'

        self.fs.mkdir_p(path)

        selinux_context = \
            f'chcon unconfined_u:object_r:samba_share_t:s0 {path}'
        # Skip applying selinux content if selinux is disabled
        try:
            self.host.exec(selinux_context)
        except subprocess.CalledProcessError:
            pass

        # Initialize share with default values
        default_value = {'path': path,
                         'comment': f'test share {name}',
                         'browseable': 'yes',
                         'writable': 'yes',
                         'printable': 'no',
                         'read only': 'no'}
        self.section(name).update(default_value)

    def smbclient(self,
                  host: str = 'localhost',
                  section: str = None,
                  command: str = None,
                  user: str = None,
                  password: str = None):
        self.host.exec(f"smbclient '//{host}/{section}' -c "
                       f"'{command}'"
                       f" -U {user}%{password}")

    def section(self, name: str) -> dict[str, str]:
        """
        Get smb.conf section.

        :param name: Section name.
        :type name: str
        :return: Section configuration object.
        :rtype: dict[str, str]
        """
        return self.__get(name)

    @property
    def global_(self) -> dict[str, str]:
        """
        Default global section configuration object.

        :raises ValueError: If global isn't set.
        :return: Section configuration object.
        :rtype: dict[str, str]
        """
        if self.default_domain is None:
            raise ValueError(f'{self.__class__}.default_domain is not set')

        return self.section('global')

    @global_.setter
    def global_(self, value: dict[str, str]) -> None:
        if self.default_domain is None:
            raise ValueError(f'{self.__class__}.default_domain is not set')

        self.config['global'] = value

    @global_.deleter
    def global_(self) -> None:
        if self.default_domain is None:
            raise ValueError(f'{self.__class__}.default_domain is not set')

        del self.config['global']

    def __get(self, section: str) -> dict[str, str]:
        self.config.setdefault(section, {})
        return self.config[section]

    def __set(self, section: str, value: dict[str, str]) -> None:
        self.config[section] = value

    def __del(self, section: str) -> None:
        del self.config[section]

    @staticmethod
    def __config_dumps(cfg: configparser) -> str:
        """ Convert configparser to string. """
        with StringIO() as ss:
            cfg.write(ss)
            ss.seek(0)
            return ss.read()

    def __set_debug_level(self, debug_level: str | None = None) -> \
            configparser:
        cfg = configparser.ConfigParser()
        cfg.read_dict(self.config)

        if debug_level is None:
            return self.cfg

        sections = ['global']

        cfg.setdefault(sections[0], {})
        if 'log level' not in cfg[sections[0]]:
            cfg[sections[0]]['log level'] = debug_level

        return cfg

    def user(self, name: str) -> SambaUser:
        """
        Get user object.

        :param name: User name.
        :type name: str
        :return: New user object.
        :rtype: SambaUser
        """
        return SambaUser(self.host, name)


class SambaUser(MultihostUtility):
    def __init__(self, host: BaseHost, name: str) -> None:
        super().__init__(host)
        self.name = name

    def add(self, password: str = 'Secret123'):
        cmd = f'echo -e "{password}\n{password}" | smbpasswd -s -a {self.name}'
        try:
            self.host.exec(cmd)
        except subprocess.CalledProcessError:
            raise ValueError(f'User {self.name} can\'t be added')

    def delete(self):
        try:
            self.host.exec(f'smbpasswd -x {self.name}')
        except subprocess.CalledProcessError:
            raise ValueError(f'User {self.name} can\'t be deleted')
