from __future__ import annotations

from typing import TYPE_CHECKING

from ..host import MultihostHost
from ..utils.automount import HostAutomount
from ..utils.local_users import HostLocalUsers
from ..utils.sssd import HostSSSD
from ..utils.samba import HostSamba
from ..ssh import SSHProcessError
from .base import LinuxRole

if TYPE_CHECKING:
    from ..multihost import Multihost


class Client(LinuxRole):
    def __init__(self, mh: Multihost, role: str, host: MultihostHost) -> None:
        super().__init__(mh, role, host)
        self.sssd: HostSSSD = HostSSSD(host, self.fs, self.svc, load_config=False)
        """
        SSSD management.
        """

        self.automount: HostAutomount = HostAutomount(host, self.svc)
        """
        API for automount testing.
        """

        self.samba: HostSamba = HostSamba(host, self.fs, self.svc,
                                          load_config=False)
        """
        Samba management.
        """

        self.local: HostLocalUsers = HostLocalUsers(host)
        """
        API for local users and groups.
        """

    def setup(self) -> None:
        """
        Setup client host:

        #. stop sssd
        #. clear sssd cache, logs and configuration
        #. import implicit domains from topology marker
        """
        super().setup()
        self.sssd.stop()
        self.sssd.clear(db=True, logs=True, config=True)

        for domain, path in self.mh.data.topology_mark.domains.items():
            self.sssd.import_domain(domain, self.mh._lookup(path))

        # If samba isn't installed on the client, don't need to stop it
        try:
            self.samba.stop()
            self.samba.clear(db=True, logs=True, config=True)
        except SSHProcessError:
            pass
