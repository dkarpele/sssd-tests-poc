from __future__ import annotations

import base64
import textwrap

from ..host import MultihostHost
from ..ssh import SSHLog
from .base import MultihostUtility


class HostFileSystem(MultihostUtility):
    """
    Perform file system operations on remote host.

    All changes are automatically reverted when a test is finished.
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        :param host: Remote host instance.
        :type host: MultihostHost
        """
        super().__init__(host)
        self.__rollback: list[str] = []

    def teardown(self):
        """
        Revert all file system changes.

        :meta private:
        """
        cmd = '\n'.join(reversed(self.__rollback))
        if cmd:
            self.host.ssh.run(cmd)

        super().teardown()

    def mkdir(self, path: str, *, mode: str = None, user: str = None, group: str = None) -> None:
        """
        Create directory on remote host.

        :param path: Path of the directory.
        :type path: str
        :param mode: Access mode (chmod value), defaults to None
        :type mode: str, optional
        :param user: Owner, defaults to None
        :type user: str, optional
        :param group: Group, defaults to None
        :type group: str, optional
        """
        self.backup(path)
        self.logger.info(f'Creating directory "{path}" on {self.host.hostname}')
        self.host.ssh.run(
            f'''
                set -ex
                rm -fr '{path}'
                mkdir '{path}'
                {self.__gen_chattrs(path, mode=mode, user=user, group=group)}
            ''',
            log_level=SSHLog.Error
        )
        self.__rollback.append(f"rm -fr '{path}'")

    def mkdir_p(self, path: str, *, mode: str = None, user: str = None, group: str = None) -> None:
        """
        Create directory on remote host, including all missing parent directories.

        :param path: Path of the directory.
        :type path: str
        :param mode: Access mode (chmod value), defaults to None
        :type mode: str, optional
        :param user: Owner, defaults to None
        :type user: str, optional
        :param group: Group, defaults to None
        :type group: str, optional
        """
        self.backup(path)
        self.logger.info(f'Creating directory "{path}" (with parents) on {self.host.hostname}')
        result = self.host.ssh.run(
            f'''
                set -ex
                rm -fr '{path}'
                mkdir -v -p '{path}' | head -1 | sed -E "s/mkdir:[^']+'(.+)'$/\\1/"
                {self.__gen_chattrs(path, mode=mode, user=user, group=group)}
            ''',
            log_level=SSHLog.Error
        )

        if result.stdout:
            self.__rollback.append(f"rm -fr '{result.stdout}'")

    def mktmp(self, *, mode: str = None, user: str = None, group: str = None) -> str:
        """
        Create temporary file on remote host.

        :param mode: Access mode (chmod value), defaults to None
        :type mode: str, optional
        :param user: Owner, defaults to None
        :type user: str, optional
        :param group: Group, defaults to None
        :type group: str, optional
        :raises OSError: If the file can not be created.
        :return: Temporary file path.
        :rtype: str
        """

        self.logger.info(f'Creating temporary file on {self.host.hostname}')
        result = self.host.ssh.run(
            '''
                set -ex
                tmp=`mktemp /tmp/mh.fs.rollback.XXXXXXXXX`
                echo $tmp
            ''',
            log_level=SSHLog.Error
        )

        tmpfile = result.stdout.strip()
        if not tmpfile:
            raise OSError("Temporary file was not created")

        self.__rollback.append(f"rm --force '{tmpfile}'")

        attrs = self.__gen_chattrs(tmpfile, mode=mode, user=user, group=group)
        if attrs:
            self.host.ssh.run(attrs, log_level=SSHLog.Error)

        return tmpfile

    def read(self, path: str) -> str:
        """
        Read remote file and return its contents.

        :param path: File path.
        :type path: str
        :return: File contents.
        :rtype: str
        """
        self.logger.info(f'Reading file "{path}" on {self.host.hostname}')
        result = self.host.ssh.exec(['cat', path], log_level=SSHLog.Error)

        return result.stdout

    def write(
        self,
        path: str,
        contents: str,
        *,
        mode: str = None,
        user: str = None,
        group: str = None,
        dedent: bool = True,
    ) -> None:
        """
        Write to a remote file.

        :param path: File path.
        :type path: str
        :param contents: File contents to write.
        :type contents: str
        :param mode: Access mode (chmod value), defaults to None
        :type mode: str, optional
        :param user: Owner, defaults to None
        :type user: str, optional
        :param group: Group, defaults to None
        :type group: str, optional
        :param dedent: Automatically dedent and strip file contents, defaults to True
        :type dedent: bool, optional
        """
        if dedent:
            contents = textwrap.dedent(contents).strip()

        self.backup(path)
        self.logger.info(
            f'Writing file "{path}" on {self.host.hostname}',
            extra={'data': {'Contents': contents}}
        )

        self.host.ssh.run(
            f'''
                set -ex
                rm -fr '{path}'
                cat > '{path}'
                {self.__gen_chattrs(path, mode=mode, user=user, group=group)}
            ''',
            input=contents, log_level=SSHLog.Error
        )
        self.__rollback.append(f"rm --force '{path}'")

    def upload(
        self,
        local_path: str,
        remote_path: str,
        *,
        mode: str = None,
        user: str = None,
        group: str = None,
    ) -> None:
        """
        Upload local file.

        :param local_path: Source local path.
        :type local_path: str
        :param remote_path: Destination remote path.
        :type remote_path: str
        :param mode: Access mode (chmod value), defaults to None
        :type mode: str, optional
        :param user: Owner, defaults to None
        :type user: str, optional
        :param group: Group, defaults to None
        :type group: str, optional
        """
        self.backup(remote_path)
        self.logger.info(f'Uploading file "{local_path}" to "{self.host.hostname}:{remote_path}"')
        with open(local_path, 'rb') as f:
            encoded = base64.b64encode(f.read()).decode('utf-8')

        self.host.ssh.run(
            f'''
                set -ex
                rm -fr '{remote_path}'
                base64 --decode > '{remote_path}'
                {self.__gen_chattrs(remote_path, mode=mode, user=user, group=group)}
            ''',
            input=encoded, log_level=SSHLog.Error
        )
        self.__rollback.append(f"rm --force '{remote_path}'")

    def download(self, remote_path: str, local_path: str) -> None:
        """
        Download file from remote host to local machine.

        :param remote_path: Remote path.
        :type remote_path: str
        :param local_path: Local path.
        :type local_path: str
        """
        self.logger.info(f'Downloading file "{remote_path}" from {self.host.hostname} to "{local_path}"')
        result = self.host.ssh.exec(['base64', remote_path], log_level=SSHLog.Error)
        with open(local_path, 'wb') as f:
            f.write(base64.b64decode(result.stdout))

    def download_files(self, paths: list[str], local_path: str) -> None:
        """
        Download multiple files from remote host. The files are stored in single
        gzipped tarball on the local machine. The remote file path may contain
        glob pattern.

        :param paths: List of remote file paths. May contain glob pattern.
        :type paths: list[str]
        :param local_path: Path to the gzipped tarball destination file on local machine.
        :type local_path: str
        """
        self.logger.info(
            f'Downloading files from {self.host.hostname} to "{local_path}"',
            extra={'data': {'Paths': paths}}
        )
        result = self.host.ssh.run(f'''
            tmp=`mktemp /tmp/mh.fs.download_files.XXXXXXXXX`
            tar -czvf "$tmp" {' '.join([f'$(compgen -G "{path}")' for path in paths])} &> /dev/null
            base64 "$tmp"
            rm -f "$tmp" &> /dev/null
        ''', log_level=SSHLog.Error)

        with open(local_path, 'wb') as f:
            f.write(base64.b64decode(result.stdout))

    def backup(self, path: str) -> bool:
        """
        Backup file or directory.

        The path is automatically restored from the backup when a test is finished.

        :param path: Path to back up.
        :type path: str
        :return: True if the path exists and backup was done, False otherwise.
        :rtype: bool
        """
        self.logger.info(f'Creating a backup of "{path}" on {self.host.hostname}')
        result = self.host.ssh.run(f'''
        set -ex

        if [ -f '{path}' ]; then
            tmp=`mktemp /tmp/mh.fs.rollback.XXXXXXXXX`
            cp --force --archive '{path}' "$tmp"
            echo "$tmp"
        elif [ -d '{path}' ]; then
            tmp=`mktemp -d /tmp/mh.fs.rollback.XXXXXXXXX`
            cp --force --archive '{path}/.' "$tmp"
            echo "$tmp"
        fi
        ''', log_level=SSHLog.Error)

        tmpfile = result.stdout.strip()
        if tmpfile:
            self.__rollback.append(f"mv --force '{tmpfile}' '{path}'")
            return True

        return False

    def __gen_chattrs(self, path: str, *, mode: str = None, user: str = None, group: str = None) -> str:
        cmds = []
        if mode is not None:
            cmds.append(f"chmod '{mode}' '{path}'")

        if user is not None:
            cmds.append(f"chown '{user}' '{path}'")

        if group is not None:
            cmds.append(f"chgrp '{group}' '{path}'")

        return ' && '.join(cmds)
