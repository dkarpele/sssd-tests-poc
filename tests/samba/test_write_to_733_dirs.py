import pytest

from lib.multihost import KnownTopology, KnownTopologyGroup
from lib.multihost.roles import Samba, Client


@pytest.mark.topology(KnownTopology.Samba)
def test_01(client: Client, samba: Samba):

    samba.user('tuser').add(password='Secret123')
    samba.fs.mkdir(path='/tmp/test_share')
    client.sssd.section('kcm').update({'debug_level': '0xfff0'})
    import pdb; pdb.set_trace()
    assert samba.role == 'samba'
