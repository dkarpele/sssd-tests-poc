import pytest

from lib.multihost import KnownTopology, KnownTopologyGroup
from lib.multihost.roles import AD, IPA, LDAP, Client, GenericADProvider, \
    GenericProvider, Samba


@pytest.mark.topology(KnownTopology.LDAP)
def test_01(ldap: LDAP):
    assert ldap.role == 'ldap'


@pytest.mark.topology(KnownTopology.LDAP)
def test_02(client: Client, ldap: LDAP):
    ldap.user(name='tuser').add()
    client.sssd.start()
    client.host.exec('id tuser')
    result = client.tools.id('tuser')
    assert 'tuser' in client.host.exec('id tuser | grep tuser').stdout
    assert result is not None
    assert result.user.name == 'tuser'


@pytest.mark.topology(KnownTopology.LDAP)
def test_03(client: Client, ldap: LDAP):
    ldap.user(name='tuser').add(uid=10001, gid=10001)
    client.sssd.start()
    result = client.tools.id(name='tuser')
    assert result is not None
    assert result.user.name == 'tuser'
    assert result.user.id == 10001
    assert result.group.id == 10001
    assert result.group.name is None


@pytest.mark.topology(KnownTopology.LDAP)
def test_04(client: Client, ldap: LDAP):
    ldap.user(name='tuser').add(uid=10001, gid=10001)
    ldap.group(name='tuser').add(gid=10001)
    client.sssd.start()
    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'
    assert result.user.id == 10001
    assert result.group.name == 'tuser'
    assert result.group.id == 10001


@pytest.mark.topology(KnownTopology.LDAP)
def test_05(client: Client, ldap: LDAP):
    u = ldap.user(name='tuser').add(uid=10001, gid=10001)
    ldap.group(name='tuser').add(gid=10001)
    ldap.group(name='users').add(gid=20001).add_member(u)

    client.sssd.start()
    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'
    assert result.user.id == 10001
    assert result.group.name == 'tuser'
    assert result.group.id == 10001
    assert result.memberof('users')


@pytest.mark.topology(KnownTopology.LDAP)
def test_06(client: Client, ldap: LDAP):
    u = ldap.user(name='tuser').add(uid=10001, gid=10001)
    ldap.group(name='tuser').add(gid=10001)
    ldap.group(name='users').add().add_member(u)
    ldap.group(name='admins').add().add_member(u)
    client.sssd.start()

    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'
    assert result.user.id == 10001
    assert result.group.name == 'tuser'
    assert result.group.id == 10001
    assert result.memberof(['users', 'admins'])


@pytest.mark.topology(KnownTopology.LDAP)
def test_07(client: Client, ldap: LDAP):
    ldap.user(name='tuser').add(password='Secret123')
    client.sssd.start()

    assert client.auth.su.password('tuser', 'Secret123')


@pytest.mark.topology(KnownTopology.LDAP)
def test_08(client: Client, ldap: LDAP):
    ldap.user(name='tuser').add(password='Secret123')
    client.sssd.start()

    assert client.auth.ssh.password('tuser', 'Secret123')


@pytest.mark.topology(KnownTopology.LDAP)
def test_08(client: Client, ldap: LDAP):
    ldap.user(name='tuser').add(password='Secret123')
    client.sssd.start()

    assert client.auth.ssh.password('tuser', 'Secret123')


@pytest.mark.parametrize('method', ['su', 'ssh'])
@pytest.mark.topology(KnownTopology.LDAP)
def test_09(client: Client, ldap: LDAP, method: str):
    ldap.user(name='tuser').add(password='Secret123')
    client.sssd.start()

    assert client.auth.parametrize(method).password('tuser', 'Secret123')


@pytest.mark.topology(KnownTopology.LDAP)
def test_10(client: Client, ldap: LDAP):
    u = ldap.user(name='tuser').add(password='Secret123')
    ldap.sudorule(name='allow_ls').add(user=u, command='/bin/ls', host='ALL')
    client.authselect.select('sssd', ['with-sudo'])
    client.sssd.enable_responder('sudo')
    client.sssd.start()

    assert client.auth.sudo.list('tuser', 'Secret123', expected=['(root) /bin/ls'])
    assert client.auth.sudo.run('tuser', 'Secret123', command='/bin/ls /root')


@pytest.mark.topology(KnownTopology.LDAP)
def test_11(client: Client, ldap: LDAP, method: str):
    u = ldap.user(name='tuser')
    ldap.sudorule(name='allow_ls').add(user=u, command='/bin/ls', host='ALL',
                                       nopasswd=True)
    client.authselect.select('sssd', ['with-sudo'])
    client.sssd.enable_responder('sudo')
    client.sssd.start()

    assert client.auth.sudo.list('tuser',
                                 expected=['(root) NOPASSWD: /bin/ls'])
    assert client.auth.sudo.run('tuser', command='/bin/ls /root')


@pytest.mark.topology(KnownTopology.LDAP)
def test_12(client: Client, ldap: LDAP):
    ldap.user(name='tuser').add()
    import pdb; pdb.set_trace()
    client.sssd.domain['use_fully_qualified_names'] = 'false'
    client.sssd.section('kcm').update({'debug_level': '0xfff0'})
    client.sssd.start()

    assert client.tools.id('tuser') is None
    assert client.tools.id('tuser@test') is not None


@pytest.mark.topology(KnownTopology.LDAP)
def test_13(client: Client, ldap: LDAP, method: str):
    ldap.user(name='tuser').add()

    with pytest.raises(Exception):
        client.sssd.domain['use_fully_qualified_name'] = 'true'
        client.sssd.start()


@pytest.mark.topology(KnownTopology.LDAP)
def test_14(client: Client, ldap: LDAP, method: str):
    u = ldap.user(name='tuser').add(uid=10001, gid=10001)
    ldap.group(name='tuser', rfc2307bis=True).add(gid=10001)
    ldap.group(name='users', rfc2307bis=True).add().add_member(u)
    ldap.group(name='admins', rfc2307bis=True).add().add_member(u)
    client.sssd.domain['ldap_schema'] = 'rfc2307bis'
    client.sssd.start()

    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'
    assert result.user.id == 10001
    assert result.group.name == 'tuser'
    assert result.group.id == 10001
    assert result.memberof(['users', 'admins'])


@pytest.mark.topology(KnownTopology.IPA)
def test_15(client: Client, ipa: IPA):
    pass


@pytest.mark.topology(KnownTopology.IPA)
def test_16(client: Client, ipa: IPA):
    ipa.user(name='tuser').add()
    client.sssd.start()

    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'


@pytest.mark.topology(KnownTopology.IPA)
def test_17(client: Client, ipa: IPA):
    ipa.user(name='tuser').add(uid=10001, gid=10001)
    client.sssd.start()

    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'
    assert result.user.id == 10001
    assert result.group.name == 'tuser'
    assert result.group.id == 10001


@pytest.mark.topology(KnownTopology.IPA)
def test_18(client: Client, ipa: IPA):
    u = ipa.user(name='tuser').add(uid=10001, gid=10001)
    ipa.group(name='users').add(gid=20001).add_member(u)
    client.sssd.start()

    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'
    assert result.user.id == 10001
    assert result.group.name == 'tuser'
    assert result.group.id == 10001
    assert result.memberof('users')


@pytest.mark.topology(KnownTopology.IPA)
def test_19(client: Client, ipa: IPA):
    u = ipa.user(name='tuser').add(uid=10001, gid=10001)
    ipa.group(name='users').add().add_member(u)
    ipa.group(name='admins').add_member(u)
    client.sssd.start()

    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'
    assert result.user.id == 10001
    assert result.group.name == 'tuser'
    assert result.group.id == 10001
    assert result.memberof(['users', 'admins'])


@pytest.mark.topology(KnownTopology.IPA)
def test_20(client: Client, ipa: IPA):
    u = ipa.user(name='tuser').add(password='Secret123')
    client.sssd.start()

    assert client.auth.su.password('tuser', 'Secret123')


@pytest.mark.topology(KnownTopology.IPA)
def test_21(client: Client, ipa: IPA):
    u = ipa.user(name='tuser').add(password='Secret123')
    client.sssd.start()

    assert client.auth.ssh.password('tuser', 'Secret123')


@pytest.mark.parametrize('method', ['su', 'ssh'])
@pytest.mark.topology(KnownTopology.IPA)
def test_22(client: Client, ipa: IPA, method: str):
    u = ipa.user(name='tuser').add(password='Secret123')
    client.sssd.start()

    assert client.auth.parametrize(method).password('tuser', 'Secret123')


@pytest.mark.parametrize('method', ['su', 'ssh'])
@pytest.mark.topology(KnownTopology.IPA)
def test_23(client: Client, ipa: IPA, method: str):
    u = ipa.user(name='tuser').add(password='Secret123')
    ipa.sudorule(name='allow_ls').add(user=u, command='/bin/ls', host='ALL')
    client.authselect.select('sssd', ['with-sudo'])
    client.sssd.enable_responder('sudo')
    client.sssd.start()

    assert client.auth.sudo.list('tuser', 'Secret123',
                                 expected=['(root) /bin/ls'])
    assert client.auth.sudo.run('tuser', 'Secret123', command='/bin/ls /root')


@pytest.mark.topology(KnownTopology.IPA)
def test_24(client: Client, ipa: IPA, method: str):
    u = ipa.user(name='tuser').add(password='Secret123')
    ipa.sudorule(name='allow_ls').add(user=u, command='/bin/ls', host='ALL',
                                      nopasswd=True)
    client.authselect.select('sssd', ['with-sudo'])
    client.sssd.enable_responder('sudo')
    client.sssd.start()

    assert client.auth.sudo.list('tuser', expected=['(root) NOPASSWD: /bin/ls'])
    assert client.auth.sudo.run('tuser', command='/bin/ls /root')


@pytest.mark.topology(KnownTopology.IPA)
def test_25(client: Client, ipa: IPA):
    u = ipa.user(name='tuser').add()
    import pdb
    client.sssd.domain['use_fully_qualified_names'] = 'true'
    pdb.set_trace()
    client.sssd.start()

    assert client.tools.id('tuser') is None
    assert client.tools.id('tuser@test') is not None


@pytest.mark.topology(KnownTopology.IPA)
def test_26(client: Client, ipa: IPA):
    ipa.user(name='tuser').add()

    with pytest.raises(Exception):
        client.sssd.domain['use_fully_qualified_name'] = 'true'
        client.sssd.start()


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.topology(KnownTopology.AD)
def test_27(client: Client, provider: GenericProvider):
    u = provider.user(name='tuser').add()
    provider.group(name='tgroup_1').add().add_member(u)
    provider.group(name='tgroup_2').add().add_member(u)
    client.sssd.start()

    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'
    assert result.memberof(['tgroup_1', 'tgroup_2'])


@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.topology(KnownTopology.AD)
def test_28(client: Client, provider: GenericProvider):
    provider.user(name='tuser').add()
    client.sssd.start()
    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'
    assert result.memberof(['domain users'])
    assert result.group.name.lower() == 'domain users'


@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.LDAP)
def test_29(client: Client, provider: GenericProvider):
    provider.user(name='tuser').add(uid=10001, gid=10001)
    if provider.role == 'ldap':
        provider.group('tuser').add(gid=10001)

    client.sssd.start()
    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'
    assert result.user.id == 10001
    assert result.group.name == 'tuser'
    assert result.group.id == 10001


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_30(client: Client, provider: GenericProvider):
    u = provider.user('tuser').add()
    provider.sudorule('defaults').add(nopasswd=True)
    provider.sudorule('allow_all').add(user='ALL', host='ALL', command='ALL')
    client.authselect.select('sssd', ['with-sudo'])
    client.sssd.enable_responder('sudo')
    client.sssd.start()

    assert client.auth.sudo.list('tuser', expected=['(root) ALL'])
    assert client.auth.sudo.run('tuser', command='/bin/ls /root')


@pytest.mark.parametrize('method', ['su', 'ssh'])
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_31(client: Client, provider: GenericProvider, method: str):
    u = provider.user('tuser').add(password='Secret123')
    client.sssd.start()

    assert client.auth.parametrize(method).password('tuser', 'Secret123')
