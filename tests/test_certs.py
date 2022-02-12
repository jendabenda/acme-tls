import subprocess
import socket
import tempfile
import os
import ssl
import json
import time
import signal
import grp
from multiprocessing import Process
from urllib.request import urlopen, Request
from urllib.error import URLError

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization as crypto_serialization, hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import mockdns


# turn on docker_compose plugin
pytest_plugins = ['docker_compose']

# networking
localhost = '::1'
pebble_port = 14000
pebble_management_port = 14001
pebble_wrong_port = 14002
mockdns_port = 14053
acme_tls_port = 14443

# pebble endpoints
pebble_url = f'https://[{localhost}]:{pebble_port}'
pebble_management_url = f'https://[{localhost}]:{pebble_management_port}'
pebble_wrong_url = f'https://[{localhost}]:{pebble_wrong_port}'


def run_acme_tls(*args, wait=True):
    """
    Run acme-tls, return stdout, stderr and exit code
    """
    process = subprocess.Popen(['./acme-tls.py'] + [str(arg) for arg in args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if wait:
        stdout, _ = process.communicate()
        stdout = stdout.decode('utf8')
        code = process.wait()

        print('stdout:')
        print(stdout)

        return code, stdout
    else:
        return process


def acme_request(url, data=None):
    """
    Make https request to pebble
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    resp = urlopen(Request(
        url,
        data=data,
        headers={'Content-Type': 'application/jose+json', 'User-Agent': 'tests'},
    ), context=ctx, timeout=5)
    code = resp.getcode()
    assert code == 200

    return json.load(resp)


class Environment:
    """
    Holds tests environment
    """

    def __init__(self):
        # setup dns mocking
        self.mockdns = Process(target=mockdns.run_server, args=(
                localhost,
                mockdns_port,
                localhost,
                False,  # verbose
            ), daemon=True)
        self.mockdns.start()

        # minimal config
        self.config = {
            'acme': f'{pebble_url}/dir',
            'host': localhost,
            'port': acme_tls_port
        }

        # pregenerate account rsa private key
        self.account_key_rsa = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        ).private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        )

        # pregenerate account ec private key
        self.account_key_ec = ec.generate_private_key(
            ec.SECP384R1()
        ).private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        )

        # pregenerate account ec private key with unsupported curve
        self.account_key_ec_unsupported = ec.generate_private_key(
            ec.SECP521R1()
        ).private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        )

        # wait for pebble to come up
        while True:
            try:
                acme_request(f'{pebble_url}/dir')
                break
            except URLError:
                time.sleep(1)


    def cleanup(self):
        """
        Cleanup
        """
        self.mockdns.terminate()


class Account:
    """
    Account dir setup
    """

    def __init__(self, config=None, account_key=None, domains_list=None):
        self.tmpdir = tempfile.TemporaryDirectory()

        if config is not None:
            with open(os.path.join(self.tmpdir.name, 'config'), 'w') as config_file:
                if isinstance(config, dict):
                    config = (f'{key} = {value}' for key, value in config.items())
                config_file.write('\n'.join(config))

        if account_key is not None:
            with open(os.path.join(self.tmpdir.name, 'account.key'), 'wb') as account_file:
                account_file.write(account_key)

        if domains_list is not None:
            with open(os.path.join(self.tmpdir.name, 'domains.list'), 'w') as list_file:
                list_file.write('\n'.join(domains_list))


    def cleanup(self):
        self.tmpdir.cleanup()


    def __enter__(self, *args, **kwargs):
        return self.tmpdir.name


    def __exit__(self, *args, **kwargs):
        self.cleanup()


@pytest.fixture
def env(session_scoped_container_getter):
    """
    Yields envorinment object
    """
    env = Environment()
    yield env
    env.cleanup()


def check_cert_domains(path, domains):
    """
    Check if certificates inclues given domais
    """
    with open(path, 'rb') as domain_cert_file:
        domain_cert = domain_cert_file.read()

    parsed_cert = x509.load_pem_x509_certificate(domain_cert)
    extension = parsed_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    cert_domains = set(extension.value.get_values_for_type(x509.DNSName))
    assert cert_domains == set(domains)

    return parsed_cert.fingerprint(crypto_hashes.SHA256())


def check_account_key(path):
    """
    Check account key
    """
    with open(path, 'rb') as account_key_file:
        account_key = account_key_file.read()
    load_pem_private_key(account_key, None, crypto_default_backend())

    return account_key


def check_validation_server(host, port, protocols=['acme-tls/1'], hostname='_'):
    """
    Check validation server
    """
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(protocols)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        server_check_timeout= 5
        with socket.create_connection((host, port), timeout=server_check_timeout) as sock:
            sock = ctx.wrap_socket(sock, server_hostname=hostname)
            sock.close()

        return True
    except Exception as exc:
        print(f'validation server check: {exc}')
        return False


def wait_for_file(path):
    """
    Wait file to be present
    """
    check_attempts = 10
    while not os.path.isfile(path):
        check_attempts -= 1
        assert check_attempts >  0
        time.sleep(2)


def wait_for_domain_cert(path, domain):
    """
    Wait and check domain certificate when ready
    """
    domain_cert = os.path.join(path, 'certificates', domain, 'domain.crt')
    wait_for_file(domain_cert)
    return check_cert_domains(domain_cert, [domain])


def wait_for_validation_server():
    """
    Wait for validation server to be ready
    """
    check_attempts = 5
    while not check_validation_server(localhost, acme_tls_port):
        check_attempts -= 1
        assert check_attempts > 0
        time.sleep(2)


def update_domains_list(path, domains_list):
    """
    Update domains.list configuration
    """
    with open(os.path.join(path, 'domains.list'), 'w') as domains_list_file:
        domains_list_file.write('\n'.join(domains_list))


def test_usage(env):
    # show help
    assert run_acme_tls('-h')[0] == 0

    # version
    assert run_acme_tls('version')[0] == 0

    # run without arguments
    assert run_acme_tls()[0] == 2


def test_config(env):
    # missing account directory
    with Account() as path:
        assert run_acme_tls('--testing', 'new-account', os.path.join(path, 'does_not_exist'))[0] == 1

    # minimal config
    with Account(env.config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

    # comments
    config = [
        ' ',
        f'acme = {pebble_url}/dir',
        f'  host = {localhost}',
        f'  # host = wrong_{localhost}',
        f'port = {acme_tls_port}  # comment',
    ]
    with Account(config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

    # missing config
    with Account(None, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1

    # syntax error
    config = ['error']
    with Account(config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1

    # unknown key
    config = dict(env.config)
    config['unknown_key'] = 'unknown'
    with Account(config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1

    # missing acme url
    config = dict(env.config)
    del config['acme']
    with Account(config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1

    # missing host
    config = dict(env.config)
    del config['host']
    with Account(config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1

    # missing port
    config = dict(env.config)
    del config['port']
    with Account(config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1

    # wrong acme ca url
    config = dict(env.config)
    config['acme'] = 'wrong_url'
    with Account(config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1

    # wrong schedule
    config = dict(env.config)
    config['schedule'] = 'not_a_number'
    with Account(config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1

    config = dict(env.config)
    config['schedule'] = '666'
    with Account(config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1

    # wrong port
    config = dict(env.config)
    config['port'] = 'not_a_number'
    with Account(config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1

    config = dict(env.config)
    config['port'] = '-666'
    with Account(config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1


def test_new_account(env):
    # unreachable acme directory
    config = dict(env.config)
    config['acme'] = f'{pebble_wrong_url}/dir'
    with Account(config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1

    # wrong acme directory
    config = dict(env.config)
    config['acme'] = f'{pebble_url}/wrong_dir'
    with Account(config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1

    with Account(env.config, env.account_key_ec) as path:
        # create new account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

        # reuse existing account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

    # create new account and generate new key
    with Account(env.config) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0
        check_account_key(os.path.join(path, 'account.key'))


def test_update_account(env):
    with Account(env.config, env.account_key_ec) as path:
        # update not existing account
        assert run_acme_tls('--testing', 'update-account', path)[0] == 1

        # create new account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

        # update existing account
        assert run_acme_tls('--testing', 'update-account', path)[0] == 0


def test_deactivate_account(env):
    with Account(env.config, env.account_key_ec) as path:
        # deactivate not existing account
        assert run_acme_tls('--testing', 'deactivate-account', path)[0] == 1

        # create new account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

        # deactivate existing account
        assert run_acme_tls('--testing', 'deactivate-account', path)[0] == 0

        # actions on deactivated account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1
        assert run_acme_tls('--testing', 'update-account', path)[0] == 1
        assert run_acme_tls('--testing', 'deactivate-account', path)[0] == 1


def test_account_keys(env):
    # rsa
    with Account(env.config, env.account_key_rsa) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1

    # unsupported elliptic curves
    with Account(env.config, env.account_key_ec_unsupported) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 1

    # elliptic curves
    with Account(env.config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0


def test_domains_list(env):
    # missing domains list
    with Account(env.config, env.account_key_ec) as path:
        assert run_acme_tls('--testing', 'renew-all', path)[0] == 1

    # empty domains list
    domains_list = []
    with Account(env.config, env.account_key_ec, domains_list) as path:
        assert run_acme_tls('--testing', 'renew-all', path)[0] == 1

    # invalid domain
    domains_list = ['_']
    with Account(env.config, env.account_key_ec, domains_list) as path:
        assert run_acme_tls('--testing', 'renew-all', path)[0] == 1

    # complex domains list
    domains_list = [
        ' # comment',
        '1.domain  # with comment',
        'domain 2.domain, 3.domain\t4.domain',
        ' ',
    ]
    with Account(env.config, env.account_key_ec, domains_list) as path:
        # create account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

        # renew all
        assert run_acme_tls('--testing', 'renew-all', path)[0] == 0
        check_cert_domains(
            os.path.join(path, 'certificates', '1.domain', 'domain.crt'),
            ['1.domain']
        )
        check_cert_domains(
            os.path.join(path, 'certificates', 'domain', 'domain.crt'),
            'domain 2.domain 3.domain 4.domain'.split(),
        )


def test_renew_all(env):
    domains_list = ['domain']

    with Account(env.config, env.account_key_ec, domains_list) as path:
        # renew all without an account
        assert run_acme_tls('--testing', 'renew-all', path)[0] == 1
        assert not os.path.exists(os.path.join(path, 'certificates', 'domain', 'domain.crt'))

        # create account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

        # renew all
        assert run_acme_tls('--testing', 'renew-all', path)[0] == 0
        domain_fprint = check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])

        # already renewed
        assert run_acme_tls('--testing', 'renew-all', path)[0] == 0
        assert domain_fprint == check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])

        # force renewal
        assert run_acme_tls('--testing', 'renew-all', path, '--force')[0] == 0
        assert domain_fprint != check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])


def test_renew_domain(env):
    domains_list = ['domain', 'ignored']

    with Account(env.config, env.account_key_ec, domains_list) as path:
        # missing domain argument
        assert run_acme_tls('--testing', 'renew', path)[0] == 2

        # renew without an account
        assert run_acme_tls('--testing', 'renew', path, '--domain', 'domain')[0] == 1
        assert not os.path.exists(os.path.join(path, 'certificates', 'domain', 'domain.crt'))

        # create account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

        # renew
        assert run_acme_tls('--testing', 'renew', path, '--domain', 'domain')[0] == 0
        domain_fprint = check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])
        assert not os.path.exists(os.path.join(path, 'certificates', 'ignored', 'ignored.crt'))

        # already renewed
        assert run_acme_tls('--testing', 'renew', path, '--domain', 'domain')[0] == 0
        assert domain_fprint == check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])
        assert not os.path.exists(os.path.join(path, 'certificates', 'ignored', 'ignored.crt'))

        # force renewal
        assert run_acme_tls('--testing', 'renew', path, '--force', '--domain', 'domain')[0] == 0
        assert domain_fprint != check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])
        assert not os.path.exists(os.path.join(path, 'certificates', 'ignored', 'ignored.crt'))


def test_revoke_all(env):
    domains_list = ['domain1', 'domain2']

    with Account(env.config, env.account_key_ec, domains_list) as path:
        # revoke without account
        assert run_acme_tls('--testing', 'revoke-all', path)[0] == 1

        # create an account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

        # get cerfitifcates
        assert run_acme_tls('--testing', 'renew', path, '--domain', 'domain1')[0] == 0

        # revoke all (only domain1 will be revoked)
        assert run_acme_tls('--testing', 'revoke-all', path)[0] == 1

        # get all cerfitifcates
        assert run_acme_tls('--testing', 'renew-all', path)[0] == 0

        # revoke all
        assert run_acme_tls('--testing', 'revoke-all', path)[0] == 1

    with Account(env.config, None, domains_list) as path:
        # create an account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0
        check_account_key(os.path.join(path, 'account.key'))

        # get all cerfitifcates
        assert run_acme_tls('--testing', 'renew-all', path)[0] == 0

        # revoke all
        assert run_acme_tls('--testing', 'revoke-all', path)[0] == 0


def test_revoke_domain(env):
    domains_list = ['domain', 'ignored']

    with Account(env.config, env.account_key_ec, domains_list) as path:
        # missing domain argument
        assert run_acme_tls('--testing', 'revoke', path)[0] == 2

        # create an account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

        # renew
        assert run_acme_tls('--testing', 'renew', path, '--domain', 'domain')[0] == 0
        domain_fprint = check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])

        # revoke
        assert run_acme_tls('--testing', 'revoke', path, '--domain', 'domain')[0] == 0

        # revoke again
        assert run_acme_tls('--testing', 'revoke', path, '--domain', 'domain')[0] == 1

        # renew again
        assert run_acme_tls('--testing', 'renew', path, '--force', '--domain', 'domain')[0] == 0
        assert domain_fprint != check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])

        # revoke
        assert run_acme_tls('--testing', 'revoke', path, '--domain', 'domain')[0] == 0


def test_contact(env):
    domains_list = ['domain']

    config = dict(env.config)
    config['contact'] = 'mailto:a@b.c'
    with Account(config, env.account_key_ec, domains_list) as path:
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0


def test_group(env):
    domains_list = ['domain']

    config = dict(env.config)
    config['group'] = 'www-data'  # user needs to be in this group
    with Account(config, env.account_key_ec, domains_list) as path:
        # create an account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

        # renew all
        assert run_acme_tls('--testing', 'renew-all', path)[0] == 0
        domain_cert = os.path.join(path, 'certificates', 'domain', 'domain.crt')
        check_cert_domains(domain_cert, ['domain'])
        stat = os.stat(domain_cert)
        gid = stat.st_gid
        assert config['group'] == grp.getgrgid(gid)[0]


def test_removals(env):
    domains_list = ['domain']

    def run(path):
        assert run_acme_tls('--testing', 'renew-all', path)[0] == 0
        check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])

    # removing fallbacks
    with Account(env.config, None, domains_list) as path:
        # create an account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

        run(path)
        os.unlink(os.path.join(path, 'fallback.key'))
        run(path)
        os.unlink(os.path.join(path, 'fallback.crt'))
        run(path)
        os.unlink(os.path.join(path, 'fallback.key'))
        os.unlink(os.path.join(path, 'fallback.crt'))
        run(path)

    # removing domain certificates
    with Account(env.config, None, domains_list) as path:
        # create an account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0
        check_account_key(os.path.join(path, 'account.key'))

        run(path)
        os.unlink(os.path.join(path, 'certificates', 'domain', 'domain.key'))
        run(path)
        os.unlink(os.path.join(path, 'certificates', 'domain', 'domain.crt'))
        run(path)
        os.unlink(os.path.join(path, 'certificates', 'domain', 'domain.key'))
        os.unlink(os.path.join(path, 'certificates', 'domain', 'domain.crt'))
        run(path)


def test_validation_server(env):
    # run validation server without an account
    with Account(env.config, None, ['domain']) as path:
        assert run_acme_tls('--testing', 'run', path)[0] == 1

    try:
        account = Account(env.config, env.account_key_ec, ['domain1'])
        path = account.tmpdir.name

        # create an account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

        # run validation server
        process = run_acme_tls('--testing', 'run', path, wait=False)

        # wait for server to come up
        wait_for_validation_server()

        # checks
        assert not check_validation_server(localhost, acme_tls_port, hostname='missing.challenges')
        assert check_validation_server(localhost, acme_tls_port, hostname='invalid.')
        assert check_validation_server(localhost, acme_tls_port, protocols=['http/1.1'])

        # remove fallbacks
        os.unlink(os.path.join(path, 'fallback.key'))
        process.send_signal(signal.SIGHUP)
        wait_for_domain_cert(path, 'domain1')

        # remove fallbacks
        update_domains_list(path, ['domain2'])
        os.unlink(os.path.join(path, 'fallback.crt'))
        process.send_signal(signal.SIGHUP)
        wait_for_domain_cert(path, 'domain2')

        # remove fallbacks
        update_domains_list(path, ['domain3'])
        os.unlink(os.path.join(path, 'fallback.key'))
        os.unlink(os.path.join(path, 'fallback.crt'))
        process.send_signal(signal.SIGHUP)
        wait_for_domain_cert(path, 'domain3')

        # wait for new domain cert
        update_domains_list(path, ['domain4'])
        process.send_signal(signal.SIGHUP)
        wait_for_domain_cert(path, 'domain4')
    finally:
        # cleanup
        try:
            process.send_signal(signal.SIGINT)
            stdout, _ = process.communicate(timeout=5)
            print(stdout.decode('utf8'))
        except Exception:
            pass
        account.cleanup()


def test_done_command(env):
    try:
        # prepare account dir
        done_file_name_1 = '.ready_file1'
        done_file_name_2 = '.ready_file2'

        config = dict(env.config)
        config['done_cmd'] = f'echo -n "file1" | cat > "{done_file_name_1}" && echo -n "file2" | cat > "{done_file_name_2}"'
        account = Account(config, env.account_key_ec, ['domain1'])
        path = account.tmpdir.name
        done_file_name_1 = os.path.join(path, done_file_name_1)
        done_file_name_2 = os.path.join(path, done_file_name_2)

        # create an account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

        # run validation server
        process = run_acme_tls('--testing', 'run', path, wait=False)

        # wait for server to come up
        wait_for_validation_server()

        # wait for domain cert
        process.send_signal(signal.SIGHUP)
        domain1_fprint = wait_for_domain_cert(path, 'domain1')
        wait_for_file(done_file_name_1)
        wait_for_file(done_file_name_2)
        with open(done_file_name_1) as done_file:
            assert done_file.read() == 'file1'
        with open(done_file_name_2) as done_file:
            assert done_file.read() == 'file2'

        # remove done files
        os.unlink(done_file_name_1)
        os.unlink(done_file_name_2)

        # wait for new domain cert
        update_domains_list(path, ['domain1', 'domain2'])
        process.send_signal(signal.SIGHUP)
        domain2_fprint = wait_for_domain_cert(path, 'domain2')
        wait_for_file(done_file_name_1)
        wait_for_file(done_file_name_2)
        with open(done_file_name_1) as done_file:
            assert done_file.read() == 'file1'
        with open(done_file_name_2) as done_file:
            assert done_file.read() == 'file2'

        # remove done files, make it directory, so next done command will fail
        os.unlink(done_file_name_1)
        os.unlink(done_file_name_2)
        os.mkdir(done_file_name_2)

        # wait for new domain cert
        update_domains_list(path, ['domain1', 'domain2', 'domain3'])
        process.send_signal(signal.SIGHUP)
        domain3_fprint = wait_for_domain_cert(path, 'domain3')
        wait_for_file(done_file_name_1)
        time.sleep(1)  # time to complete done command
        assert os.path.isdir(done_file_name_2)

        # check domain fingerprints
        update_domains_list(path, ['domain1', 'domain2', 'domain3', 'domain4'])
        process.send_signal(signal.SIGHUP)
        domain4_fprint = wait_for_domain_cert(path, 'domain4')
        assert domain1_fprint == wait_for_domain_cert(path, 'domain1')
        assert domain2_fprint == wait_for_domain_cert(path, 'domain2')
        assert domain3_fprint == wait_for_domain_cert(path, 'domain3')

        # remove done files
        os.unlink(done_file_name_1)
        os.rmdir(done_file_name_2)

        # done cmd should not run
        process.send_signal(signal.SIGHUP)
        time.sleep(3)  # to to complete certificate validation checks
        assert domain1_fprint == wait_for_domain_cert(path, 'domain1')
        assert domain2_fprint == wait_for_domain_cert(path, 'domain2')
        assert domain3_fprint == wait_for_domain_cert(path, 'domain3')
        assert domain4_fprint == wait_for_domain_cert(path, 'domain4')
        assert not os.path.isfile(done_file_name_1)
        assert not os.path.isfile(done_file_name_2)
    finally:
        # cleanup
        try:
            process.send_signal(signal.SIGINT)
            stdout, _ = process.communicate(timeout=5)
            stdout = stdout.decode('utf8')

            # check that last done comman was not run
            assert stdout.split('\n')[-2] == 'watchdog: no new certificates were issued, not running done callback\n'

            print(stdout)
        except Exception:
            pass
        account.cleanup()


def test_port_conflict(env):
    try:
        account = Account(env.config, env.account_key_ec, ['domain'])
        path = account.tmpdir.name

        # create an account
        assert run_acme_tls('--testing', 'new-account', path)[0] == 0

        # run validation server
        process = run_acme_tls('--testing', 'run', path, wait=False)

        # wait for server to come up
        wait_for_validation_server()

        # renew certificates
        assert run_acme_tls('--testing', 'renew-all', path)[0] == 0
        check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])
    finally:
        # cleanup
        try:
            process.send_signal(signal.SIGINT)
            stdout, _ = process.communicate(timeout=5)
            stdout = stdout.decode('utf8')
            print(stdout)
        except Exception:
            pass
        account.cleanup()
