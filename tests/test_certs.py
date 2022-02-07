import subprocess
import socket
import tempfile
import os
import ssl
import json
import time
import signal
from multiprocessing import Process
from urllib.request import urlopen, Request
from urllib.error import URLError

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

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


def run_certs(*args, wait=True):
    """
    Run certs, return stdout, stderr and exit code
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


def request(url, data=None):
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
                request(f'{pebble_url}/dir')
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

    def __init__(self, domains_list=None, account_key=None):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.domais_list = domains_list
        self.account_key = account_key

        if domains_list:
            with open(os.path.join(self.tmpdir.name, 'domains.list'), 'w') as list_file:
                list_file.write('\n'.join(domains_list))

        if account_key:
            with open(os.path.join(self.tmpdir.name, 'account.key'), 'wb') as account_file:
                account_file.write(self.account_key)


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


def test_usage(env):
    # show help
    assert run_certs('-h')[0] == 0

    # version
    assert run_certs('--version')[0] == 0

    # run without arguments
    assert run_certs()[0] == 2

    # missing acme url
    with tempfile.TemporaryDirectory() as path:
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--schedule', 'once',
        )[0] == 2

    # wrong acme ca url
    with tempfile.TemporaryDirectory() as path:
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', 'wrong_url',
            '--schedule', 'once',
        )[0] == 2

    # wrong schedule
    with tempfile.TemporaryDirectory() as path:
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_url}/dir',
            '--schedule', '-1',
        )[0] == 2


def test_failures(env):
    domains_list = ['_']  # invalid domain

    # missing domain list
    with Account() as path:
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_url}/dir',
            '--new-account-key',
            '--schedule', 'once',
            '--testing',
        )[0] == 1

    # missing account key
    with Account(domains_list) as path:
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_url}/dir',
            '--new-account-key',
            '--schedule', 'once',
            '--testing',
        )[0] == 1

    # unreachable acme ca
    with Account(domains_list, env.account_key_ec) as path:
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_wrong_url}/dir',
            '--new-account-key',
            '--schedule', 'once',
            '--testing',
        )[0] == 1

    # wrong acme ca path
    with Account(domains_list, env.account_key_ec) as path:
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_url}/wrong_dir',
            '--new-account-key',
            '--schedule', 'once',
            '--testing',
        )[0] == 1

    # failed validation for all domains
    with Account(domains_list, env.account_key_ec) as path:
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_url}/dir',
            '--new-account-key',
            '--schedule', 'once',
            '--testing',
        )[0] == 1


def test_domains_list(env):
    domains_list = [
        ' # comment',
        '1.domain  # with comment',
        'domain 2.domain, 3.domain\t4.domain',
        ' ',
    ]

    with Account(domains_list, env.account_key_ec) as path:
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_url}/dir',
            '--new-account-key',
            '--schedule', 'once',
            '--testing',
        )[0] == 0

        check_cert_domains(os.path.join(path, 'certificates', '1.domain', 'domain.crt'), ['1.domain'])
        check_cert_domains(
            os.path.join(path, 'certificates', 'domain', 'domain.crt'),
            'domain 2.domain 3.domain 4.domain'.split(),
        )


def test_account_keys(env):
    domains_list = ['domain']

    # rsa
    with Account(domains_list, env.account_key_rsa) as path:
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_url}/dir',
            '--new-account-key',
            '--schedule', 'once',
            '--testing',
        )[0] == 1

    # unsupported elliptic curves
    with Account(domains_list, env.account_key_ec_unsupported) as path:
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_url}/dir',
            '--new-account-key',
            '--schedule', 'once',
            '--testing',
        )[0] == 1

    # elliptic curves
    with Account(domains_list, env.account_key_ec) as path:
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_url}/dir',
            '--new-account-key',
            '--schedule', 'once',
            '--testing',
        )[0] == 0
        check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])


def test_run(env):
    domains_list = ['domain']

    def run(path):
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_url}/dir',
            '--new-account-key',
            '--schedule', 'once',
            '--testing',
        )[0] == 0
        check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])

    def run_force(path):
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_url}/dir',
            '--new-account-key',
            '--schedule', 'force',
            '--testing',
        )[0] == 0
        check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])

    # run
    with Account(domains_list) as path:
        run(path)
        run(path)

    # run force
    with Account(domains_list) as path:
        run_force(path)
        run_force(path)


def test_contact(env):
    domains_list = ['domain']

    with Account(domains_list) as path:
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_url}/dir',
            '--schedule', 'force',
            '--new-account-key',
            '--contact', 'mailto:a@b.c',
            '--contact', 'mailto:d@e.f',
            '--testing',
        )[0] == 0
        check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])


def test_removals(env):
    domains_list = ['domain']

    def run(path):
        assert run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_url}/dir',
            '--new-account-key',
            '--schedule', 'force',
            '--testing',
        )[0] == 0
        check_cert_domains(os.path.join(path, 'certificates', 'domain', 'domain.crt'), ['domain'])

    # removing fallbacks
    with Account(domains_list) as path:
        run(path)
        os.unlink(os.path.join(path, 'fallback.key'))
        run(path)
        os.unlink(os.path.join(path, 'fallback.crt'))
        run(path)
        os.unlink(os.path.join(path, 'fallback.key'))
        os.unlink(os.path.join(path, 'fallback.crt'))
        run(path)

    # removing domain certificates
    with Account(domains_list) as path:
        run(path)
        os.unlink(os.path.join(path, 'certificates', 'domain', 'domain.key'))
        run(path)
        os.unlink(os.path.join(path, 'certificates', 'domain', 'domain.crt'))
        run(path)
        os.unlink(os.path.join(path, 'certificates', 'domain', 'domain.key'))
        os.unlink(os.path.join(path, 'certificates', 'domain', 'domain.crt'))
        run(path)


def test_validation_server(env):
    def wait_and_check(domain):
        domain_cert = os.path.join(path, 'certificates', domain, 'domain.crt')
        check_attempts = 10
        while not os.path.isfile(domain_cert):
            check_attempts -= 1
            assert check_attempts >  0
            time.sleep(2)
        check_cert_domains(domain_cert, [domain])

    def update_domains_list(domain):
        with open(os.path.join(path, 'domains.list'), 'w') as domains_list_file:
            domains_list_file.write(domain)

    try:
        account = Account(['domain1'])
        path = account.tmpdir.name

        # run validation server
        process = run_certs(
            '--path', path,
            '--host', localhost,
            '--port', acme_tls_port,
            '--acme', f'{pebble_url}/dir',
            '--new-account-key',
            '--testing',
            wait=False,
        )

        # wait for server to come up
        check_attempts = 5
        while not check_validation_server(localhost, acme_tls_port):
            check_attempts -= 1
            assert check_attempts > 0
            time.sleep(2)

        # checks
        assert not check_validation_server(localhost, acme_tls_port, hostname='missing.challenges')
        assert check_validation_server(localhost, acme_tls_port, hostname='invalid.')
        assert check_validation_server(localhost, acme_tls_port, protocols=['http/1.1'])

        # remove fallbacks
        os.unlink(os.path.join(path, 'fallback.key'))
        process.send_signal(signal.SIGHUP)
        wait_and_check('domain1')

        # remove fallbacks
        update_domains_list('domain2')
        os.unlink(os.path.join(path, 'fallback.crt'))
        process.send_signal(signal.SIGHUP)
        wait_and_check('domain2')

        # remove fallbacks
        update_domains_list('domain3')
        os.unlink(os.path.join(path, 'fallback.key'))
        os.unlink(os.path.join(path, 'fallback.crt'))
        process.send_signal(signal.SIGHUP)
        wait_and_check('domain3')

        # wait for new domain cert
        update_domains_list('domain4')
        process.send_signal(signal.SIGHUP)
        wait_and_check('domain4')
    finally:
        # cleanup
        try:
            process.send_signal(signal.SIGINT)
            stdout, _ = process.communicate(timeout=5)
            print(stdout.decode('utf8'))
        except Exception:
            pass
        account.cleanup()
