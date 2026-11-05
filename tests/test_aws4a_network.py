"""Guard behavior with reversible fake modules; real isolation is tested separately."""

from types import SimpleNamespace

import pytest

from cloudsecops_live.integrations.aws_posture import network


@pytest.mark.parametrize("platform_methods", [False, True])
def test_separate_guard_denies_network_and_processes_without_ambient_configuration(
    monkeypatch, platform_methods
):
    def original(*args, **kwargs):
        raise AssertionError("unguarded operation reached")

    class Socket:
        connect = connect_ex = bind = sendto = original

    class ExistingSSL(Socket):
        def connect(self, address):
            return super().connect(address)

    if platform_methods:
        Socket.sendmsg = original
    fake_socket = SimpleNamespace(
        socket=Socket,
        **{
            name: original
            for name in (
                "getaddrinfo",
                "gethostbyname",
                "gethostbyname_ex",
                "gethostbyaddr",
                "getnameinfo",
                "getfqdn",
                "create_connection",
            )
        },
    )
    fake_process = SimpleNamespace(Popen=original)
    fake_os = SimpleNamespace(system=original)
    if platform_methods:
        for name in ("fork", "forkpty", "posix_spawn", "posix_spawnp", "setsid", "setpgid"):
            setattr(fake_os, name, original)
    hooks = []
    monkeypatch.setattr(network, "socket", fake_socket)
    monkeypatch.setattr(network, "subprocess", fake_process)
    monkeypatch.setattr(network, "os", fake_os)
    monkeypatch.setattr(network, "sys", SimpleNamespace(addaudithook=hooks.append))
    network.install_posture_guard()
    for operation in (
        lambda: fake_socket.getaddrinfo("example.invalid", 443),
        lambda: Socket().connect(("127.0.0.1", 443)),
        lambda: ExistingSSL().connect(("example.invalid", 443)),
        lambda: Socket().sendto(b"private-fake-marker", ("127.0.0.1", 1)),
        lambda: fake_process.Popen(["must-not-execute"]),
        lambda: fake_os.system("must-not-execute"),
    ):
        with pytest.raises(PermissionError) as rejected:
            operation()
        assert "private-fake-marker" not in str(rejected.value)
    assert len(hooks) == 1
    assert hooks[0]("unrelated.safe.event", ()) is None
    for event in (
        "subprocess.Popen",
        "os.system",
        "os.fork",
        "os.forkpty",
        "os.exec",
        "os.posix_spawn",
    ):
        with pytest.raises(PermissionError):
            hooks[0](event, ())
