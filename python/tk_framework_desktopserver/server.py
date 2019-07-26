# Copyright (c) 2013 Shotgun Software Inc.
#
# CONFIDENTIAL AND PROPRIETARY
#
# This work is provided "AS IS" and subject to the Shotgun Pipeline Toolkit
# Source Code License included in this distribution package. See LICENSE.
# By accessing, using, copying or modifying this work you indicate your
# agreement to the Shotgun Pipeline Toolkit Source Code License. All rights
# not expressly granted therein are reserved by Shotgun Software Inc.

import os
import threading
import base64

from .server_protocol import ServerProtocol

from twisted.internet import reactor, ssl, error
from twisted.python import log

from autobahn.twisted.websocket import WebSocketServerFactory, listenWS

from .errors import MissingCertificateError, PortBusyError
from . import certificates

from .logger import get_logger

from sgtk.platform.qt import QtCore

logger = get_logger(__name__)


class Server(object):
    _DEFAULT_PORT = 9000
    _DEFAULT_KEYS_PATH = "../resources/keys"

    _reactor_thread = None
    _observer = None

    class Notifier(QtCore.QObject):
        different_user_requested = QtCore.Signal(str, int)

    def __init__(self, keys_path, encrypt, host, user_id, host_aliases, is_wss, port=None):
        """
        Constructor.

        :param keys_path: Path to the keys. If the path is relative, it will be relative to the
            current working directory. Mandatory
        :param encrypt: If True, the communication with clients will be encrypted.
        :param host: Url of the host we're expecting requests from.
        :param user_id: Id of the user we're expecting requests from.
        :param host_aliases: List of aliases available for the current host.
        :param port: Port to listen for websocket requests from.
        :param low_level_debug: If True, wss traffic will be written to the console.
        """
        self._port = port or self._DEFAULT_PORT
        self._keys_path = keys_path or self._DEFAULT_KEYS_PATH
        self._host = host
        self._user_id = user_id
        self._is_wss = is_wss

        self._host_aliases = host_aliases

        # If encryption is required, compute a server id and retrieve the secret associated to it.
        if encrypt:
            # urandom is considered cryptographically secure as it calls the OS's CSRNG, so we can
            # use that to generate our own server id.
            self._ws_server_id = base64.urlsafe_b64encode(os.urandom(16))
        else:
            self._ws_server_id = None

        self.notifier = self.Notifier()

        if not os.path.exists(keys_path):
            raise MissingCertificateError(keys_path)

        logger.debug("Browser integration using certificates at %s", self._keys_path)
        logger.debug("Encryption: %s", encrypt)

    def get_logger(self):
        """
        :returns: The python logger root for the framework.
        """
        return logger

    def _raise_if_missing_certificate(self, certificate_path):
        """
        Raises an exception is a certificate file is missing.

        :param certificate_path: Path to the certificate file.

        :raises Exception: Thrown if the certificate file is missing.
        """
        if not os.path.exists(certificate_path):
            raise MissingCertificateError("Missing certificate file: %s" % certificate_path)

    def _start_server(self):
        """
        Start shotgun web server, listening to websocket connections.

        :param debug: Boolean Show debug output. Will also Start local web server to test client pages.
        """
        if self._is_wss:
            cert_crt_path, cert_key_path = certificates.get_certificate_file_names(self._keys_path)
            self._raise_if_missing_certificate(cert_key_path)
            self._raise_if_missing_certificate(cert_crt_path)
            self.context_factory = ssl.DefaultOpenSSLContextFactory(
                cert_key_path, cert_crt_path
            )
        else:
            # SSL server context: load server key and certificate
            self.context_factory = None


        # FIXME: Seems like the debugging flags are gone from the initializer at the moment.
        # We should try to restore these.
        self.factory = WebSocketServerFactory(
            "%s://localhost:%d" % ("wss" if self._is_wss else "ws", self._port)
        )

        self.factory.protocol = ServerProtocol
        self.factory.host = self._host
        self.factory.host_aliases = self._host_aliases
        self.factory.user_id = self._user_id
        self.factory.notifier = self.notifier
        self.factory.ws_server_id = self._ws_server_id
        self.factory.setProtocolOptions(echoCloseCodeReason=True)
        try:
            self.listener = listenWS(self.factory, self.context_factory)
        except error.CannotListenError, e:
            raise PortBusyError(str(e))

    @classmethod
    def init_twisted_logging(cls):
        twisted = get_logger("twisted")
        # This will take the Twisted logging and forward it to Python's logging.
        cls._observer = log.PythonLoggingObserver(twisted.name)
        cls._observer.start()

    @classmethod
    def start_reactor(cls):
        """
        Starts the reactor in a Python thread.
        """
        # Reactor thread has already been started, do not start again.
        if cls._reactor_thread:
            return

        def start():
            reactor.run(installSignalHandlers=0)

        cls._reactor_thread = threading.Thread(target=start)
        cls._reactor_thread.start()

    def start(self):
        """
        Start shotgun web server, listening to websocket connections.
        """
        self._start_server()

    @classmethod
    def is_running(cls):
        """
        :returns: True if the server is up and running, False otherwise.
        """
        return self._reactor_thread.isAlive()

    @classmethod
    def tear_down_reactor(self):
        """
        Tears down Twisted.
        """
        reactor.callFromThread(reactor.stop)
        self._reactor_thread.join()
