# Copyright (c) 2013 Shotgun Software Inc.
#
# CONFIDENTIAL AND PROPRIETARY
#
# This work is provided "AS IS" and subject to the Shotgun Pipeline Toolkit
# Source Code License included in this distribution package. See LICENSE.
# By accessing, using, copying or modifying this work you indicate your
# agreement to the Shotgun Pipeline Toolkit Source Code License. All rights
# not expressly granted therein are reserved by Shotgun Software Inc.

import json
from process_manager import *

ShotgunIntegrationAPI_MAJOR = 0
ShotgunIntegrationAPI_MINOR = 1
ShotgunIntegrationAPI_PATCH = 0


class ShotgunAPI():
    """
    Public API For all the commands that can be sent from Shotgun Client.

    Every function of this class is accessible to outside clients.

    Every command receives a data dictionary of the command sent from the client
    """

    def __init__(self, host):
        self.host = host
        self.pm = ProcessManager()

        # Public Callable API methods on this object
        self.public_api = ['echo', 'open', 'executeToolkitCommand', 'executeTankCommand',
                                'pickFileOrDirectory', 'pickFileOrDirectories', 'version']

    def _handle_toolkit_output(self, out, err, return_code):
        """
        Used as a callback to handle toolkit command output.

        :param out: String Stdout output.
        :param err: String Stderr output.
        :param return_code: Int Process Return code.
        """

        reply = {}
        reply['retcode'] = return_code
        reply['out'] = out
        reply['err'] = err

        self.host.json_reply(reply)

    def open(self, data):
        """
        Simple message echo

        :param data: Message data. ['filepath': String]
        """

        try:
            self.pm.open(data['filepath'])
        except Exception, e:
            self.host.report_error(e.message)

    def echo(self, data):
        """
        Simple message echo. Used for test and as a simple example.

        :param data: Message data. ['message': String]
        """

        # Create reply object
        reply = {}
        reply['message'] = data['message']

        self.host.json_reply(reply)

    def executeToolkitCommand(self, data):
        pipeline_config_path = data['pipelineConfigPath']
        command = data['command']
        args = data['args']

        # Verify arguments
        if not args:
            args = []

        if not isinstance(args, list):
            message = "ExecuteToolkitCommand 'args' must be a list."
            self.host.report_error(message)
            raise Exception(message)

        try:
            self.pm.execute_toolkit_command(pipeline_config_path, command, args, self._handle_toolkit_output)
        except Exception, e:
            self.host.report_error(e.message)

    def executeTankCommand(self, data):
        return self.executeToolkitCommand(data)

    def pickFileOrDirectory(self, data):
        """
        Pick single file or directory
        :param data:
        """

        files = self.pm.pick_file_or_directory(False)
        self.host.json_reply(files)

    def pickFileOrDirectories(self, data):
        """
        Pick single file or directory
        :param data:
        """

        files = self.pm.pick_file_or_directory(True)
        self.host.json_reply(files)

    def version(self, data=None):
        reply = {}
        reply["major"] = ShotgunIntegrationAPI_MAJOR
        reply["minor"] = ShotgunIntegrationAPI_MINOR
        reply["patch"] = ShotgunIntegrationAPI_PATCH

        self.host.json_reply(reply)
