from unittest.mock import MagicMock
from flask_testing import TestCase
import sys
import os
import logging
import json

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from dashboard import app
from common import log_handler, LOG_LEVEL

logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)
logger.addHandler(log_handler)


def docker_stub(worker_api):
    return "docker"

def swarm_stub(worker_api):
    return "swarm"

class HostCreateTest(TestCase):
    def create_app(self):
        """
        Create a flask web app
        :return: flask web app object
        """
        app.config['TESTING'] = True
        app.config['LOGIN_DISABLED'] = False
        return app

    def _remove_all_hosts(self):
        res = self.client.get('/api/hosts')
        hosts = res.data.decode('utf-8')
        hosts = json.loads(hosts)
        for h in hosts['data']:
            print(h, type(h))
            self.client.delete('/api/host', data=dict(id=h['id']))
    def _login(self, username, password):
        """
        Login in a user
        :param username: username for this user
        :param password: password for this user
        :return: login response
        """
        return self.client.post('/api/auth/login',
                                data=dict(
                                    username=username,
                                    password=password
                                ),
                                follow_redirects=True)

    def test_swarm_host_create(self):
        self._remove_all_hosts()
        self._test_host_create("swarm")

    def test_docker_host_create(self):
        self._remove_all_hosts()
        self._test_host_create("docker")

    def _test_host_create(self, host_type):
        """
        Test get/edit user profile,
        Create new user, then get profile of this user,
        use fake data to update user profile,
        then get the update response validate with new data
        :return: None
        """
        self._login("admin", "pass")
        
        if host_type == "docker":
            detect_daemon_type = MagicMock(side_effect=docker_stub)
        else:
            detect_daemon_type = MagicMock(side_effect=swarm_stub)
        response = self.client.post("/api/host",
                                        data=dict(
                                            name="test_host",
                                            worker_api="192.168.2.173:2375",
                                            capacity=5,
                                            log_type="local",
                                            log_server="",
                                            log_level="DEBUG",
                                            host_type=host_type
                                        ))
        self.assert200(response, "create {} host test failed".format(host_type))
