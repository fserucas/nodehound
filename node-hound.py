import json
import logging.config
import os

from prettytable import PrettyTable

from nodepool import launcher
from nodepool import provider_manager
from nodepool import status
from nodepool.zk import zookeeper as zk
from nodepool.zk import ZooKeeperClient
from nodepool.cmd import NodepoolApp
from nodepool.cmd.config_validator import ConfigValidator

log = logging.getLogger(__name__)

import pudb

pu.db


class NodeHound(NodepoolApp):
    def create_parser(self):
        parser = super(NodeHound, self).create_parser()

        parser.add_argument(
            "-c",
            dest="config",
            default="/etc/nodepool/nodepool.yaml",
            help="path to config file",
        )

        parser.add_argument("-s", dest="secure", help="path to secure file")

        parser.add_argument(
            "--debug",
            dest="debug",
            action="store_true",
            help="show DEBUG level logging",
        )
        subparsers = parser.add_subparsers(
            title="commands",
            description="valid commands",
            dest="command",
            help="additional help",
        )

        cmd_config_validate = subparsers.add_parser(
            "config-validate", help="Validate configuration file"
        )
        cmd_config_validate.set_defaults(func=self.config_validate)

        return parser

    def setup_logging(self):
        # NOTE(jamielennox): This should just be the same as other apps
        if self.args.debug:
            m = "%(asctime)s %(levelname)s %(name)s: %(message)s"
            logging.basicConfig(level=logging.DEBUG, format=m)

        elif self.args.logconfig:
            super(NodeHound, self).setup_logging()

        else:
            m = "%(asctime)s %(levelname)s %(name)s: %(message)s"
            logging.basicConfig(level=logging.INFO, format=m)

            l = logging.getLogger("kazoo")
            l.setLevel(logging.WARNING)
            l = logging.getLogger("nodepool.ComponentRegistry")
            l.setLevel(logging.WARNING)

    def config_validate(self):
        validator = ConfigValidator(self.args.config)
        return validator.validate()
        # TODO(asselin,yolanda): add validation of secure.conf

    def run(self):
        self.zk = None

        self.pool = launcher.NodePool(self.args.secure, self.args.config)
        config = self.pool.loadConfig()

        self.zk_client = ZooKeeperClient(
                config.zookeeper_servers,
                tls_cert=config.zookeeper_tls_cert,
                tls_key=config.zookeeper_tls_key,
                tls_ca=config.zookeeper_tls_ca,
                timeout=config.zookeeper_timeout,
            )
        self.zk_client.connect()
        self.zk = zk.ZooKeeper(self.zk_client, enable_cache=False)

        self.pool.setConfig(config)

        resutls = status.image_list(self.zk)
        
        self.args.func()

        if self.zk:
            self.zk.disconnect()

        


if __name__ == "__main__":
    NodeHound.main()
