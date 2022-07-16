import json
import logging
from collections import defaultdict

import luigi
from luigi.util import inherits
from luigi.contrib.external_program import ExternalProgramTask

from recon.targets import TargetList
from recon.config import top_tcp_ports, top_udp_ports, masscan_config


@inherits(TargetList)
class Masscan(ExternalProgramTask):
    # Run masscan against a target
    # masscan -v --open-only --banners --rate 1000 -e tun0 -oJ masscan.tesla.json --ports 80,443,22,21 -iL tesla.ips
    # Luigi command: PYTHONPATH=$(pwd) luigi --local-scheduler --module recon.masscan Masscan --target-file tesla --ports 80,443,22,21

    # Args:
    #    rate: desired rate for transmitting packets (packets per second)
    #    interface: use the named raw network interface, such as "eth0"
    #    top_ports: Scan top N most popular ports
    #    ports: specifies the port(s) to be scanned
    #    target_file: specifies the file on disk containing a list of ips or domains *--* Required by upstream Task

    rate = luigi.Parameter(default=masscan_config.get("rate"))
    interface = luigi.Parameter(default=masscan_config.get("iface"))
    top_ports = luigi.IntParameter(default=0)  # IntParameter -> top_ports expected as int
    ports = luigi.Parameter(default="")

    def __init__(self, *args, **kwargs):
        super(Masscan, self).__init__(*args, **kwargs)
        self.masscan_output = f"masscan.{self.target_file}.json"

    def requires(self):
        # Masscan requires TargetList which expects target_file as a parameter.
        return {"target_list": TargetList(target_file=self.target_file)}

    def output(self):
        # Returns the target output for this task.
        return luigi.LocalTarget(self.masscan_output)

    def program_args(self):

        if not self.ports and not self.top_ports:
            # need at least one
            logging.error("Must specify either --top-ports or --ports.")
            exit(1)

        if self.top_ports < 0:
            # sanity check
            logging.error("--top-ports must be greater than 0")
            exit(2)

        if self.top_ports:
            # if --top-ports used, format the top_*_ports lists as strings and then into a proper masscan --ports option
            top_tcp_ports_str = ",".join(str(x) for x in top_tcp_ports[: self.top_ports])
            top_udp_ports_str = ",".join(str(x) for x in top_udp_ports[: self.top_ports])

            self.ports = f"{top_tcp_ports_str},U:{top_udp_ports_str}"
            self.top_ports = 0

        command = [
            "masscan",
            "-v",
            "--open",
            "--banners",
            "--rate",
            self.rate,
            "-e",
            self.interface,
            "-oJ",
            self.masscan_output,
            "--ports",
            self.ports,
            "-iL",
            self.input().get("target_list").path,
        ]

        return command


@inherits(Masscan)
class ParseMasscanOutput(luigi.Task):
    # Read masscan JSON results and create a dictionary for processing.

    # Args:
    #    top_ports: Scan top N most popular ports *--* Required by upstream Task
    #    ports: specifies the port(s) to be scanned *--* Required by upstream Task
    #    interface: use the named raw network interface, such as "eth0" *--* Required by upstream Task
    #    rate: desired rate for transmitting packets (packets per second) *--* Required by upstream Task
    #    target_file: specifies the file on disk containing a list of ips or domains *--* Required by upstream Task
    

    def requires(self):
        # Pass args into masscan

        args = {
            "rate": self.rate,
            "target_file": self.target_file,
            "top_ports": self.top_ports,
            "interface": self.interface,
            "ports": self.ports,
        }
        return Masscan(**args)

    def output(self):
        # Returns json output for this task.
        return luigi.LocalTarget(f"masscan.{self.target_file}.parsed.json")

    def run(self):
        # Reads masscan results and creates a dictionary of IPs and ports.
        ip_dict = defaultdict(lambda: defaultdict(set)) 

        try:
            entries = json.load(self.input().open())  # load masscan results from Masscan Task
        except json.decoder.JSONDecodeError as e:
            return print(e)

        for entry in entries:
            single_target_ip = entry.get("ip")
            for port_entry in entry.get("ports"):
                protocol = port_entry.get("proto")
                ip_dict[single_target_ip][protocol].add(str(port_entry.get("port")))

        with open(self.output().path, "wb") as f:
            json.dump(dict(ip_dict), f)
