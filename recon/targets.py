import shutil
import logging
import ipaddress

import luigi


class TargetList(luigi.ExternalTask):
    target_file = luigi.Parameter()

    def output(self):
        # Read file and checks if valid ip address
        try:
            with open(self.target_file) as f:
                first_line = f.readline()
                ipaddress.ip_interface(first_line.strip())
        except OSError as e:
            return logging.error(f"opening {self.target_file}: {e.strerror}")
        except ValueError as e:
            # domain names
            logging.debug(e)
            file_extension = f"{self.target_file}.domains"
        else:
            # ip addresses
            file_extension = f"{self.target_file}.ips"

        shutil.copy(self.target_file, file_extension)  # copy file with new extension
        return luigi.LocalTarget(file_extension)
