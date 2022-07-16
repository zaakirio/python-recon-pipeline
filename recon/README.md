# Reconnaissance Pipeline (WIP)

## Installation
1. `apt install pipenv`
2. To run the pipelines, you need to set your `PYTHONPATH` environment variable to the path of this project on disk by adding `export PYTHONPATH=/path/to/recon-pipeline` to your `.bashrc`   
3. `pipenv install`
4. `pipenv shell`

## Running
Pipeline currently only supports masscan, to run masscan recon:
1. `PYTHONPATH=$(pwd) luigi --local-scheduler --module recon.masscan ParseMasscanOutput --target-file scavenger --top-ports 1000`


