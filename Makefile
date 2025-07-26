
build_dir ?= build
qualifier ?= dev
cia_file ?= cias/bd.cia

conda_cmd ?= micromamba
pip_cmd ?= pip
env_name ?= "bd-dev"
game ?= "BD"

help:
	@echo
	@cat data/bravely-default-cover.ascii
	@echo "*** Welcome bravely default hacker!! ***"
	@echo 
	@echo This is a convenience make command to run various bravely default utilities.
	@echo ----------------------------------------------------------------------------
	@echo
	@echo make cia-unpack
	@echo "    Usage: make cia-unpack cia_file=path-to-mycia.cia build_dir=build qualifier=foobar to extract a cia file to build/foobar"
	@echo make environment
	@echo "    Builds a conda environment for development and pip installs anything outside conda's scope."
	@echo make crowd-unpack
	@echo "    Unpacks bravely crowd data."
	@echo make crowd-pack
	@echo "    Packs bravely crowd data."
	@echo make deploy
	@echo "    Deploy bravely code and crowd data (to citra by default)."




cia-unpack:
	@echo Running unpacking tool.
	bin/unpack.sh $(cia_file) $(build_dir)/$(qualifier)


environment:
	@$(pip_cmd) install -r requirements.txt --break-system-packages
	@$(conda_cmd) env create -n $(env_name) -f environment.yaml -y

crowd-unpack:
	$(conda_cmd) run -n $(env_name) bin/crowd.sh -r $(build_dir)/$(qualifier) -o $(build_dir)/crowd-$(qualifier)-unpacked -g $(game) unpack

crowd-pack:
	$(conda_cmd) run -n $(env_name) bin/crowd.sh -r $(build_dir)/crowd-$(qualifier)-unpacked -o $(build_dir)/crowd-$(qualifier)-packed -g $(game) pack

deploy:
	QUALIFIER=${qualifier} BUILD_DIR=${build_dir} bin/deploy.sh 