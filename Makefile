
build_dir ?= build
qualifier ?= dev
cia_file ?= cias/bd.cia

conda_cmd ?= micromamba
pip_cmd ?= pip
env_name ?= "bd-dev"
game ?= BD

user ?= carm

citra_dir ?= /data/citra/citra-emu

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
	@echo make deploy-code
	@echo "    Deploy bravely code and (to citra by default)."
	@echo make deploy-romfs
	@echo "    Deploy bravely romfs dir and crowd data (to citra by default)."

ctrtool:
	git submodule update --init
	make -C Project_CTR progs

3dstool:
	git submodule update --init
	make -C 3dstool install

cia-unpack: ctrtool 3dstool
	@echo Running unpacking tool.
	bin/unpack.sh $(cia_file) $(build_dir)/$(qualifier)

environment:
	@$(pip_cmd) install -r requirements.txt --break-system-packages
	@$(conda_cmd) env create -n $(env_name) -f environment.yaml -y

crowd-unpack:
	$(conda_cmd) run -n $(env_name) bin/crowd.sh -r $(build_dir)/$(qualifier) -o $(build_dir)/crowd-$(qualifier)-unpacked -g $(game) unpack

crowd-pack:
	$(conda_cmd) run -n $(env_name) bin/crowd.sh -r $(build_dir)/crowd-$(qualifier)-unpacked -o $(build_dir)/crowd-$(qualifier)-packed -g $(game) pack

deploy-code:
	QUALIFIER=${qualifier} USER=${user} BUILD_DIR=${build_dir} CITRA_DIR=${citra_dir} bin/deploy_code.sh 

deploy-romfs:
	QUALIFIER=${qualifier} USER=${user} BUILD_DIR=${build_dir} CITRA_DIR=${citra_dir} bin/deploy_romfs.sh

clean:
	rm -rf build
