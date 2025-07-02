
build_dir ?= build
qualifier ?= dev
cia_file ?= cias/bd.cia

help:
	@echo
	@cat data/bravely-default-cover.ascii
	@echo "*** Welcome bravely default hacker!! ***"
	@echo 
	@echo This is a convenience make command to run various bravely default utilities.
	@echo ----------------------------------------------------------------------------
	@echo
	@echo make extract
	@echo "    Usage: make extract cia_file=path-to-mycia.cia build_dir=build qualifier=foobar to extract a cia file to build/foobar"


extract:
	@echo Running unpacking tool.
	bin/unpack.sh $(cia_file) $(build_dir)/$(qualifier)




