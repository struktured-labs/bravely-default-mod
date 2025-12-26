
build_dir ?= build
qualifier ?= dev
cia_file ?= cias/bd.cia
CONTAINER_ENGINE ?= docker

# Pixi-based environment (replaces micromamba/uv)
PIXICMD ?= pixi
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
	@echo make ips-99k-patch
	@echo "    Generate IPS patch for 99k limit code.bin patch."
	@echo make ips-crowd-patch
	@echo "    Generate IPS patch for crowd data modifications."
	@echo make ghidra-setup
	@echo "    Download & install local Ghidra distribution to ./ghidra."
	@echo make ghidra-patch
	@echo "    Run headless Ghidra patch (999k limit) on code.bin."
	@echo make ghidra-image
	@echo "    Build local Ghidra headless Docker image."
	@echo make ips-99k-patch-docker
	@echo "    Run 99k limit patch via Dockerized Ghidra and produce IPS."
	@echo make ghidra-slim-image
	@echo "    Build slim image (requires local extracted ghidra/ directory)."
	@echo make ips-99k-patch-docker-slim
	@echo "    Run patch using slim image and locally extracted ghidra."

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
	$(PIXICMD) install
	@echo "✅ Pixi environment ready. Use 'pixi run <task>' or 'pixi shell'."

crowd-unpack:
	$(PIXICMD) run crowd-unpack

crowd-pack:
	$(PIXICMD) run crowd-pack

deploy-code:
	QUALIFIER=${qualifier} USER=${user} BUILD_DIR=${build_dir} CITRA_DIR=${citra_dir} bin/deploy_code.sh 

deploy-romfs:
	QUALIFIER=${qualifier} USER=${user} BUILD_DIR=${build_dir} CITRA_DIR=${citra_dir} bin/deploy_romfs.sh

ips-99k-patch: ctrtool 3dstool
	@echo "Generating 99k limit IPS patch..."
	# Ensure we have clean unpacked CIA
	@if [ ! -f $(build_dir)/$(qualifier)/cxi/exefs_dir/code.bin ]; then \
		echo "Error: Original code.bin not found. Run 'make cia-unpack' first."; \
		exit 1; \
	fi
	# Copy original code.bin for backup
	@mkdir -p $(build_dir)/$(qualifier)/patches
	@cp $(build_dir)/$(qualifier)/cxi/exefs_dir/code.bin $(build_dir)/$(qualifier)/patches/code.bin.original
	# Run Ghidra patch script to modify code.bin
	@QUALIFIER=$(qualifier) BUILD_DIR=$(build_dir) bin/ghidra-patch.sh
	# Generate IPS patch
	@python3 bin/create_ips.py \
		$(build_dir)/$(qualifier)/patches/code.bin.original \
		$(build_dir)/$(qualifier)/cxi/exefs_dir/code.bin \
		$(build_dir)/$(qualifier)/patches/99k-limit.ips
	@echo "✅ IPS patch created: $(build_dir)/$(qualifier)/patches/99k-limit.ips"

ips-crowd-patch: crowd-pack
	@echo "Generating crowd data IPS patch..."
	@if [ ! -d $(build_dir)/crowd-$(qualifier)-unpacked ]; then \
		echo "Error: Unpacked crowd data not found. Run 'make crowd-unpack' first."; \
		exit 1; \
	fi
	# Find crowd data files to patch (typically .br files)
	@mkdir -p $(build_dir)/$(qualifier)/patches
	@echo "Searching for modified crowd data files..."
	@for file in $$(find $(build_dir)/crowd-$(qualifier)-packed -type f -name "*.br" 2>/dev/null); do \
		relpath=$$(echo $$file | sed "s|$(build_dir)/crowd-$(qualifier)-packed/||"); \
		original="$(build_dir)/$(qualifier)/romfs/$$relpath"; \
		if [ -f "$$original" ]; then \
			if ! cmp -s "$$file" "$$original"; then \
				patchname=$$(echo $$relpath | tr '/' '_' | sed 's/\.br$$//'); \
				echo "Creating IPS for $$relpath -> crowd-$$patchname.ips"; \
				python3 bin/create_ips.py "$$original" "$$file" \
					"$(build_dir)/$(qualifier)/patches/crowd-$$patchname.ips"; \
			fi; \
		fi; \
	done
	@echo "✅ Crowd IPS patches created in: $(build_dir)/$(qualifier)/patches/"

ghidra-patch:
	QUALIFIER=$(qualifier) BUILD_DIR=$(build_dir) bash bin/ghidra-patch.sh

ghidra-setup:
	bash bin/setup_ghidra.sh

GHIDRA_VERSION ?= 11.4
GHIDRA_IMAGE ?= ghidra-headless:$(GHIDRA_VERSION)
GHIDRA_SLIM_IMAGE ?= ghidra-headless-slim:latest

ghidra-image:
	@if ! command -v $(CONTAINER_ENGINE) >/dev/null 2>&1; then \
		echo "Error: $(CONTAINER_ENGINE) not found. Install Docker or set CONTAINER_ENGINE=podman"; \
		exit 127; \
	fi
	$(CONTAINER_ENGINE) build --build-arg GHIDRA_VERSION=$(GHIDRA_VERSION) -t $(GHIDRA_IMAGE) -f docker/ghidra/Dockerfile docker/ghidra

ips-99k-patch-docker: ghidra-image
	@echo "Running 99k limit patch inside Docker (Ghidra $(GHIDRA_VERSION))"
	@if [ ! -f $(build_dir)/$(qualifier)/cxi/exefs_dir/code.bin ]; then \
		echo "Error: code.bin not found. Run 'make cia-unpack' first."; \
		exit 1; \
	fi
	@mkdir -p $(build_dir)/$(qualifier)/patches
	@if [ ! -f $(build_dir)/$(qualifier)/patches/code.bin.original ]; then \
		cp $(build_dir)/$(qualifier)/cxi/exefs_dir/code.bin $(build_dir)/$(qualifier)/patches/code.bin.original; \
		echo "Backed up original code.bin"; \
	fi
	$(CONTAINER_ENGINE) run --rm \
		-v $$PWD:/.ws -w /.ws \
		$(GHIDRA_IMAGE) \
		$(build_dir)/$(qualifier)/ghidra bd-$(qualifier) \
		-import $(build_dir)/$(qualifier)/cxi/exefs_dir/code.bin \
		-scriptPath ghidra_scripts \
		-processor ARM:LE:32:v7 \
		-postScript 999k-limit-patch.py
	@python3 bin/create_ips.py \
		$(build_dir)/$(qualifier)/patches/code.bin.original \
		$(build_dir)/$(qualifier)/cxi/exefs_dir/code.bin \
		$(build_dir)/$(qualifier)/patches/99k-limit.docker.ips
	@echo "✅ Docker IPS patch created: $(build_dir)/$(qualifier)/patches/99k-limit.docker.ips"

ghidra-slim-image:
	@if [ ! -d ghidra ]; then \
		echo "Error: local 'ghidra' directory not found. Download Ghidra zip from https://github.com/NationalSecurityAgency/ghidra/releases and unzip to ./ghidra"; \
		exit 1; \
	fi
	$(CONTAINER_ENGINE) build -t $(GHIDRA_SLIM_IMAGE) -f docker/ghidra/Dockerfile.slim docker/ghidra

ips-99k-patch-docker-slim: ghidra-slim-image
	@echo "Running patch in slim container using local ghidra distribution" 
	@if [ ! -f $(build_dir)/$(qualifier)/cxi/exefs_dir/code.bin ]; then \
		echo "Error: code.bin not found. Run 'make cia-unpack' first."; \
		exit 1; \
	fi
	@mkdir -p $(build_dir)/$(qualifier)/patches
	@if [ ! -f $(build_dir)/$(qualifier)/patches/code.bin.original ]; then \
		cp $(build_dir)/$(qualifier)/cxi/exefs_dir/code.bin $(build_dir)/$(qualifier)/patches/code.bin.original; \
	fi
	$(CONTAINER_ENGINE) run --rm -v $$PWD:/.ws -w /.ws $(GHIDRA_SLIM_IMAGE) \
		$(build_dir)/$(qualifier)/ghidra bd-$(qualifier) \
		-import $(build_dir)/$(qualifier)/cxi/exefs_dir/code.bin \
		-scriptPath ghidra_scripts \
		-processor ARM:LE:32:v7 \
		-postScript 999k-limit-patch.py
	@python3 bin/create_ips.py \
		$(build_dir)/$(qualifier)/patches/code.bin.original \
		$(build_dir)/$(qualifier)/cxi/exefs_dir/code.bin \
		$(build_dir)/$(qualifier)/patches/99k-limit.docker-slim.ips
	@echo "✅ Slim Docker IPS patch created: $(build_dir)/$(qualifier)/patches/99k-limit.docker-slim.ips"

clean:
	rm -rf build
