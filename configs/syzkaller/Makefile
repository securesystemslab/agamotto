FIXUP=../../scripts/fixup.py

MODES=baseline agamotto snapshot

HOST?=localhost
PORT?=56841
WORKDIR?=workdir
VMCNT?=1

CONFIGS=usb.rsi usb.mwifiex usb.ar5523 usb.btusb usb.usx2y usb.pn533 usb.go7007 usb.si470x

files := $(foreach mode,$(MODES),$(foreach config,$(CONFIGS),generated/$(mode)-$(config).cfg))
files_1 := $(foreach mode,$(MODES),$(foreach config,$(CONFIGS),generated/$(mode)-$(config).cfg.1))
files_2 := $(foreach mode,$(MODES),$(foreach config,$(CONFIGS),generated/$(mode)-$(config).cfg.2))
files_3 := $(foreach mode,$(MODES),$(foreach config,$(CONFIGS),generated/$(mode)-$(config).cfg.3))

all: $(files) $(files_1) $(files_2) $(files_3)

generated/%-2d.cfg: %-2d.cfg |generated
	$(FIXUP) -i $^ -o $@ -c $(VMCNT) -t $(HOST) -p $(PORT) -w $(WORKDIR)

generated/%.cfg: %.cfg |generated
	$(FIXUP) -i $^ -o $@ -c $(VMCNT) -t $(HOST) -p $(PORT) -w $(WORKDIR)

generated/%.cfg.1: %.cfg |generated
	$(FIXUP) -i $^ -o $@ -c $(VMCNT) -t $(HOST) -p $(PORT) -w $(WORKDIR) -r 1

generated/%.cfg.2: %.cfg |generated
	$(FIXUP) -i $^ -o $@ -c $(VMCNT) -t $(HOST) -p $(PORT) -w $(WORKDIR) -r 2

generated/%.cfg.3: %.cfg |generated
	$(FIXUP) -i $^ -o $@ -c $(VMCNT) -t $(HOST) -p $(PORT) -w $(WORKDIR) -r 3

generated:
	mkdir -p generated

clean:
	rm -rf generated
