ABUILD_FLAGS=-r -D "age-plugin-se repository" -P $(CURDIR)/packages

all:
	abuild $(ABUILD_FLAGS)

clean:
	-abuild $(ABUILD_FLAGS) cleanpkg

update-checksums:
	abuild $(ABUILD_FLAGS) checksum
