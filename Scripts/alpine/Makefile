PKGDIR=main/age-plugin-se
ABUILD_FLAGS=-r -D "age-plugin-se repository" -P $(CURDIR)/packages

all:
	cd $(PKGDIR) && abuild $(ABUILD_FLAGS)

clean:
	cd $(PKGDIR) && abuild $(ABUILD_FLAGS) cleanpkg

update-checksums:
	cd $(PKGDIR) && abuild $(ABUILD_FLAGS) checksum
