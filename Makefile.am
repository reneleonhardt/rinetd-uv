
AUTOMAKE_OPTIONS = foreign dist-bzip2

SUBDIRS = src

EXTRA_DIST = bootstrap COPYING CHANGES.md README.md DOCUMENTATION.md BUILD.md \
	BUFFER_OPTIMIZATION.md TCP-UDP_MIXED_MODE.md CLEANUP_SUMMARY.md \
	index.html rinetd.vcxproj generate-manpage.sh generate-html.sh \
	$(man_MANS) $(sysconf_DATA)

man_MANS = rinetd-uv.8
sysconf_DATA = rinetd-uv.conf
noinst_DATA = index.html

# Generate man page from DOCUMENTATION.md using pandoc (if available)
rinetd-uv.8: DOCUMENTATION.md
	@if which pandoc >/dev/null 2>&1; then \
		echo "Generating man page from DOCUMENTATION.md..."; \
		./generate-manpage.sh; \
	else \
		echo "Warning: pandoc not found, keeping existing rinetd-uv.8"; \
		touch $@; \
	fi

# Generate HTML from DOCUMENTATION.md using pandoc (if available)
# Falls back to roffit if pandoc is not available (for backward compatibility)
index.html: DOCUMENTATION.md
	@if which pandoc >/dev/null 2>&1; then \
		echo "Generating HTML from DOCUMENTATION.md..."; \
		./generate-html.sh; \
	elif [ -f rinetd-uv.8 ] && which roffit >/dev/null 2>&1; then \
		echo "Using roffit to generate HTML from rinetd-uv.8..."; \
		roffit < rinetd-uv.8 > $@; \
	else \
		echo "Warning: neither pandoc nor roffit found, keeping existing index.html"; \
		touch $@; \
	fi

# Convenience targets for documentation generation
.PHONY: docs docs-man docs-html

docs: docs-man docs-html

docs-man: rinetd-uv.8

docs-html: index.html

# This is for Travis CI; we don't have a testsuite yet.
test:

