## JA4proxy PDF Documentation Makefile
## Builds all three documents: brochure, user-guide, reference-manual

LATEX     = pdflatex
LATEXOPTS = -interaction=nonstopmode -halt-on-error -file-line-error
MAKEINDEX = makeindex

BROCHURE  = brochure/brochure.tex
UGDIR     = user-guide
RMDIR     = reference-manual

.PHONY: all brochure user-guide reference-manual clean distclean

all: brochure user-guide reference-manual

## ── Brochure ──────────────────────────────────────────────────────────────────
brochure: brochure/brochure.pdf

brochure/brochure.pdf: brochure/brochure.tex brochure/brochure-body.tex \
                        shared/ja4proxy-style.sty \
                        shared/artwork/cover-common.tex \
                        shared/artwork/cover-back.tex
	@echo "==> Building brochure (pass 1)..."
	@cd brochure && $(LATEX) $(LATEXOPTS) brochure.tex
	@echo "==> Building brochure (pass 2)..."
	@cd brochure && $(LATEX) $(LATEXOPTS) brochure.tex
	@echo "==> brochure/brochure.pdf ready."

## ── User Guide ───────────────────────────────────────────────────────────────
user-guide: user-guide/user-guide.pdf

user-guide/user-guide.pdf: user-guide/user-guide.tex \
    $(wildcard user-guide/chapters/*.tex) \
    shared/ja4proxy-style.sty \
    shared/artwork/cover-common.tex \
    shared/artwork/cover-back.tex
	@echo "==> Building user-guide (pass 1)..."
	@cd user-guide && $(LATEX) $(LATEXOPTS) user-guide.tex
	@echo "==> Building user-guide (pass 2: index)..."
	@cd user-guide && $(MAKEINDEX) user-guide.idx 2>/dev/null || true
	@echo "==> Building user-guide (pass 3: refs)..."
	@cd user-guide && $(LATEX) $(LATEXOPTS) user-guide.tex
	@echo "==> user-guide/user-guide.pdf ready."

## ── Reference Manual ─────────────────────────────────────────────────────────
reference-manual: reference-manual/reference-manual.pdf

reference-manual/reference-manual.pdf: reference-manual/reference-manual.tex \
    $(wildcard reference-manual/chapters/*.tex) \
    shared/ja4proxy-style.sty \
    shared/artwork/cover-common.tex \
    shared/artwork/cover-back.tex
	@echo "==> Building reference-manual (pass 1)..."
	@cd reference-manual && $(LATEX) $(LATEXOPTS) reference-manual.tex
	@echo "==> Building reference-manual (pass 2: index)..."
	@cd reference-manual && $(MAKEINDEX) reference-manual.idx 2>/dev/null || true
	@echo "==> Building reference-manual (pass 3: refs)..."
	@cd reference-manual && $(LATEX) $(LATEXOPTS) reference-manual.tex
	@echo "==> reference-manual/reference-manual.pdf ready."

## ── Clean ────────────────────────────────────────────────────────────────────
clean:
	@for d in brochure user-guide reference-manual; do \
	  echo "Cleaning $$d..."; \
	  cd $$d && rm -f *.aux *.log *.toc *.idx *.ind *.ilg *.out \
	            *.lof *.lot *.synctex.gz *.fls *.fdb_latexmk \
	            *.nav *.snm *.vrb 2>/dev/null; \
	  cd ..; \
	done

distclean: clean
	@rm -f brochure/brochure.pdf
	@rm -f user-guide/user-guide.pdf
	@rm -f reference-manual/reference-manual.pdf
	@echo "All PDFs removed."
