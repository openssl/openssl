IMAGE_SRC = overview.dot
IMAGES = $(patsubst %.dot,images/%.png,$(IMAGE_SRC))

.PHONY: all

all: $(IMAGES)

images/%.png : %.dot
	dot -Tpng $< >$@
