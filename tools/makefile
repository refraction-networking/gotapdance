
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
BINARY_NAMES=clientconf v6lookup elligator-test


all: test build
build:
	mkdir -p bin;
	for binary in $(BINARY_NAMES) ; do \
		echo "building $$binary"; \
		cd $$binary && $(GOBUILD) -o ../bin/$$binary ; \
		cd ../; \
	done

clientconf:
	echo "building clientconf"; \
	cd clientconf && $(GOBUILD) -o ../bin/clientconf ; \
	cd ../; \

v6lookup:
	echo "building v6lookup"; \
	cd v6lookup && $(GOBUILD) -o ../bin/v6lookup ; \
	cd ../; \

elligator-test:
	echo "building elligator-test"; \
	cd elligator-test && $(GOBUILD) -o ../bin/elligator-test ; \
	cd ../; \

test: 
		$(GOTEST) ./...
clean: 
		$(GOCLEAN)
		rm -rf bin