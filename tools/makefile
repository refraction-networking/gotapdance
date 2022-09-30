
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
BINARY_NAMES=clientconf v6lookup elligator-test utls-test # cjprobe


all: build
build:
	mkdir -p bin;
	for binary in $(BINARY_NAMES) ; do \
		echo "building $$binary"; \
		cd $$binary && $(GOBUILD) -o ../bin/$$binary ; \
		cd -; \
	done

cc:
	echo "building clientconf"; \
	cd clientconf && $(GOBUILD) -o ../bin/clientconf ; \
	cd ../; \

cc2:
	echo "building clientconf2"; \
	cd clientconf2 && $(GOBUILD) -o ../bin/clientconf2 ; \
	cd ../; \

v6lookup:
	echo "building v6lookup"; \
	cd v6lookup && $(GOBUILD) -o ../bin/v6lookup ; \
	cd ../; \

cjprobe:
	echo "building conjure probe tool"; \
	cd cjprobe && $(GOBUILD) -o ../bin/cjprobe ; \
	cd ../; \

elligator-test:
	echo "building elligator-test"; \
	cd elligator-test && $(GOBUILD) -o ../bin/elligator-test ; \
	cd ../; \

utls-test:
	echo "building utls-test"; \
	cd utls-test && $(GOBUILD) -o ../bin/utls ; \
	cd -; \

test: 
		$(GOTEST) ./...
clean: 
		$(GOCLEAN)
		rm -rf bin
