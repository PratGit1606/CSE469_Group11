.PHONY: all clean

all: bchoc

bchoc: main.py
	echo "#!/usr/bin/env bash" > bchoc
	echo "python3 \$$PWD/main.py \$$@" >> bchoc
	chmod +x bchoc

clean:
	rm -f bchoc
