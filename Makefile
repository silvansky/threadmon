CC=clang
OPTS=-Wall -pedantic
LOPTS=-framework Security -framework CoreFoundation -sectcreate __TEXT __info_plist ./Info.plist
SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)

TARGET=threadmon

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LOPTS) -o $@ $^
	codesign -s "ThreadmonCert" ./$@

.c.o:
	$(CC) -c $(OPTS) $<

clean:
	rm $(TARGET) $(OBJECTS)

install:
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm /usr/local/bin/$(TARGET)
