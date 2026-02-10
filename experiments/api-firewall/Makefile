TARGET := api-firewall

all: gen build

gen:
	go generate ./...

build:
	go build -o $(TARGET)

run: build
	sudo ./$(TARGET)

clean:
	rm -f bpf_bpf*
	rm -f $(TARGET)
	rm -f bpf/*.o
