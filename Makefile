CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -D_DEFAULT_SOURCE -Iinclude
LDFLAGS = -lpcap

APP_TARGET = bin/packet_ids
APP_SRC = src/packet_ids_cli.c src/ids_tracker.c src/alert_logger.c src/alert_export.c src/parse_utils.c src/packet_parser.c src/capture_source.c src/bpf_filter.c src/perf_metrics.c

SETUP_CHECK_TARGET = bin/pcap_setup_check
SETUP_CHECK_SRC = src/pcap_setup_check.c
INTERFACE_LIST_TARGET = bin/interface_list
INTERFACE_LIST_SRC = src/interface_list.c
CAPTURE_BASIC_TARGET = bin/live_capture_basic
CAPTURE_BASIC_SRC = src/live_capture_basic.c
PARSE_DEMO_TARGET = bin/packet_header_parser_demo
PARSE_DEMO_SRC = src/packet_header_parser_demo.c
IDS_RULE_DEMO_TARGET = bin/ids_live_rule_demo
IDS_RULE_DEMO_SRC = src/ids_live_rule_demo.c src/ids_tracker.c src/alert_logger.c src/alert_export.c src/parse_utils.c src/bpf_filter.c
TRACKER_TEST_TARGET = bin/ids_tracker_test
TRACKER_TEST_SRC = tests/ids_tracker_test.c src/ids_tracker.c
REPLAY_DEMO_TARGET = bin/ids_live_or_pcap
REPLAY_DEMO_SRC = src/ids_live_or_pcap.c src/ids_tracker.c src/alert_logger.c src/alert_export.c src/parse_utils.c src/packet_parser.c src/capture_source.c src/bpf_filter.c src/perf_metrics.c
INTEGRATION_TEST_TARGET = bin/pcap_integration_test
INTEGRATION_TEST_SRC = tests/pcap_integration_test.c

.PHONY: all app setup_check list_interfaces capture_basic parse_headers_demo ids_rule_demo tracker_test replay_demo integration_test clean

all: app

app: $(APP_TARGET)

setup_check: $(SETUP_CHECK_TARGET)

list_interfaces: $(INTERFACE_LIST_TARGET)

capture_basic: $(CAPTURE_BASIC_TARGET)

parse_headers_demo: $(PARSE_DEMO_TARGET)

ids_rule_demo: $(IDS_RULE_DEMO_TARGET)

tracker_test: $(TRACKER_TEST_TARGET)

replay_demo: $(REPLAY_DEMO_TARGET)

integration_test: $(INTEGRATION_TEST_TARGET) $(REPLAY_DEMO_TARGET)
	./$(INTEGRATION_TEST_TARGET)

$(APP_TARGET): $(APP_SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(APP_SRC) -o $(APP_TARGET) $(LDFLAGS)

$(SETUP_CHECK_TARGET): $(SETUP_CHECK_SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(SETUP_CHECK_SRC) -o $(SETUP_CHECK_TARGET) $(LDFLAGS)

$(INTERFACE_LIST_TARGET): $(INTERFACE_LIST_SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(INTERFACE_LIST_SRC) -o $(INTERFACE_LIST_TARGET) $(LDFLAGS)

$(CAPTURE_BASIC_TARGET): $(CAPTURE_BASIC_SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(CAPTURE_BASIC_SRC) -o $(CAPTURE_BASIC_TARGET) $(LDFLAGS)

$(PARSE_DEMO_TARGET): $(PARSE_DEMO_SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(PARSE_DEMO_SRC) -o $(PARSE_DEMO_TARGET) $(LDFLAGS)

$(IDS_RULE_DEMO_TARGET): $(IDS_RULE_DEMO_SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(IDS_RULE_DEMO_SRC) -o $(IDS_RULE_DEMO_TARGET) $(LDFLAGS)

$(TRACKER_TEST_TARGET): $(TRACKER_TEST_SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(TRACKER_TEST_SRC) -o $(TRACKER_TEST_TARGET)

$(REPLAY_DEMO_TARGET): $(REPLAY_DEMO_SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(REPLAY_DEMO_SRC) -o $(REPLAY_DEMO_TARGET) $(LDFLAGS)

$(INTEGRATION_TEST_TARGET): $(INTEGRATION_TEST_SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(INTEGRATION_TEST_SRC) -o $(INTEGRATION_TEST_TARGET) $(LDFLAGS)

clean:
	rm -rf bin
