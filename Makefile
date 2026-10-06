.PHONY: all check test test-all test-perf perf verify view dashboard status stop clean restore-strict jwt-refresh
all:
	python3 scripts/zta.py start
check:
	python3 scripts/zta.py check
test test-all:
	python3 scripts/zta.py test
perf test-perf:
	python3 scripts/zta.py perf
verify:
	python3 scripts/zta.py verify
view dashboard:
	python3 scripts/zta.py dashboard
status:
	python3 scripts/zta.py status
stop clean:
	python3 scripts/zta.py stop
restore-strict:
	python3 scripts/zta.py restore-strict
jwt-refresh:
	python3 scripts/zta.py jwt-refresh