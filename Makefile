.PHONY: install test eval demo run mcp stack record

install:
	pip install -r requirements.txt

test:
	pytest -q

eval:
	python -m evals.run_eval

demo:
	python -m scripts.demo

run:
	uvicorn ccagent.api.app:create_app --factory --port 8080

mcp:
	python -m ccagent.mcp_server

stack:
	python -m scripts.run_all

record:
	python -m scripts.record_demo && python -m scripts.build_demo_page
