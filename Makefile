start:
	@echo "Starting app ..."
	docker-compose up -d

stop:
	@echo "Stopping app ..."
	docker-compose down
