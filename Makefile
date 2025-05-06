# ==== Пути ====
SRC_DIR = src
TEST_DIR = tests

# ==== Цели ====

help:
	@echo "Доступные команды:"
	@echo "  install         - Установить зависимости через poetry"
	@echo "  test            - Запустить тесты"
	@echo "  run             - Запустить сервер API"
	@echo "  lint            - Проверить стиль кода с помощью flake8"
	@echo "  format          - Форматировать код с помощью black"
	@echo "  venv            - Создать виртуальное окружение"
	@echo "  docker-build    - Собрать Docker-образ"
	@echo "  docker-run      - Запустить сервер в Docker"
	@echo "  clean           - Очистить временные файлы"

# ==== Инсталляция ====

install:
	poetry install

venv:
	python -m venv venv
	@echo "Активируйте виртуальное окружение командой: source venv/bin/activate"

# ==== Тестирование ====

test:
	poetry run pytest $(TEST_DIR)/test.py -v

test-cov:
    poetry run pytest --cov=api_scoring $(TEST_DIR)/test.py -v

# ==== Запуск ====

run:
	poetry run python -m src.api_scoring.api

# ==== Линтинг и форматирование ====

lint:
	poetry run flake8 $(SRC_DIR) $(TEST_DIR)

format:
	poetry run black src tests

# ==== Docker ====

docker-build:
	docker build -t scoring-api .

docker-run:
	docker run -p 8080:8080 scoring-api

# ==== Очистка ====

clean:
	rm -rf __pycache__ \
	       *.pyc \
           .pytest_cache \
           htmlcov \
           .coverage \
           .tox \
           dist \
           build \
           *.egg-info \
           venv
	@echo "Очистка завершена"
