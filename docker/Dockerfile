# syntax=docker/dockerfile:1
FROM python:3.14-slim AS build
WORKDIR /src
RUN pip install --no-cache-dir "poetry>=2,<3"
COPY pyproject.toml poetry.lock README.md LICENSE ./
COPY src ./src
RUN poetry build -f wheel -o /dist

FROM python:3.14-slim AS runtime
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin app
COPY --from=build /dist /dist
RUN pip install --no-cache-dir /dist/*.whl && rm -rf /dist
USER app
WORKDIR /work
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
ENTRYPOINT ["dg-configurator"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080", "--allowed-host", "localhost", "--allowed-host", "127.0.0.1"]
