# Quick start

This ten-minute walkthrough builds a small MQTT-to-MQTT bridge in the web UI — the same scenario as `tests/fixtures/configs/valid/v1.0/minimal.json` — and packages it for deployment.

1. **Start the UI.** Run `dg-configurator serve --open-browser`. The UI is served on `http://127.0.0.1:8080`.
2. **Select the config version.** Leave the version selector in the toolbar on `1.1`, or choose `1.0` if your Data Gateway is older.
3. **Create two endpoints.** In the palette, add two `mqtt-client` endpoints. Select the first one and set its name to `mqtt-in` and its URL to `mqtt://broker.local:1883`; set the second to `mqtt-out` with the same URL.
4. **Add an input and an output.** Select `mqtt-in` and add an `mqtt-subscriber` input (name `temp`, message format `json`, topic `sensors/temp`). Select `mqtt-out` and add an `mqtt-publisher` output (name `temp-out`, message format `json`, topic `out/temp`).
5. **Connect them.** Drag from the input port (*Inputs (sources)*) of `mqtt-in` to the output port (*Outputs (sinks)*) of `mqtt-out`. The diagnostics panel at the bottom must show no errors.
6. **Export.** Use *Export config.json* to download the configuration, or *Save project* to keep the graph layout as a `.dgproj` file.
7. **Package.** Choose *Package…*. For a plain package leave *Sign* unchecked and select *Create package*; the browser downloads `config.zip`. For a signed package generate a key pair first with `dg-configurator keygen -o keys` and select `keys/private.pem` in the dialog (see [packages-and-signing.md](packages-and-signing.md)).
8. **Deploy.** Upload the zip to the Data Gateway via the "apply configuration" function of your Nerve installation. A signed package requires the matching public key to be configured on the Data Gateway.

The same flow on the command line:

```bash
dg-configurator validate config.json
dg-configurator pack config.json -o config.zip
```
