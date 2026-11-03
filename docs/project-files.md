# Project files (`.dgproj`)

A project file stores everything the web UI needs to continue editing: the configuration, its supporting files and the graph layout. It is a zip archive (deterministic, like the deployment packages):

```text
project.dgproj
├── project.json      # format metadata + graph layout
├── config.json       # the configuration document
└── files/            # supporting files, same relative names as in config.json
    └── certs/ca.pem
```

`project.json`:

```json
{
  "formatVersion": 1,
  "tool": "dg-configurator",
  "layout": {
    "nodes": {
      "1": {"x": 40, "y": 40},
      "2": {"x": 680, "y": 40}
    }
  }
}
```

| Field | Meaning |
|---|---|
| `formatVersion` | Version of this file format; currently `1`. Files with another version are rejected |
| `tool` | Name of the tool that wrote the file |
| `layout.nodes` | Position of each endpoint node, keyed by endpoint id |

The format is versioned so that future changes can be documented here as `formatVersion: 2` and later. Importing a project that is missing `config.json` or `project.json` fails with an error message.
