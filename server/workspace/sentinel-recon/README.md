# Sentinel Recon

A multithreaded network reconnaissance scanner built and validated using the **Sentinel Primordial IDE**.

## Features

- Concurrent port scanning with configurable thread pool
- Service identification for 19 common services
- Banner grabbing for service fingerprinting
- JSON export for integration with other tools
- Flexible port specification (ranges, lists, mixed)

## Usage

```bash
python scanner.py <target> <ports>
python scanner.py 192.168.1.1 22,80,443,8080
python scanner.py 10.0.0.1 1-1024
```

## Testing

```bash
python test_scanner.py
```

## Built With

Sentinel Primordial IDE - Universal Web IDE with autonomous agent capabilities.
