# GM69ProDecode example

Reads a scan from a GM69Pro barcode module over UART2, decodes the DOSIPAS
ticket on the ESP32 and prints the 33-column summary lines plus the full JSON
on the serial monitor.

## Wiring

| GM69Pro | ESP32-WROOM-32E |
|---|---|
| TX | GPIO33 (UART2 RX) |
| RX | GPIO32 (UART2 TX) |
| VCC / GND | 3V3 / GND |

UART: 9600 baud, 8N1. A scan is complete after about 50 ms without new bytes.
The sketch sets the UART RX buffer to 4096 bytes so a whole payload is buffered
even if `loop()` is late.

## Scanner settings that matter

The GM69Pro must output the Aztec payload **byte-exact**. The only setting found
to do that is the **"European double-byte characters" charset**:

```
16 4F 64 50 62 4E 62 63 2E
```

The factory default (GB2312) drops bytes from binary payloads, so tickets fail
to decode with that setting. The sketch sends the charset command at start-up.

The module beeps on every configuration command. Send the **mute command
first**:

```
16 57 61 5A 61 53 61 2E
```

Both commands are in `GM69ProDecode.ino`; the settings persist in the module,
so sending them at every boot is harmless.

## Build

With PlatformIO, from this directory (the library is picked up from `../..`):

```
pio run -e esp32dev            # with signature verification
pio run -e esp32dev_noverify   # without (about 39 KB less flash)
pio run -e esp32dev -t upload && pio device monitor
```

With the Arduino IDE: install the library (this repository) and open the
sketch. Board: ESP32 Dev Module.

## What you get

Illustrative output (timings depend on the ticket):

```
---------------------------------
U2 FCB3 issuer 1187
Intercode network 250502
Issued 2025-10-02 15:03Z
openTicket
From  2025-10-02 15:03Z
Until 2025-10-02 16:03Z
second class, 1x adult
Price 1.20 EUR
L2 signature VALID
---------------------------------
decode 1920 us, verify 51234 us (valid), arena 5088 B, stack high-water 5120 B, free heap 290000 B
{"format":"U2","level2SignedData":{...}}
```
