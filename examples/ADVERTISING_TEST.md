**Advertising Test Guide**

This short guide explains how to test the BlueZ-based advertiser and the project's scanner so your teammates can reproduce the results.

**Prerequisites**
- Linux machine(s) with a BLE adapter (hci0). BlueZ installed and running.
- Python virtualenv with project dependencies: create and activate `.venv` then `pip install -r requirements.txt`.
- If you will run the advertiser on the Linux machine that hosts BlueZ you will typically need `sudo` (or proper polkit/capabilities configured).

Files of interest
- `common/ble_advertiser_bluez.py` — BlueZ advertiser helper (registers LEAdvertisement1).
- `examples/advertise_ble_example.py` — small advertiser example (registers for 10s by default).
- `examples/quick_ble_debug.py` — debug scanner that prints raw advertisement data.
- `examples/quick_ble_test.py` — project scanner that filters for the project's ManufacturerData format (company ID 0xFFFF + 16 byte NID + 4 byte HopCount).

Quick test (recommended: use TWO devices)
1) On Device A (advertiser): run the advertiser as root so it can register with BlueZ.

```fish
sudo .venv/bin/python3 examples/advertise_ble_example.py
```

This prints logs like:
- `Preparing ManufacturerData: company=0xFFFF len=20 bytes payload=...` (the hex payload)
- `Registering advertisement on BlueZ adapter /org/bluez/hci0`
- `Advertisement registered: NID=... Hop=...`

2) On Device B (scanner): run the debug scanner while Device A is advertising.

```fish
.venv/bin/python3 examples/quick_ble_debug.py --time 8
```

Look for a `manufacturer_data` dictionary containing the company id `65535` (0xFFFF). Example debug output line:

```
AdvertisementData(manufacturer_data={65535: b'...'}, rssi=-XX)
```

If you see `manufacturer_data` with the `65535` key and a bytes value of length 20, `examples/quick_ble_test.py` should also detect the device and report the NID and Hop Count.

Single-machine notes (common pitfalls)
- Many controllers do not show their own advertisements when scanning from the same adapter. If you run both advertiser and scanner on the same adapter you may not see the advert — use two devices (or a phone app) for reliable testing.
- Running the advertiser without `sudo` usually fails with D-Bus/permission errors. If you want to avoid `sudo`, see the section below.

Troubleshooting commands (run on the advertiser machine)
- Check adapter status:
  ```fish
  hciconfig -a
  ```
- Check BlueZ controller info:
  ```fish
  sudo btmgmt info
  bluetoothctl show
  systemctl status bluetooth --no-pager
  ```
- Check rfkill:
  ```fish
  rfkill list
  ```

Common errors and fixes
- `The name org.bluez was not provided by any .service files`: ensure `bluetooth.service` is running (`systemctl status bluetooth`) and run advertiser as root or configure polkit.
- `Failed to parse advertisement` or `parse_advertisement()` warnings in journal: we had an initial mismatch in properties (now fixed). If you still see parse warnings, ensure `common/ble_advertiser_bluez.py` is the version included in this repo (it logs the ManufacturerData it registers).

Run a phone-based advertiser (alternative)
- If you don't have a second Linux device, you can use a smartphone (Android/iOS) with the nRF Connect app to craft a Manufacturer Specific Data advertisement that matches the project's payload format:
  - Company ID: `65535` (0xFFFF)
  - Data bytes: 16 bytes for the NID (UUID) followed by 4 bytes little-endian hop count. Example NID: `00000000-0000-0000-0000-000000000001` and hop=1 produces bytes `00000000000000000000000000000101000000` (hex).

Allowing advertising without `sudo` (optional)
- Two common ways to avoid `sudo`:
  1. Grant the Python interpreter the `cap_net_raw` capability (less recommended for dev machines):
     ```fish
     sudo setcap cap_net_raw+eip $(which python3)
     ```
     Note: this affects the system python. If you limit to venv python copy the venv's `python3` path.
  2. Create a Polkit rule to allow registering advertisements for your user (safer, but requires writing a `.pkla` or JavaScript policy rule depending on distro). If you want, I can prepare a suggested polkit rule for your distro.

Integration notes for developers
- The `BLEConnectionManager` now exposes async helpers:
  - `await manager.start_advertising(hop_count)` — starts BlueZ advertising (returns False if BlueZ advertiser isn't available on platform).
  - `await manager.stop_advertising()` — stops advertising.
  - `manager.update_advertisement_hop(new_hop)` — updates hop in memory; re-registration required for BlueZ to apply the change.

Expected ManufacturerData format (project spec)
- Company ID: 2 bytes (0xFFFF) — used as the key in `manufacturer_data`.
- Payload: 20 bytes total: 16 bytes UUID (NID) + 4 bytes hop count (int32 little-endian).
- Example payload hex (NID `00000000-0000-0000-0000-000000000001`, hop=1):

```
00000000000000000000000000000101000000
```

If you want, I can add this document to `README.md` or create a short `docs/` page. I can also provide a sample polkit rule for your distro — tell me which Linux distribution you're using and I will prepare it.
