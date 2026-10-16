# Third-party assets

The repository includes local runtime assets so the analyzer can operate
without fetching browser or geolocation resources.

| Asset | Version/build | License/source |
| --- | --- | --- |
| Chart.js | 4.5.1 | MIT, https://www.chartjs.org |
| Font Awesome Free | 6.0.0 | Icons CC BY 4.0, fonts SIL OFL 1.1, code MIT |
| Inter | downloaded CSS subsets | SIL Open Font License, https://fonts.google.com/specimen/Inter |
| Tailwind CSS output | 4.3.0 | MIT; generated from the project templates |
| GeoLite2 City | build 2026-07-14 05:32:54 UTC | MaxMind GeoLite2, https://dev.maxmind.com/geoip/geolite2-free-geolocation-data |
| GeoLite2 ASN | build 2026-07-16 08:15:34 UTC | MaxMind GeoLite2, https://dev.maxmind.com/geoip/geolite2-free-geolocation-data |
| CPython Windows installer | 3.12.x, x64 | Python Software Foundation License |
| Wireshark Windows installer | 4.6.8, x64 | GPL-2.0-or-later |

GeoLite2 SHA-256 checksums:

```text
E2765534F9FC6E0BCDA4C46D8BC58BFAC5FEEA6CA2D5581219E53C99CD3B073D  GeoLite2-City.mmdb
EF828BC0E65E36357D8D5B5905F4F3ED34FA7F3AE1F3BC9596DED92DBE24D8EF  GeoLite2-ASN.mmdb
```

Bundle-root installer SHA-256 checksums:

```text
C6BDF93F4B2DE6DFA1A3A847E7C24AE10EDF7F6318653D452CD4381415700ADA  python-3.12.0-amd64.exe
8EBA737CB6875D9B3709228D37893F71125BDC50D7148E24D9CDC755259E9C3A  Wireshark-x64.exe
```

Both installers have valid Authenticode signatures from their respective
foundations. The Python packages installed through the requirements files
retain their own licenses. Ollama and model weights are optional local
components and are not redistributed here.
