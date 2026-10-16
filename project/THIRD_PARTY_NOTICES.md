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

GeoLite2 SHA-256 checksums:

```text
E2765534F9FC6E0BCDA4C46D8BC58BFAC5FEEA6CA2D5581219E53C99CD3B073D  GeoLite2-City.mmdb
EF828BC0E65E36357D8D5B5905F4F3ED34FA7F3AE1F3BC9596DED92DBE24D8EF  GeoLite2-ASN.mmdb
```

The Python packages installed through the requirements files retain their own
licenses. Wireshark/TShark and Ollama are optional external programs and are not
redistributed here.
