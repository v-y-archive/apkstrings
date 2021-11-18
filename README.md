# apkstrings
Get all APK package strings from .dex strings table and .so libraries.

### Usage

```python
from apkstrings import get_package_strings

try:
    apk_path = input("Please specify APK:")
    strings = get_package_strings(apk_path, analyze_dex=True, analyze_so=True)
    [print(s) for s in strings if "something" in s]

except APKParseException:
    exit("Wrong APK file.")
```
