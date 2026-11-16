# Flapping and duplicate alerts

Applies to repeated alerts such as high load or disk usage that fire and clear many times.

Steps:
1. Confirm de-duplication grouped the repeats into one alert with an occurrence count.
2. Check whether the threshold matches the workload; tune it at the source.
3. Use a suppression rule only with an expiry and a reason, never permanently.
4. Medium-severity noise does not open incidents on its own.
