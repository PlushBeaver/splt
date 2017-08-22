# SPLT: record packet lengths and arrival times

Intended for use in network-related data analysis.
Recording only incoming traffic is domain-specific, not technical limitation.
Output is CSV for easy parsing and efficient compression.

Example:

`./splt eth0 'tcp port 80' | gzip -c >http.csv.gz`
