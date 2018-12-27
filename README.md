# DNS-Zone-Check
# This script uses WMI to check DNS A records for a given zone and looks for several things.
# It pings the host for Online status. It checks the A records to see if they are static and for staleness.
# It checks the PTR records for presence, and to see if they are static or stale.
# The output is color coded for the results.
# The host being online can be White, Green, or Yellow. 
# If the hostname and Online are in White, it has a Static A record.
# If the hostname and Online are in Green, it has a recently updated A record. 
# If the hostname and Online are in Yellow, it has a stale A record. 
# If the host is offline, it will be in Red.
# Static DNS records are White, Updated DNS records are Green, Stale DNS records are Yellow, No DNS records = Red
# If the reverse DNS zone exists it will be in Green.