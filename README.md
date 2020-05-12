# cveid2desc
Use NVD CVE files to get a description from a set CVE ID in a file

generate_dataset - Parses a bunch of NIST NVD datafiles available from https://nvd.nist.gov/vuln/data-feeds .
Converts a set number of files to a dictionary of {nvdID:description} pairs, and returns them, later on we use the same dataset to enrich a file with CVE ID's to add descriptions. 

This can be used to enrich systems that drop a CVE ID for something with some context on that said CVE... 
