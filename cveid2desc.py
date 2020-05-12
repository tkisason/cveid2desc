#!/usr/bin/env python3
# cat nvdcve-1.1-2020.json | jq '.CVE_Items[].cve'   | jq -r '{(.CVE_data_meta.ID):(.description.description_data[].value)}'

import json 


def generate_dataset():
    dataset = {}
    files = ['nvdcve-1.1-2016.json', 'nvdcve-1.1-2017.json', 'nvdcve-1.1-2018.json', 'nvdcve-1.1-2019.json', 'nvdcve-1.1-2020.json', 'nvdcve-1.1-2010.json']
    for file in files:
        CVE = json.loads(open(file).read())
        for CVE_Item in CVE['CVE_Items']:
            id = CVE_Item['cve']['CVE_data_meta']['ID']
            desc = CVE_Item['cve']['description']['description_data'][0]['value']
            dataset[id] = desc
    return dataset


def add_info_to_file(filein, fileout, dataset):
    outfile = open(fileout, 'w')
    for line in open(filein):
        id = line.rstrip()
        line = id + '\t' + dataset[id] + '\n'
        outfile.write(line)
    outfile.close()
