#!/usr/bin/env python3
# cat nvdcve-1.1-2020.json | jq '.CVE_Items[].cve'   | jq -r '{(.CVE_data_meta.ID):(.description.description_data[].value)}'

import json


def extract_descriptions():
    id_desc_dataset = {}
    files = [
        "nvdcve-1.1-2016.json",
        "nvdcve-1.1-2017.json",
        "nvdcve-1.1-2018.json",
        "nvdcve-1.1-2019.json",
        "nvdcve-1.1-2020.json",
        "nvdcve-1.1-2010.json",
    ]
    for file in files:
        CVE = json.loads(open(file).read())
        for CVE_Item in CVE["CVE_Items"]:
            id = CVE_Item["cve"]["CVE_data_meta"]["ID"]
            desc = CVE_Item["cve"]["description"]["description_data"][0]["value"]
            id_desc_dataset[id] = desc
    return id_desc_dataset


def extract_patches():
    id_patch_dataset = {}
    files = [
        "nvdcve-1.1-2016.json",
        "nvdcve-1.1-2017.json",
        "nvdcve-1.1-2018.json",
        "nvdcve-1.1-2019.json",
        "nvdcve-1.1-2020.json",
        "nvdcve-1.1-2010.json",
    ]
    for file in files:
        CVE = json.loads(open(file).read())
        for CVE_Item in CVE["CVE_Items"]:
            id = CVE_Item["cve"]["CVE_data_meta"]["ID"]
            urls = ""
            for item in CVE_Item["cve"]["references"]["reference_data"]:
                if "Patch" in item["tags"]:
                    if urls == "":
                        urls = item["url"]
                    else:
                        urls += " ; " + item["url"]
            if urls != "":
                id_patch_dataset[id] = urls
    return id_patch_dataset


def add_info_to_file(filein, fileout, dataset_desc, dataset_patch):
    outfile = open(fileout, "w")
    for line in open(filein):
        id = line.rstrip()
        if id in dataset_patch:
            line = id + "\t" + dataset_desc[id] + "\t" + dataset_patch[id] + "\n"
        else:
            line = id + "\t" + dataset_desc[id] + "\n"
        outfile.write(line)
    outfile.close()
