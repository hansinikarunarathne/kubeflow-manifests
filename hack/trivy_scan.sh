#!/bin/bash

# Directory containing the text files
DIRECTORY="./docs/image_lists"

mkdir -p "${DIRECTORY}/security_scan_reports"

echo "Started scanning images"
# Loop through each text file in the specified directory
for file in "$DIRECTORY"/*.txt; do
    while IFS= read -r line; do
        # Extract the image name (removing the tag/version)
        image_name=$(echo "$line" | cut -d':' -f1)
        echo "Scanning $image_name"
        if [[ "$image_name" == *"/"* ]]; then
                image_name_scan=$(echo "$image_name" | awk -F'/' '{print $NF}')
        fi
        trivy image --format json --output "${DIRECTORY}/security_scan_reports/${image_name_scan}_scan.json" "$image_name"
    done < "$file"
done