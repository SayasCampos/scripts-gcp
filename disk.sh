#!/bin/bash

CSV_FILE="disks.csv"

# Add rows to CSV file
echo "name,type,sizeGb,architecture,zone,creationTimestamp,users,resourcePolicies" > $CSV_FILE

ORG_IDS=("735126565061")

for ORG_ID in "${ORG_IDS[@]}"
do
    echo "Folder or organization: $ORG_ID"
    for PROJECT_ID in $(gcloud projects list --format="value(projectId)" --filter="parent.id=$ORG_ID")
    do
        echo "  Project ID: $PROJECT_ID"
        disk=$(gcloud compute disks list --project=$PROJECT_ID  --format="value(name)") #List all disk throught projects
        
        validate_disks=$(gcloud compute addresses list --project=$PROJECT_ID  --format="value(name)" | wc -l)  #Validate in the project if we have disks
        if [[ $validate_disks -eq 0 ]]; then
            echo "No Disks in this project or the user does not have permission to list the Disks"
        else
            # Add to the CSV file
            gcloud compute disks list --project=$PROJECT_ID  --format="csv($PROJECT_ID,name,type,sizeGb,architecture,zone,creationTimestamp,users,resourcePolicies)" | sed -E 's|https://www.googleapis.com/compute/v1/projects/[^/]*/zones/||g; s|https://www.googleapis.com/compute/v1/projects/[^/]+/regions/[^/]+/resourcePolicies/||g' >> $CSV_FILE
        fi
    done
done

echo "Datos guardados en $CSV_FILE"
