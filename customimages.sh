#!/bin/bash
CSV_FILE="customimages.csv"
ORG_IDS=("735126565061")

echo "name,archiveSizeBytes,diskSizeGb,creationTimestamp, architecture, storageLocations" > $CSV_FILE

for ORG_ID in "${ORG_IDS[@]}"
do
    echo "Carpetas o organization: $ORG_ID"
    for PROJECT_ID in $(gcloud projects list --format="value(projectId)" --filter="parent.id=$ORG_ID")
        do
            #Print the Project ID selected
            echo "  Project ID: $PROJECT_ID"

            #This command is to know if the project selected has a custom images  
            NUM_IMAGES=$(gcloud compute images list --project $PROJECT_ID --no-standard-images  --format="value(name)")
            echo "$NUM_IMAGES"    

            if [[ $NUM_IMAGES -eq 0 ]]; 
            then
                echo "Custom images do not exist in this project"
            else
                # Obtain the custom values of the images created by the client or myself 
                gcloud compute images list --project=$PROJECT_ID --no-standard-images --format="csv($PROJECT_ID,name,archiveSizeBytes,diskSizeGb,creationTimestamp, architecture, storageLocations)" >> $CSV_FILE
            fi        
        done
done    

echo "Datos guardados en $CSV_FILE"
