#!/usr/bin/env bash

# The script:
# 1. Extract all the images used by the Kubeflow Working Groups
# - The reported image lists are saved in respective files under ../docs/image_lists directory
# 2. Scan the reported images using Trivy for security vulnerabilities
# - Scanned reports will be saved in JSON format inside ../image_lists/security_scan_reports folder
# The script must be executed from the hack folder as it use relative paths

echo "Extracting Images"
images=()

declare -A wg_dirs=(
  [automl]="../apps/katib/upstream/installs"
  [pipelines]="../apps/pipeline/upstream/env ../apps/kfp-tekton/upstream/env"
  [training]="../apps/training-operator/upstream/overlays"
  [manifests]="../common/cert-manager/cert-manager/base ../common/cert-manager/kubeflow-issuer/base ../common/istio-1-17/istio-crds/base ../common/istio-1-17/istio-namespace/base ../common/istio-1-17/istio-install/overlays/oauth2-proxy ../common/oidc-client/oauth2-proxy/overlays/m2m-self-signed ../common/dex/overlays/oauth2-proxy ../common/knative/knative-serving/overlays/gateways ../common/knative/knative-eventing/base ../common/istio-1-17/cluster-local-gateway/base ../common/kubeflow-namespace/base ../common/kubeflow-roles/base ../common/istio-1-17/kubeflow-istio-resources/base"
  [workbenches]="../apps/pvcviewer-controller/upstream/base ../apps/admission-webhook/upstream/overlays ../apps/centraldashboard/upstream/overlays/oauth2-proxy ../apps/jupyter/jupyter-web-app/upstream/overlays ../apps/volumes-web-app/upstream/overlays ../apps/tensorboard/tensorboards-web-app/upstream/overlays ../apps/profiles/upstream/overlays ../apps/jupyter/notebook-controller/upstream/overlays ../apps/tensorboard/tensorboard-controller/upstream/overlays"
  [serving]="../contrib/kserve - ../contrib/kserve/models-web-app/overlays/kubeflow"
)

save_images() {
  wg=${1:-""}
  shift
  local images=("$@")
  output_file="../docs/image_lists/kf_${version}_${wg}_images.txt"
  printf "%s\n" "${images[@]}" > "$output_file"
  echo "File ${output_file} successfully created"
}

validate_semantic_version() {
  local version="${1:-"latest"}"

  local regex="^[0-9]+\.[0-9]+\.[0-9]+$"  # Regular expression for semantic version pattern
  if [[ $version  =~ $regex || $version = "latest" ]]; then
      echo "$version"
  else
      echo "Invalid semantic version: '$version'"
      return 1
  fi
}

if ! version=$(validate_semantic_version "$1") ; then
    echo "$version. Exiting script."
    exit 1
fi

echo "Running the script using Kubeflow version: $version"

for wg in "${!wg_dirs[@]}"; do
  declare -a dirs=(${wg_dirs[$wg]})
  wg_images=()
  for (( i=0; i<"${#dirs[@]}"; i++ )); do
    for F in $(find "${dirs[$i]}" \( -name kustomization.yaml   -o -name kustomization.yml -o -name Kustomization \)); do
        dir=$(dirname -- "$F")
        # Generate k8s resources specified in 'dir' using the 'kustomize build' command.
        kbuild=$(kustomize build "$dir")
        return_code=$?
        if [ $return_code -ne 0 ]; then
          printf 'ERROR:\t Failed \"kustomize build\" command for directory: %s. See error above\n' "$dir"
          continue
        fi
        # Grep the output of 'kustomize build' command for 'image:' and '- image' lines and return just the image itself
        mapfile kimages -t  <<< "$(grep '\-\?\s\image:'<<<"$kbuild" | sed -re 's/\s-?\simage: *//;s/^[ \t]*//g' | sed '/^\$/d;/{/d' )"
        wg_images+=("${kimages[@]}")
    done
  done
  uniq_wg_images=($(echo "${wg_images[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
  images+=(${uniq_wg_images[@]})
  save_images "${wg}" "${uniq_wg_images[@]}"
done

uniq_images=($(echo "${images[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
save_images "all" "${uniq_images[@]}"

# Directory containing the text files
DIRECTORY="../docs/image_lists"

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