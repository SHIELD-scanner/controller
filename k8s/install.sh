 kubectl apply -f deployment.yaml
 kubectl apply -f mongo.yaml
#  kubectl create -f https://raw.githubusercontent.com/aquasecurity/trivy-operator/main/deploy/static/trivy-operator.yaml

#  helm repo add falcosecurity https://falcosecurity.github.io/charts
# helm repo update
# helm install --replace falco --namespace falco --create-namespace --set tty=true falcosecurity/falco
# kubectl get pods -n falco
# helm upgrade --install falco falcosecurity/falco \
#   --namespace falco-system \
#   --set tty=true \
#   --set falco.grpc.enabled=true \
#   --set falco.grpc.bind_address="0.0.0.0:5060" \
#   --set falco.grpc_output.enabled=true