export POD_NAME=$(kubectl get pods --namespace default -l "app.kubernetes.io/name=falco-exporter,app.kubernetes.io/instance=falco-exporter" -o jsonpath="{.items[0].metadata.name}")
echo "Visit http://127.0.0.1:9376/metrics to use your application"
kubectl port-forward --namespace default $POD_NAME 9376
echo